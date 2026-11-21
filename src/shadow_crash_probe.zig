// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test-only subprocess target. Pause with a real uncommitted state transaction,
//! or immediately after its commit, so a driver can kill without running defers.
const std = @import("std");
const rlp = @import("rlp");
const types = @import("types.zig");
const kv = @import("db/kv.zig");
const Eth = @import("db/eth.zig").Eth;
const snapshots = @import("db/snapshot.zig");
const branches = @import("db/branches.zig");
const AccountTrie = @import("trie/account_trie.zig").AccountTrie;
const NodeCollector = @import("trie/trie.zig").NodeCollector;
const genesis = @import("node/blockchain.zig").glamsterdam_devnet8_config.genesis_header;

fn emit(io: std.Io, value: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, &buffer);
    try std.json.Stringify.value(value, .{}, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}

fn pause(io: std.Io, phase: []const u8) !void {
    try emit(io, .{ .ready = phase });
    while (true) try io.sleep(.fromSeconds(1), .awake);
}

pub fn main(init: std.process.Init) !void {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const mode = args.next() orelse return error.MissingMode;
    const path = args.next() orelse return error.MissingDirectory;
    if (args.next() != null) return error.InvalidArguments;
    const a = init.arena.allocator();
    var store = try kv.Store.initBounded(a, path, 64 << 20, 1 << 20);
    defer store.deinit() catch {};
    var eth = Eth.init(&store);
    const key = types.keccakOfU160(0x1111);
    if (std.mem.eql(u8, mode, "inspect")) {
        const txn = try store.transaction_ro();
        defer txn.abort() catch {};
        const header = try snapshots.readCheckpoint(&store, txn, a) orelse return error.StateNotReady;
        const selected = try branches.state(&store, txn) orelse return error.StateNotReady;
        if (!std.meta.eql(header.hash(), selected.head.hash())) return error.StateCheckpointBranchMismatch;
        var trie = try eth.openAccountTrie(a, txn, header.state_root);
        defer eth.closeAccountTrie(&trie);
        const proof = try trie.inner.prove(key);
        const encoded = proof.value orelse return error.MissingAccount;
        var account: types.Account = undefined;
        if (try rlp.deserialize(types.Account, a, encoded, &account) != encoded.len) return error.MalformedAccount;
        if (account.nonce != header.number or account.balance != header.number * 42) return error.StateCheckpointMismatch;
        return emit(init.io, .{ .number = header.number, .balance = account.balance, .root = std.fmt.bytesToHex(header.state_root, .lower), .authenticated = true });
    }
    const initial = std.mem.eql(u8, mode, "init");
    const before = std.mem.eql(u8, mode, "before-commit");
    if (!initial and !before and !std.mem.eql(u8, mode, "after-commit")) return error.InvalidArguments;
    const txn = try store.transaction_rw();
    var committed = false;
    defer if (!committed) txn.abort() catch {};
    const previous = try snapshots.readCheckpoint(&store, txn, a);
    if ((initial and previous != null) or (!initial and (previous == null or previous.?.number != 1))) return error.UnexpectedCheckpoint;
    inline for (.{ .accounts, .account_trie }) |table| try store.table(txn, table).drop(false);
    const number: u64 = if (initial) 1 else 2;
    var account = types.EmptyAccount;
    account.nonce = number;
    account.balance = number * 42;
    var collector = try NodeCollector.init(a, 16);
    var trie = AccountTrie.init(a).withCollector(&collector);
    try trie.update(&.{key}, &.{account});
    var header = genesis;
    header.number = number;
    header.parent_hash = if (previous) |p| p.hash() else genesis.hash();
    header.state_root = try trie.rootHash();
    try eth.commitAccountTrieNodes(txn, &collector);
    try eth.writeAccount(a, txn, key, account);
    try snapshots.writeCheckpoint(&store, txn, a, header);
    if (previous) |p| try branches.select(&store, txn, a, p, &.{header}) else try branches.initialize(&store, txn, a, header);
    if (before) try pause(init.io, mode);
    try txn.commit();
    committed = true;
    if (!initial) try pause(init.io, mode);
    try emit(init.io, .{ .initialized = true });
}
