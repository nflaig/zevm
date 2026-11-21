// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const types = @import("types.zig");
const kv = @import("db/kv.zig");
const Eth = @import("db/eth.zig").Eth;
const snapshots = @import("db/snapshot.zig");
const Shadow = @import("rpc/shadow.zig").Shadow;
const AccountTrie = @import("trie/account_trie.zig").AccountTrie;
const StorageTrie = @import("trie/storage_trie.zig").StorageTrie;
const NodeCollector = @import("trie/trie.zig").NodeCollector;
const genesis = @import("node/blockchain.zig").glamsterdam_devnet8_config.genesis_header;
const a = std.testing.allocator;

const queries = [_]Shadow.Query{
    .{ .address = .{ .bytes = @splat(0x11) }, .storageKeys = &.{ .init(0), .init(1), .init(2), .init(99) } },
    .{ .address = .{ .bytes = @splat(0xee) }, .storageKeys = &.{.init(0)} },
};

const Fixture = struct {
    dir: std.testing.TmpDir,
    store: kv.Store,

    fn init() !Fixture {
        var dir = std.testing.tmpDir(.{});
        errdefer dir.cleanup();
        try dir.dir.createDir(std.testing.io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const size = try dir.dir.realPathFile(std.testing.io, "db", &path);
        return .{ .dir = dir, .store = try kv.Store.initBounded(a, path[0..size], 64 << 20, 1 << 20) };
    }

    fn deinit(self: *Fixture) void {
        self.store.deinit() catch unreachable;
        self.dir.cleanup();
    }

    fn write(self: *Fixture, number: u64, balance: u256, checkpoint: bool) !types.BlockHeader {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const alloc = arena.allocator();
        var eth = Eth.init(&self.store);
        const txn = try self.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        inline for (.{ .accounts, .storage, .codes, .account_trie, .storage_tries }) |table|
            try self.store.table(txn, table).drop(false);
        const addr_hash = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
        var sc = try NodeCollector.init(alloc, 256);
        var st = StorageTrie.init(alloc).withCollector(&sc);
        const keys = [_][32]u8{ types.keccakOfU256(0), types.keccakOfU256(1), types.keccakOfU256(2) };
        const values = [_]u256{ balance, 1, 999 };
        try st.update(&keys, &values);
        const storage_root = try st.rootHash();
        try eth.commitStorageTrieNodes(txn, addr_hash, &sc);
        for (keys, values) |key, value| try eth.writeStorage(txn, addr_hash, key, value);
        const account: types.Account = .{
            .nonce = number,
            .balance = balance,
            .storage_hash = storage_root,
            .code_hash = try eth.writeCode(txn, &.{ 0x60, 0x00, 0x00 }),
        };
        var ac = try NodeCollector.init(alloc, 256);
        var at = AccountTrie.init(alloc).withCollector(&ac);
        try at.update(&.{addr_hash}, &.{account});
        var header = genesis;
        header.number = number;
        header.state_root = try at.rootHash();
        try eth.commitAccountTrieNodes(txn, &ac);
        try eth.writeAccount(alloc, txn, addr_hash, account);
        if (checkpoint) try snapshots.writeCheckpoint(&self.store, txn, alloc, header);
        try txn.commit();
        return header;
    }
};

fn parent(header: types.BlockHeader) Shadow.Parent {
    return .{ .blockHash = .{ .bytes = header.hash() }, .stateRoot = .{ .bytes = header.state_root } };
}

test "shadow rejects partial state, unknown parent and incorrect root" {
    var f = try Fixture.init();
    defer f.deinit();
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    _ = try f.write(1, 42, false);
    try std.testing.expectError(error.StateNotReady, views.publish(a));
    try std.testing.expectEqual(0, views.status().count);
    const header = try f.write(1, 42, true);
    try views.publish(a);
    try std.testing.expectError(error.StateViewUnavailable, views.acquire(@splat(0), header.state_root));
    try std.testing.expectError(error.StateRootMismatch, views.acquire(header.hash(), @splat(0)));
}

test "shadow authenticated reads survive advancement, eviction and caller-owned leases" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const first = try f.write(1, 42, true);
    try views.publish(a);
    const lease = try views.acquire(first.hash(), first.state_root);
    defer lease.deinit();
    const second = try f.write(2, 84, true);
    try views.publish(a);
    const old = try api.read(arena.allocator(), parent(first), &queries);
    const new = try api.read(arena.allocator(), parent(second), &queries);
    try std.testing.expectEqual(42, old.accounts[0].balance.number);
    try std.testing.expectEqual(84, new.accounts[0].balance.number);
    try std.testing.expectEqual(42, old.accounts[0].storageProof[0].value.number);
    try std.testing.expectEqual(1, old.accounts[0].storageProof[1].value.number);
    try std.testing.expectEqual(999, old.accounts[0].storageProof[2].value.number);
    try std.testing.expectEqual(0, old.accounts[0].storageProof[3].value.number);
    try std.testing.expectEqual(0, old.accounts[1].balance.number);
    try std.testing.expectEqual(0, old.accounts[1].storageProof[0].value.number);
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 0x00, 0x00 }, old.accounts[0].code.bytes);
    try std.testing.expect(old.parent.databaseVersion.number < new.parent.databaseVersion.number);
    for (3..12) |i| {
        _ = try f.write(i, i, true);
        try views.publish(a);
    }
    try std.testing.expectEqual(snapshots.Snapshots.capacity, views.status().count);
    try std.testing.expectError(error.StateViewUnavailable, views.acquire(first.hash(), first.state_root));
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    try std.testing.expectEqual(42, (try eth.readAccount(lease.txn, key)).?.balance);
    // The returned witness owns bytes after its RPC-local DB lease is closed.
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 0x00, 0x00 }, old.accounts[0].code.bytes);
}

test "shadow authenticates flat leaves and code instead of trusting checkpoint labels" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    const header = try f.write(1, 42, true);
    const txn = try f.store.transaction_rw();
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    var account = (try eth.readAccount(txn, key)).?;
    account.balance = 43;
    try eth.writeAccount(a, txn, key, account);
    try txn.commit();
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectError(error.StateRootMismatch, api.read(arena.allocator(), parent(header), &queries));
}

test "shadow checkpoint and state rollback together and restart recovers only committed view" {
    var f = try Fixture.init();
    defer f.deinit();
    const committed = try f.write(1, 42, true);
    const txn = try f.store.transaction_rw();
    var wrong = committed;
    wrong.number = 999;
    try snapshots.writeCheckpoint(&f.store, txn, a, wrong);
    try txn.abort();
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    try std.testing.expectEqual(committed.hash(), views.status().headers[0].hash());
    try std.testing.expectError(error.StateViewUnavailable, views.acquire(wrong.hash(), wrong.state_root));
}

test "shadow retains distinct branches at the same height and rejects oversized queries" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    const left = try f.write(7, 111, true);
    try views.publish(a);
    const right = try f.write(7, 222, true);
    try views.publish(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectEqual(111, (try api.read(arena.allocator(), parent(left), &queries)).accounts[0].balance.number);
    try std.testing.expectEqual(222, (try api.read(arena.allocator(), parent(right), &queries)).accounts[0].balance.number);
    var oversized: [17]Shadow.Query = @splat(queries[0]);
    try std.testing.expectError(error.StateQueryLimit, api.read(arena.allocator(), parent(left), &oversized));
    const bad_parent: Shadow.Parent = .{ .blockHash = parent(left).blockHash, .stateRoot = parent(right).stateRoot };
    try std.testing.expectError(error.StateRootMismatch, api.read(arena.allocator(), bad_parent, &queries));
}

test "shadow missing and corrupted code never become empty code" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    const header = try f.write(1, 42, true);
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    for (0..2) |i| {
        const txn = try f.store.transaction_rw();
        const account = (try eth.readAccount(txn, key)).?;
        const table = f.store.table(txn, .codes);
        if (i == 0) try table.delete(&account.code_hash) else try table.set(&account.code_hash, &.{0xff}, .Upsert);
        try txn.commit();
        var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
        defer views.deinit();
        try views.publish(a);
        var api: Shadow = .{ .snapshots = &views, .eth = &eth };
        const expected = if (i == 0) error.CodeUnavailable else error.CodeHashMismatch;
        try std.testing.expectError(expected, api.read(arena.allocator(), parent(header), &queries));
    }
}

fn readAllocationCase(backing: std.mem.Allocator, api: *Shadow, header: types.BlockHeader) !void {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    _ = try api.read(arena.allocator(), parent(header), &queries);
}

test "shadow allocation failures release DB cursors and read leases" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    const header = try f.write(1, 42, true);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    try std.testing.checkAllAllocationFailures(a, readAllocationCase, .{ &api, header });
    try readAllocationCase(a, &api, header);
    try std.testing.expectEqual(header.hash(), views.status().headers[0].hash());
}
