// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const native = @import("native_state.zig");
const types = native.types;
const kv = native.kv;
const rlp = @import("rlp");
const snapshot = @import("db/snapshot.zig");
const trie = @import("trie/trie.zig");
const AccountTrie = @import("trie/account_trie.zig").AccountTrie;
const StorageTrie = @import("trie/storage_trie.zig").StorageTrie;
const genesis = @import("node/blockchain.zig").glamsterdam_devnet8_config.genesis_header;
const a = std.testing.allocator;
const io = std.testing.io;
const address: u160 = 0x1234;

/// Real bounded MDBX, with separately owned stable Store/Eth/Snapshots/Reader.
/// Each test declares owners before leases, so reverse defers release leases
/// before snapshots and the database. Writers replace flat/trie state in one
/// transaction; old readers must continue seeing their original version.
const Fixture = struct {
    dir: std.testing.TmpDir,
    store: kv.Store,

    fn init() !Fixture {
        var dir = std.testing.tmpDir(.{});
        errdefer dir.cleanup();
        try dir.dir.createDir(io, "db", .default_dir);
        var path: [1024]u8 = undefined;
        const len = try dir.dir.realPathFile(io, "db", &path);
        return .{ .dir = dir, .store = try kv.Store.initBounded(a, path[0..len], 64 << 20, 1 << 20) };
    }

    fn deinit(self: *Fixture) void {
        self.store.deinit() catch unreachable;
        self.dir.cleanup();
    }

    fn write(self: *Fixture, number: u64, balance: u256, previous: ?types.BlockHeader) !types.BlockHeader {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const alloc = arena.allocator();
        var eth = native.Eth.init(&self.store);
        const txn = try self.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        inline for (.{ .accounts, .storage, .account_trie, .storage_tries }) |table| try self.store.table(txn, table).drop(false);
        const key = types.keccakOfU160(address);
        var storage_nodes = try trie.NodeCollector.init(alloc, 256);
        var storage = StorageTrie.init(alloc).withCollector(&storage_nodes);
        const keys = [_][32]u8{ types.keccakOfU256(0), types.keccakOfU256(1), types.keccakOfU256(2) };
        const values = [_]u256{ balance, 17, 999 };
        try storage.update(&keys, &values);
        const storage_root = try storage.rootHash();
        try eth.commitStorageTrieNodes(txn, key, &storage_nodes);
        for (keys, values) |slot, value| try eth.writeStorage(txn, key, slot, value);
        const account: types.Account = .{
            .nonce = number,
            .balance = balance,
            .storage_hash = storage_root,
            .code_hash = try eth.writeCode(txn, &.{ 0x60, @truncate(balance), 0x00 }),
        };
        var account_nodes = try trie.NodeCollector.init(alloc, 256);
        var accounts = AccountTrie.init(alloc).withCollector(&account_nodes);
        try accounts.updateNoDeletions(&.{key}, &.{account});
        var header = genesis;
        header.number = number;
        header.timestamp += number;
        header.slot_number = number;
        header.block_access_list_hash = @splat(0x44);
        if (previous) |prev| header.parent_hash = prev.hash();
        header.state_root = try accounts.rootHash();
        try eth.commitAccountTrieNodes(txn, &account_nodes);
        try eth.writeAccount(alloc, txn, key, account);
        try snapshot.writeCheckpoint(&self.store, txn, alloc, header);
        var encoded = std.array_list.Managed(u8).init(alloc);
        try rlp.serialize(types.BlockHeader, alloc, header, &encoded);
        try self.store.table(txn, .branch_headers).set(&header.hash(), encoded.items, .Upsert);
        try txn.commit();
        return header;
    }
};

fn parent(header: types.BlockHeader) native.Parent {
    return .{ .block_hash = header.hash(), .state_root = header.state_root };
}

test "native lease keeps exact state across writer updates sibling reorg and eviction" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    const base = try f.write(0, 41, null);
    try views.publish(a);
    const first = try f.write(1, 42, base);
    try views.publish(a);
    var lease = try reader.acquire(parent(first));
    defer lease.deinit();
    const stamp = try lease.stamp();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const account = try lease.readAccount(alloc, address);
    const copied_code = try lease.readCode(alloc, account.code_hash);
    const copied_node = try lease.readNode(alloc, null, &.{}, first.state_root);
    try std.testing.expectEqual(first.state_root, @import("evm/crypto/hash.zig").keccak256(copied_node));
    var latest = try f.write(1, 90, base);
    try views.publish(a);
    var sibling = try reader.acquire(parent(latest));
    defer sibling.deinit();
    try std.testing.expectEqual(@as(u256, 90), (try sibling.readAccount(alloc, address)).balance);
    const sibling_ancestors = try sibling.readAncestors(alloc, 2);
    const first_ancestors = try lease.readAncestors(alloc, 2);
    try std.testing.expectEqual(latest.hash(), sibling_ancestors[0].hash());
    try std.testing.expectEqual(first.hash(), first_ancestors[0].hash());
    try std.testing.expectEqual(base.hash(), first_ancestors[1].hash());
    for (0..native.Snapshots.capacity + 1) |i| {
        latest = try f.write(2 + i, 100 + i, latest);
        try views.publish(a);
    }
    try std.testing.expectError(error.StateViewUnavailable, reader.acquire(parent(first)));
    try std.testing.expectEqual(stamp, try lease.stamp());
    try std.testing.expectEqual(@as(u256, 42), (try lease.readAccount(alloc, address)).balance);
    try std.testing.expectEqual(@as(u256, 42), try lease.readStorage(alloc, address, 0));
    try std.testing.expectEqual(@as(u256, 0), try lease.readStorage(alloc, address, 99));
    try std.testing.expectEqual(types.EmptyAccount, try lease.readAccount(alloc, 0xffff));
    try std.testing.expectEqual(@as(u256, 0), try lease.readStorage(alloc, 0xffff, 0));
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 42, 0 }, try lease.readCode(alloc, account.code_hash));
    lease.deinit();
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 42, 0 }, copied_code);
    try std.testing.expectEqual(first.state_root, @import("evm/crypto/hash.zig").keccak256(copied_node));
    try std.testing.expectError(error.NativeStateLeaseClosed, lease.readAccount(alloc, address));
}

test "native lease rejects unverified wrong root wrong store and pre Gloas views without leaking admission" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    const header = try f.write(1, 42, null);
    try std.testing.expectError(error.StateViewUnavailable, reader.acquire(parent(header)));
    try views.publish(a);
    var wrong = parent(header);
    wrong.state_root[0] ^= 1;
    try std.testing.expectError(error.StateRootMismatch, reader.acquire(wrong));
    var other = try Fixture.init();
    defer other.deinit();
    var mismatched = native.Eth.init(&other.store);
    reader.eth = &mismatched;
    try std.testing.expectError(error.NativeStateStoreMismatch, reader.acquire(parent(header)));
    reader.eth = &eth;
    var pre = header;
    pre.slot_number = null;
    pre.block_access_list_hash = null;
    const txn = try f.store.transaction_rw();
    errdefer txn.abort() catch unreachable;
    try snapshot.writeCheckpoint(&f.store, txn, a, pre);
    try txn.commit();
    try views.publish(a);
    try std.testing.expectError(error.PostGloasRequired, reader.acquire(parent(pre)));
    try std.testing.expectEqual(@as(usize, 0), reader.active_leases);
    var lease = try reader.acquire(parent(header));
    lease.deinit();
}

test "native lease admission is bounded and released capacity can be reused" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    const header = try f.write(0, 42, null);
    try views.publish(a);
    var leases: [native.Reader.max_leases]native.Lease = undefined;
    var count: usize = 0;
    defer for (leases[0..count]) |*lease| lease.deinit();
    while (count < leases.len) : (count += 1) leases[count] = try reader.acquire(parent(header));
    try std.testing.expectError(error.NativeStateLeaseLimit, reader.acquire(parent(header)));
    leases[0].deinit();
    leases[0].deinit();
    leases[0] = try reader.acquire(parent(header));
    try std.testing.expectEqual(leases.len, reader.active_leases);
}

test "native missing and corrupt state never becomes zero on a verified marker" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const header = try f.write(1, 42, null);
    try views.publish(a);
    var intact = try reader.acquire(parent(header));
    defer intact.deinit();
    const corrupt = try f.store.transaction_rw();
    try eth.putAccountTrieNode(corrupt, &.{}, &.{0xc0});
    try corrupt.commit();
    try views.publish(a);
    var bad = try reader.acquire(parent(header));
    defer bad.deinit();
    try std.testing.expectError(error.StateRootMismatch, bad.readAccount(alloc, address));
    const missing = try f.store.transaction_rw();
    try f.store.table(missing, .account_trie).drop(false);
    try f.store.table(missing, .accounts).drop(false);
    try missing.commit();
    try views.publish(a);
    var absent = try reader.acquire(parent(header));
    defer absent.deinit();
    try std.testing.expectError(error.SubTrieNotAvailable, absent.readAccount(alloc, address));
    try std.testing.expectError(error.SubTrieNotAvailable, absent.readAccount(alloc, 0xffff));
    try std.testing.expectEqual(@as(u256, 42), (try intact.readAccount(alloc, address)).balance);
}

test "native missing storage and code fail while prior copied values remain owned" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const header = try f.write(1, 42, null);
    try views.publish(a);
    var intact = try reader.acquire(parent(header));
    defer intact.deinit();
    const account = try intact.readAccount(alloc, address);
    const copied = try intact.readCode(alloc, account.code_hash);
    const txn = try f.store.transaction_rw();
    try f.store.table(txn, .storage).drop(false);
    try f.store.table(txn, .storage_tries).drop(false);
    try f.store.table(txn, .codes).delete(&account.code_hash);
    try txn.commit();
    try views.publish(a);
    var missing = try reader.acquire(parent(header));
    defer missing.deinit();
    try std.testing.expectError(error.SubTrieNotAvailable, missing.readStorage(alloc, address, 0));
    try std.testing.expectError(error.SubTrieNotAvailable, missing.readStorage(alloc, address, 99));
    try std.testing.expectError(error.CodeUnavailable, missing.readCode(alloc, account.code_hash));
    try std.testing.expectEqual(@as(u256, 42), try intact.readStorage(alloc, address, 0));
    try std.testing.expectEqualSlices(u8, copied, try intact.readCode(alloc, account.code_hash));
    const corrupt = try f.store.transaction_rw();
    try f.store.table(corrupt, .codes).set(&account.code_hash, &.{0x99}, .Upsert);
    try corrupt.commit();
    try views.publish(a);
    var bad = try reader.acquire(parent(header));
    defer bad.deinit();
    try std.testing.expectError(error.CodeHashMismatch, bad.readCode(alloc, account.code_hash));
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 42, 0 }, copied);
}

test "native reconstructed flat leaves still authenticate against exact parent roots" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const header = try f.write(1, 42, null);
    try views.publish(a);
    var old = try reader.acquire(parent(header));
    defer old.deinit();
    var account = try old.readAccount(alloc, address);
    const corrupt_account = try f.store.transaction_rw();
    try f.store.table(corrupt_account, .account_trie).drop(false);
    account.balance = 999;
    try eth.writeAccount(alloc, corrupt_account, types.keccakOfU160(address), account);
    try corrupt_account.commit();
    try views.publish(a);
    var bad_account = try reader.acquire(parent(header));
    defer bad_account.deinit();
    try std.testing.expectError(error.StateRootMismatch, bad_account.readAccount(alloc, address));
    _ = try f.write(1, 42, null);
    const corrupt_storage = try f.store.transaction_rw();
    try eth.writeStorage(corrupt_storage, types.keccakOfU160(address), types.keccakOfU256(0), 777);
    try corrupt_storage.commit();
    try views.publish(a);
    var bad_storage = try reader.acquire(parent(header));
    defer bad_storage.deinit();
    try std.testing.expectError(error.StateRootMismatch, bad_storage.readStorage(alloc, address, 0));
    try std.testing.expectEqual(@as(u256, 42), try old.readStorage(alloc, address, 0));
}

test "native finalizer nodes require correct path owner and expected hash" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    const header = try f.write(1, 42, null);
    try views.publish(a);
    var lease = try reader.acquire(parent(header));
    defer lease.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const account = try lease.readAccount(alloc, address);
    const nodes = try lease.readNodes(alloc, &.{
        .{ .path = &.{}, .expected_hash = header.state_root },
        .{ .owner = address, .path = &.{}, .expected_hash = account.storage_hash },
    });
    try std.testing.expectEqual(header.state_root, @import("evm/crypto/hash.zig").keccak256(nodes[0]));
    try std.testing.expectEqual(account.storage_hash, @import("evm/crypto/hash.zig").keccak256(nodes[1]));
    try std.testing.expectError(error.TrieNodeHashMismatch, lease.readNode(alloc, null, &.{}, @splat(0)));
    try std.testing.expectError(error.TrieNodeNotHashReference, lease.readNode(alloc, 0xffff, &.{}, account.storage_hash));
    try std.testing.expectError(error.InvalidTrieNodePath, lease.readNode(alloc, address, &.{16}, account.storage_hash));
    try std.testing.expectError(error.StateQueryLimit, lease.readNodes(alloc, &.{}));
    const queries: [17]native.NodeQuery = @splat(.{ .path = &.{}, .expected_hash = header.state_root });
    try std.testing.expectError(error.StateQueryLimit, lease.readNodes(alloc, &queries));
}

test "native ancestors use authenticated later backfill without changing leased state" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const base = try f.write(0, 41, null);
    const header = try f.write(1, 42, base);
    const remove = try f.store.transaction_rw();
    try f.store.table(remove, .branch_headers).delete(&base.hash());
    try remove.commit();
    try views.publish(a);
    var lease = try reader.acquire(parent(header));
    defer lease.deinit();
    try std.testing.expectError(error.AncestorUnavailable, lease.readAncestors(alloc, 2));
    _ = try f.write(1, 90, base);
    var encoded = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(types.BlockHeader, alloc, base, &encoded);
    const backfill = try f.store.transaction_rw();
    try f.store.table(backfill, .branch_headers).set(&base.hash(), encoded.items, .Upsert);
    try backfill.commit();
    const ancestors = try lease.readAncestors(alloc, 2);
    try std.testing.expectEqual(header.hash(), ancestors[0].hash());
    try std.testing.expectEqual(base.hash(), ancestors[1].hash());
    try std.testing.expectEqual(@as(u256, 42), (try lease.readAccount(alloc, address)).balance);
    try std.testing.expectError(error.AncestorQueryLimit, lease.readAncestors(alloc, 0));
    try std.testing.expectError(error.AncestorQueryLimit, lease.readAncestors(alloc, 3));
    encoded.clearRetainingCapacity();
    try rlp.serialize(types.BlockHeader, alloc, header, &encoded);
    const corrupt = try f.store.transaction_rw();
    try f.store.table(corrupt, .branch_headers).set(&base.hash(), encoded.items, .Upsert);
    try corrupt.commit();
    try std.testing.expectError(error.InvalidBranchHeader, lease.readAncestors(alloc, 2));
}

fn allocationRead(allocator: std.mem.Allocator, lease: *native.Lease) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const account = try lease.readAccount(alloc, address);
    try std.testing.expectEqual(@as(u256, 42), account.balance);
    try std.testing.expectEqual(@as(u256, 42), try lease.readStorage(alloc, address, 0));
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 42, 0 }, try lease.readCode(alloc, account.code_hash));
    _ = try lease.readNode(alloc, address, &.{}, account.storage_hash);
    _ = try lease.readAncestors(alloc, 1);
}

test "native read allocation failures close cursors and preserve usable lease" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    const header = try f.write(1, 42, null);
    try views.publish(a);
    var lease = try reader.acquire(parent(header));
    defer lease.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationRead, .{&lease});
    try allocationRead(a, &lease);
    try std.testing.expectEqual(@as(usize, 1), reader.active_leases);
}

test "native cancelled lease admission does not leak a retained reader" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    const header = try f.write(0, 42, null);
    try views.publish(a);
    try reader.mutex.lock(io);
    var locked = true;
    defer if (locked) reader.mutex.unlock(io);
    const Waiting = struct {
        fn run(owner: *native.Reader, p: native.Parent) !void {
            var lease = try owner.acquire(p);
            defer lease.deinit();
        }
    };
    var waiter = io.concurrent(Waiting.run, .{ &reader, parent(header) }) catch return error.SkipZigTest;
    try std.testing.expectError(error.Canceled, waiter.cancel(io));
    try std.testing.expectEqual(@as(usize, 0), reader.active_leases);
    reader.mutex.unlock(io);
    locked = false;
    var lease = try reader.acquire(parent(header));
    lease.deinit();
}

test "native read only store opens existing handles without changing state or allowing writes" {
    var f = try Fixture.init();
    defer f.dir.cleanup();
    var writer_open = true;
    defer if (writer_open) f.store.deinit() catch unreachable;
    const header = try f.write(0, 42, null);
    const before = try f.store.env.info();
    var path: [1024]u8 = undefined;
    const len = try f.dir.dir.realPathFile(io, "db", &path);
    try f.store.deinit();
    writer_open = false;
    var store = try kv.Store.openReadOnly(a, path[0..len]);
    defer store.deinit() catch unreachable;
    var eth = native.Eth.init(&store);
    var views: native.Snapshots = .{ .io = io, .store = &store };
    defer views.deinit();
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    try views.publish(a);
    var lease = try reader.acquire(parent(header));
    defer lease.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectEqual(@as(u256, 42), (try lease.readAccount(arena.allocator(), address)).balance);
    try std.testing.expectError(error.ACCESS, store.transaction_rw());
    const after = try store.env.info();
    try std.testing.expectEqual(before.recent_txnid, after.recent_txnid);
    try std.testing.expectEqual(before.geo, after.geo);
}

test "native read only open fails for a missing table and does not recreate it" {
    var f = try Fixture.init();
    defer f.dir.cleanup();
    var writer_open = true;
    defer if (writer_open) f.store.deinit() catch unreachable;
    _ = try f.write(0, 42, null);
    const remove = try f.store.transaction_rw();
    try f.store.table(remove, .state_undo).drop(true);
    try remove.commit();
    var path: [1024]u8 = undefined;
    const len = try f.dir.dir.realPathFile(io, "db", &path);
    try f.store.deinit();
    writer_open = false;
    try std.testing.expectError(error.MDBX_NOTFOUND, kv.Store.openReadOnly(a, path[0..len]));
    // Repeating the failed open also exercises cleanup after partial DBI opens.
    try std.testing.expectError(error.MDBX_NOTFOUND, kv.Store.openReadOnly(a, path[0..len]));
}
