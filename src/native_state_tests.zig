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

fn requireMandatoryMdbxChecks(options: []const u8) !void {
    var fields = std.mem.tokenizeScalar(u8, options, ' ');
    while (fields.next()) |field| {
        if (!std.mem.startsWith(u8, field, "CHECKING=")) continue;
        const value = field["CHECKING=".len..];
        if (try std.fmt.parseInt(i8, value, 10) < 0) return error.MdbxMandatoryChecksDisabled;
        return;
    }
    return error.MdbxCheckingOptionMissing;
}

test "native linked MDBX retains mandatory failure checks" {
    // Inspect the linked C object, not a Zig/header macro: DEBUG=-1 otherwise
    // defaults CHECKING to -1 and silently suppresses fatal mutex failures.
    const options = @import("lmdbx").c.mdbx_build.options;
    try std.testing.expect(options != null);
    try requireMandatoryMdbxChecks(std.mem.span(options));
    try requireMandatoryMdbxChecks("DEBUG=-1 CHECKING=0 WORDBITS=64");
    try std.testing.expectError(error.MdbxMandatoryChecksDisabled, requireMandatoryMdbxChecks("DEBUG=-1 CHECKING=-1 WORDBITS=64"));
    try std.testing.expectError(error.MdbxCheckingOptionMissing, requireMandatoryMdbxChecks("DEBUG=-1 WORDBITS=64"));
}

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
        return self.writeStorage(number, balance, previous, &.{ types.keccakOfU256(0), types.keccakOfU256(1), types.keccakOfU256(2) }, &.{ balance, 17, 999 });
    }

    fn writeStorage(self: *Fixture, number: u64, balance: u256, previous: ?types.BlockHeader, keys: []const [32]u8, values: []const u256) !types.BlockHeader {
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
        try storage.update(keys, values);
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

/// Keys deliberately form a root extension, a branch with hashed children,
/// and a deeper extension containing an embedded branch and tiny inline leaves.
fn cacheKeys() [3][32]u8 {
    var keys: [3][32]u8 = @splat(@splat(0));
    keys[0][0] = 0x12;
    keys[0][31] = 0x10;
    keys[1] = keys[0];
    keys[1][31] = 0x11;
    keys[2][0] = 0x13;
    return keys;
}

fn nodeQueries(alloc: std.mem.Allocator, lease: *native.Lease, owner: ?u160) ![]native.NodeQuery {
    const root = if (owner) |addr| (try lease.readAccount(alloc, addr)).storage_hash else (try lease.header()).state_root;
    var queries: std.ArrayList(native.NodeQuery) = .empty;
    try queries.append(alloc, .{ .owner = owner, .path = &.{}, .expected_hash = root });
    var i: usize = 0;
    while (i < queries.items.len) : (i += 1) {
        const query = queries.items[i];
        // Every enumerated edge is independently checked by the baseline root
        // walk, so this helper cannot hide a wrong path emitted by the parser.
        const encoded = try lease.readNode(alloc, owner, query.path, query.expected_hash);
        const references = try trie.Trie.hashedChildReferences(alloc, encoded, query.path);
        for (references.entries[0..references.count]) |child| {
            if (queries.items.len >= 64) return error.TestFixtureNodeLimit;
            try queries.append(alloc, .{ .owner = owner, .path = try alloc.dupe(u8, child.path[0..child.depth]), .expected_hash = child.hash });
        }
    }
    return queries.items;
}

test "native cache authenticates branch extension and inline edges with owned output" {
    var f = try Fixture.init();
    defer f.deinit();
    const keys = cacheKeys();
    const header = try f.writeStorage(1, 42, null, &keys, &.{ 1, 2, 3 });
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var control = try reader.acquire(parent(header));
    defer control.deinit();
    var cached = try reader.acquire(parent(header));
    defer cached.deinit();
    try std.testing.expect(!cached.nodeCacheStats().enabled);
    try cached.enableNodeCache(a, .{});
    try std.testing.expectError(error.NativeNodeCacheAlreadyEnabled, cached.enableNodeCache(a, .{}));
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const queries = try nodeQueries(alloc, &control, address);
    try std.testing.expectEqual(@as(usize, 4), queries.len);
    _ = try cached.readAccount(alloc, address);
    for (queries) |q| {
        const expected = try control.readNode(alloc, q.owner, q.path, q.expected_hash);
        try std.testing.expectEqualSlices(u8, expected, try cached.readNode(alloc, q.owner, q.path, q.expected_hash));
    }
    var stats = cached.nodeCacheStats();
    try std.testing.expectEqual(queries.len, stats.authorized_reads);
    try std.testing.expectEqual(@as(u64, 0), stats.fallback_reads);
    try std.testing.expectEqual(@as(u64, 0), stats.owner_reads);
    try std.testing.expect(stats.retained_bytes > 0);
    var key_buf: [64]u8 = undefined;
    const inline_path = trie.writeHexKey(&keys[0], &key_buf)[0..63];
    try std.testing.expectError(error.TrieNodeNotHashReference, cached.readNode(alloc, address, inline_path, queries[0].expected_hash));
    const copy = try cached.readNode(alloc, address, &.{}, queries[0].expected_hash);
    const saved = try alloc.dupe(u8, copy);
    @constCast(copy)[0] ^= 1;
    try std.testing.expectEqualSlices(u8, saved, try cached.readNode(alloc, address, &.{}, queries[0].expected_hash));
    stats = cached.nodeCacheStats();
    try std.testing.expectEqual(@as(u64, 2), stats.hits);
    cached.deinit();
    try std.testing.expectEqual(queries[0].expected_hash, @import("evm/crypto/hash.zig").keccak256(saved));
}

test "native cache cannot authorize unreachable content wrong owners or wrong hashes" {
    var f = try Fixture.init();
    defer f.deinit();
    const keys = cacheKeys();
    const header = try f.writeStorage(1, 42, null, &keys, &.{ 1, 2, 3 });
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var control = try reader.acquire(parent(header));
    defer control.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const queries = try nodeQueries(alloc, &control, address);
    const root_bytes = try control.readNode(alloc, address, &.{}, queries[0].expected_hash);
    // Valid content exists in the DB at an unreachable path and another owner.
    const tx = try f.store.transaction_rw();
    try eth.putStorageTrieNode(tx, types.keccakOfU160(address), &.{15}, root_bytes);
    try eth.putStorageTrieNode(tx, types.keccakOfU160(0xffff), &.{}, root_bytes);
    try tx.commit();
    try views.publish(a);
    var cached = try reader.acquire(parent(header));
    defer cached.deinit();
    try cached.enableNodeCache(a, .{});
    _ = try cached.readNode(alloc, address, &.{}, queries[0].expected_hash);
    const entries = cached.nodeCacheStats().entries;
    try std.testing.expectError(error.TrieNodePathUnavailable, cached.readNode(alloc, address, &.{15}, queries[0].expected_hash));
    try std.testing.expectError(error.TrieNodeNotHashReference, cached.readNode(alloc, 0xffff, &.{}, queries[0].expected_hash));
    try std.testing.expectError(error.TrieNodeHashMismatch, cached.readNode(alloc, address, queries[1].path, queries[0].expected_hash));
    try std.testing.expectError(error.TrieNodeHashMismatch, cached.readNode(alloc, null, &.{}, queries[0].expected_hash));
    try std.testing.expectEqual(entries, cached.nodeCacheStats().entries);
    try std.testing.expectEqualSlices(u8, root_bytes, try cached.readNode(alloc, address, &.{}, queries[0].expected_hash));
}

test "native node cache is exact lease state across deletion reorg and snapshot eviction" {
    var f = try Fixture.init();
    defer f.deinit();
    const keys = cacheKeys();
    const header = try f.writeStorage(1, 42, null, &keys, &.{ 1, 2, 3 });
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var old = try reader.acquire(parent(header));
    defer old.deinit();
    try old.enableNodeCache(a, .{});
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const old_root = (try old.readAccount(alloc, address)).storage_hash;
    const before = try old.readNode(alloc, address, &.{}, old_root);
    // Same-height sibling removes one inline leaf, collapsing the branch.
    var latest = try f.writeStorage(1, 90, null, &.{ keys[0], keys[2] }, &.{ 1, 3 });
    try views.publish(a);
    var sibling = try reader.acquire(parent(latest));
    defer sibling.deinit();
    try sibling.enableNodeCache(a, .{});
    const current_root = (try sibling.readAccount(alloc, address)).storage_hash;
    try std.testing.expect(!std.meta.eql(current_root, old_root));
    _ = try sibling.readNode(alloc, address, &.{}, current_root);
    try std.testing.expectError(error.TrieNodeHashMismatch, sibling.readNode(alloc, address, &.{}, old_root));
    for (0..native.Snapshots.capacity + 1) |i| {
        latest = try f.write(2 + i, 100 + i, latest);
        try views.publish(a);
    }
    try std.testing.expectError(error.StateViewUnavailable, reader.acquire(parent(header)));
    try std.testing.expectEqualSlices(u8, before, try old.readNode(alloc, address, &.{}, old_root));
    const child_queries = try nodeQueries(alloc, &old, address);
    try std.testing.expectEqual(@as(usize, 4), child_queries.len);
}

test "native cache entry and byte limits preserve uncached fallbacks" {
    var f = try Fixture.init();
    defer f.deinit();
    const header = try f.write(1, 42, null);
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var control = try reader.acquire(parent(header));
    defer control.deinit();
    var limited = try reader.acquire(parent(header));
    defer limited.deinit();
    try std.testing.expectError(error.InvalidNativeNodeCacheLimit, limited.enableNodeCache(a, .{ .max_entries = 0 }));
    try std.testing.expectError(error.InvalidNativeNodeCacheLimit, limited.enableNodeCache(a, .{ .max_entries = 16385 }));
    try std.testing.expectError(error.InvalidNativeNodeCacheLimit, limited.enableNodeCache(a, .{ .max_bytes = (16 << 20) + 1 }));
    try limited.enableNodeCache(a, .{ .max_entries = 2, .max_bytes = 0 });
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const queries = try nodeQueries(alloc, &control, address);
    for (0..2) |_| for (queries) |q| {
        try std.testing.expectEqualSlices(u8, try control.readNode(alloc, q.owner, q.path, q.expected_hash), try limited.readNode(alloc, q.owner, q.path, q.expected_hash));
    };
    const stats = limited.nodeCacheStats();
    try std.testing.expectEqual(@as(usize, 2), stats.entries);
    try std.testing.expectEqual(@as(usize, 0), stats.retained_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.hits);
    try std.testing.expect(stats.authorized_reads > 0 and stats.fallback_reads > 0 and stats.capacity_misses > 0);
    // Authorization-only with room for all edges skips root walks without
    // retaining any RLP. This is a separate benchmark variant from byte hits.
    var authorized = try reader.acquire(parent(header));
    defer authorized.deinit();
    try authorized.enableNodeCache(a, .{ .max_bytes = 0 });
    _ = try authorized.readAccount(alloc, address);
    for (queries) |q| _ = try authorized.readNode(alloc, q.owner, q.path, q.expected_hash);
    try std.testing.expectEqual(@as(u64, 0), authorized.nodeCacheStats().fallback_reads);
    try std.testing.expectEqual(queries.len, authorized.nodeCacheStats().authorized_reads);
    try std.testing.expectEqual(@as(usize, 0), authorized.nodeCacheStats().retained_bytes);
}

test "native authorized cache reads still reject missing and corrupt child preimages" {
    var f = try Fixture.init();
    defer f.deinit();
    const keys = cacheKeys();
    const header = try f.writeStorage(1, 42, null, &keys, &.{ 1, 2, 3 });
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var intact = try reader.acquire(parent(header));
    defer intact.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const queries = try nodeQueries(alloc, &intact, address);
    const child = queries[1];
    const root = queries[0];
    const corrupt = try f.store.transaction_rw();
    try eth.putStorageTrieNode(corrupt, types.keccakOfU160(address), child.path, &.{0xc0});
    try corrupt.commit();
    try views.publish(a);
    var bad = try reader.acquire(parent(header));
    defer bad.deinit();
    try bad.enableNodeCache(a, .{});
    _ = try bad.readNode(alloc, address, root.path, root.expected_hash);
    const before = bad.nodeCacheStats();
    try std.testing.expectError(error.StateRootMismatch, bad.readNode(alloc, address, child.path, child.expected_hash));
    try std.testing.expectEqual(before.entries, bad.nodeCacheStats().entries);
    try std.testing.expectEqual(before.retained_bytes, bad.nodeCacheStats().retained_bytes);
    const missing = try f.store.transaction_rw();
    try eth.deleteStorageTrieNode(missing, types.keccakOfU160(address), child.path);
    try f.store.table(missing, .storage).drop(false);
    try missing.commit();
    try views.publish(a);
    var absent = try reader.acquire(parent(header));
    defer absent.deinit();
    try absent.enableNodeCache(a, .{});
    _ = try absent.readNode(alloc, address, root.path, root.expected_hash);
    try std.testing.expectError(error.SubTrieNotAvailable, absent.readNode(alloc, address, child.path, child.expected_hash));
    _ = try intact.readNode(alloc, address, child.path, child.expected_hash);
}

test "native node cache cancellation precedes hits and authorization publication" {
    var f = try Fixture.init();
    defer f.deinit();
    const header = try f.write(1, 42, null);
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    var lease = try reader.acquire(parent(header));
    defer lease.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    // Inject cancellation at the real Io boundary, without scheduling races or
    // changing any lock/database implementation used by the original Io.
    const Cancel = struct {
        var calls: usize = 0;
        var fail_at: usize = 0;
        fn check(_: ?*anyopaque) std.Io.Cancelable!void {
            calls += 1;
            if (calls == fail_at) return error.Canceled;
        }
    };
    var vtable = io.vtable.*;
    vtable.checkCancel = Cancel.check;
    views.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer views.io = io;
    Cancel.calls = 0;
    Cancel.fail_at = 2;
    try std.testing.expectError(error.Canceled, lease.enableNodeCache(a, .{}));
    try std.testing.expect(!lease.nodeCacheStats().enabled);
    Cancel.fail_at = 0;
    try lease.enableNodeCache(a, .{});
    Cancel.calls = 0;
    Cancel.fail_at = 2;
    try std.testing.expectError(error.Canceled, lease.readNode(alloc, null, &.{}, header.state_root));
    try std.testing.expectEqual(@as(usize, 1), lease.nodeCacheStats().entries);
    try std.testing.expectEqual(@as(usize, 0), lease.nodeCacheStats().retained_bytes);
    Cancel.fail_at = 0;
    const bytes = try lease.readNode(alloc, null, &.{}, header.state_root);
    const before = lease.nodeCacheStats();
    Cancel.calls = 0;
    Cancel.fail_at = 1;
    try std.testing.expectError(error.Canceled, lease.readNode(alloc, null, &.{}, header.state_root));
    try std.testing.expectEqual(before, lease.nodeCacheStats());
    Cancel.fail_at = 0;
    try std.testing.expectEqualSlices(u8, bytes, try lease.readNode(alloc, null, &.{}, header.state_root));
}

fn cacheAllocationRead(allocator: std.mem.Allocator, reader: *native.Reader, p: native.Parent) !void {
    var lease = try reader.acquire(p);
    defer lease.deinit();
    try lease.enableNodeCache(allocator, .{ .max_entries = 32, .max_bytes = 4096 });
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const root = (try lease.readAccount(alloc, address)).storage_hash;
    const first = try lease.readNode(alloc, address, &.{}, root);
    try std.testing.expectEqualSlices(u8, first, try lease.readNode(alloc, address, &.{}, root));
}

test "native cache allocation failures release admission metadata and preimages" {
    var f = try Fixture.init();
    defer f.deinit();
    const header = try f.write(1, 42, null);
    var eth = native.Eth.init(&f.store);
    var views: native.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var reader: native.Reader = .{ .eth = &eth, .snapshots = &views };
    defer reader.deinit();
    const deterministic: std.mem.Allocator = .{ .ptr = a.ptr, .vtable = &.{
        .alloc = a.vtable.alloc,
        .resize = std.mem.Allocator.noResize,
        .remap = std.mem.Allocator.noRemap,
        .free = a.vtable.free,
    } };
    try std.testing.checkAllAllocationFailures(deterministic, cacheAllocationRead, .{ &reader, parent(header) });
    try std.testing.expectEqual(@as(usize, 0), reader.active_leases);
    try cacheAllocationRead(a, &reader, parent(header));
    try std.testing.expectEqual(@as(usize, 0), reader.active_leases);
}

test "native cache edge decoder rejects malformed boundaries before authorization" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const terminal: [64]u8 = @splat(0);
    const leaf = [_]u8{ 0xc2, 0x20, 0x01 };
    try std.testing.expectEqual(@as(usize, 0), (try trie.Trie.hashedChildReferences(alloc, &leaf, &terminal)).count);
    try std.testing.expectError(error.MalformedTrieNode, trie.Trie.hashedChildReferences(alloc, &leaf, &.{}));
    try std.testing.expectError(error.MalformedTrieNode, trie.Trie.hashedChildReferences(alloc, &.{ 0xc2, 0x80, 0x80 }, &.{}));
    try std.testing.expectError(error.MalformedTrieNode, trie.Trie.hashedChildReferences(alloc, &.{ 0xc2, 0x20, 0x01, 0x00 }, &terminal));
    try std.testing.expectError(error.InvalidTrieNodePath, trie.Trie.hashedChildReferences(alloc, &leaf, &.{16}));
}
