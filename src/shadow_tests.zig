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
const undo = @import("db/undo.zig");
const branches = @import("db/branches.zig");
const keccak256 = @import("evm/crypto/hash.zig").keccak256;
const bootstrap = @import("db/bootstrap.zig");

test {
    _ = @import("node/consensus.zig");
}

const queries = [_]Shadow.Query{
    .{ .address = .{ .bytes = @splat(0x11) }, .storageKeys = &.{ .init(0), .init(1), .init(2), .init(99) } },
    .{ .address = .{ .bytes = @splat(0xee) }, .storageKeys = &.{.init(0)} },
};

fn prepareIncompleteBootstrap(fixture: *Fixture) !types.BlockHeader {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var header = try fixture.write(10, 123, false);
    header.slot_number = 20;
    header.block_access_list_hash = @splat(0x44);
    const txn = try fixture.store.transaction_rw();
    errdefer txn.abort() catch unreachable;
    try branches.initialize(&fixture.store, txn, arena.allocator(), header);
    try txn.commit();
    return header;
}

test "shadow incomplete bootstrap reset is atomic and never publishes partial state" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const header = try prepareIncompleteBootstrap(&fixture);
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    const old = try fixture.store.transaction_ro();
    defer old.abort() catch unreachable;
    try std.testing.expect((try fixture.store.table(old, .accounts).get(&key)) != null);
    const cancelled = try fixture.store.transaction_rw();
    _ = try bootstrap.restart(&fixture.store, cancelled, a, header.hash());
    try std.testing.expect((try fixture.store.table(cancelled, .accounts).get(&key)) == null);
    try cancelled.abort();
    const resumed = try fixture.store.transaction_rw();
    try std.testing.expect((try fixture.store.table(resumed, .accounts).get(&key)) != null);
    try std.testing.expectEqual(header.hash(), (try bootstrap.restart(&fixture.store, resumed, a, header.hash())).hash());
    try resumed.commit();
    const latest = try fixture.store.transaction_ro();
    defer latest.abort() catch unreachable;
    try std.testing.expect((try fixture.store.table(latest, .accounts).get(&key)) == null);
    try std.testing.expect((try fixture.store.table(old, .accounts).get(&key)) != null);
    try std.testing.expectEqual(null, try snapshots.readCheckpoint(&fixture.store, latest, a));
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &fixture.store };
    defer views.deinit();
    try std.testing.expectError(error.StateNotReady, views.publish(a));
    try std.testing.expectEqual(0, views.status().count);
    try std.testing.expectError(error.StateViewUnavailable, views.acquire(header.hash(), header.state_root));
}

test "shadow bootstrap reset rejects wrong anchors and never clears verified state" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const header = try prepareIncompleteBootstrap(&fixture);
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    const txn = try fixture.store.transaction_rw();
    defer txn.abort() catch unreachable;
    try std.testing.expectError(error.BootstrapBranchMismatch, bootstrap.restart(&fixture.store, txn, a, @splat(0x55)));
    try std.testing.expect((try fixture.store.table(txn, .accounts).get(&key)) != null);
    try snapshots.writeCheckpoint(&fixture.store, txn, a, header);
    try std.testing.expectError(error.StateAlreadyVerified, bootstrap.restart(&fixture.store, txn, a, header.hash()));
    try std.testing.expect((try fixture.store.table(txn, .accounts).get(&key)) != null);
}

test "shadow bootstrap reset rejects a progressed branch without a checkpoint" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const header = try prepareIncompleteBootstrap(&fixture);
    var child = header;
    child.number += 1;
    child.parent_hash = header.hash();
    const txn = try fixture.store.transaction_rw();
    defer txn.abort() catch unreachable;
    try branches.select(&fixture.store, txn, arena.allocator(), header, &.{child});
    try std.testing.expectError(error.BootstrapBranchMismatch, bootstrap.restart(&fixture.store, txn, a, child.hash()));
}

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
        return self.transition(number, balance, checkpoint, null, null);
    }

    fn transition(self: *Fixture, number: u64, balance: u256, checkpoint: bool, previous: ?types.BlockHeader, record: ?undo.Record) !types.BlockHeader {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const alloc = arena.allocator();
        var eth = Eth.init(&self.store);
        const txn = try self.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        inline for (.{ .accounts, .storage, .account_trie, .storage_tries }) |table|
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
        if (previous) |parent_header| header.parent_hash = parent_header.hash();
        header.state_root = try at.rootHash();
        try eth.commitAccountTrieNodes(txn, &ac);
        try eth.writeAccount(alloc, txn, addr_hash, account);
        if (checkpoint) try snapshots.writeCheckpoint(&self.store, txn, alloc, header);
        if (record) |r| try undo.save(&self.store, txn, alloc, header, r);
        if (previous) |p| try branches.select(&self.store, txn, alloc, p, &.{header});
        if (checkpoint) try branches.initialize(&self.store, txn, alloc, header);
        try txn.commit();
        return header;
    }

    fn capture(self: *Fixture, allocator: std.mem.Allocator, parent_header: types.BlockHeader, balance: u256) !undo.Record {
        var eth = Eth.init(&self.store);
        const txn = try self.store.transaction_ro();
        defer txn.abort() catch unreachable;
        var values = [_]types.StorageChange{.{ .index = 1, .value = balance }};
        var storage = [_]types.SlotChanges{.{ .key = 0, .changes = &values }};
        var balances = [_]types.BalanceChange{.{ .index = 1, .balance = balance }};
        var nonces = [_]types.NonceChange{.{ .index = 1, .nonce = parent_header.number + 1 }};
        var changes = [_]types.AccountChanges{.{
            .addr = std.mem.readInt(u160, &queries[0].address.bytes, .big),
            .storage_changes = &storage,
            .storage_reads = &.{},
            .balance_changes = &balances,
            .nonce_changes = &nonces,
            .code_changes = &.{},
        }};
        return undo.capture(&eth, txn, allocator, parent_header, try types.HashedBlockAccessLists.init(allocator, &changes));
    }
};

fn parent(header: types.BlockHeader) Shadow.Parent {
    return .{ .blockHash = .{ .bytes = header.hash() }, .stateRoot = .{ .bytes = header.state_root } };
}

test "shadow exact trie nodes authenticate path hash owner and retained version" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    defer api.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const first = try f.write(1, 42, true);
    try views.publish(a);
    const proof = try api.read(alloc, parent(first), &queries);
    const slot_proof = proof.accounts[0].storageProof[0].proof;
    try std.testing.expectEqual(@as(usize, 2), slot_proof.len);
    const hashed_slot = types.keccakOfU256(0);
    const path = [_]u8{hashed_slot[0] >> 4};
    const query: Shadow.NodeQuery = .{ .owner = queries[0].address, .path = .{ .bytes = &path }, .expectedHash = .{ .bytes = keccak256(slot_proof[1].bytes) } };
    const result = try api.readNodes(alloc, parent(first), &.{
        .{ .path = .{ .bytes = &.{} }, .expectedHash = .{ .bytes = first.state_root } },
        query,
    });
    try std.testing.expectEqualSlices(u8, proof.accounts[0].accountProof[0].bytes, result.nodes[0].bytes);
    try std.testing.expectEqualSlices(u8, slot_proof[1].bytes, result.nodes[1].bytes);
    var bad = query;
    bad.expectedHash.bytes = @splat(0);
    try std.testing.expectError(error.TrieNodeHashMismatch, api.readNodes(alloc, parent(first), &.{bad}));
    bad = query;
    bad.owner = queries[1].address;
    try std.testing.expectError(error.StateAccountUnavailable, api.readNodes(alloc, parent(first), &.{bad}));
    bad = query;
    bad.path.bytes = &.{16};
    try std.testing.expectError(error.InvalidTrieNodePath, api.readNodes(alloc, parent(first), &.{bad}));
    try std.testing.expectError(error.StateQueryLimit, api.readNodes(alloc, parent(first), &.{}));
    const second = try f.write(2, 84, true);
    try views.publish(a);
    const old = try api.readNodes(alloc, parent(first), &.{query});
    try std.testing.expectEqualSlices(u8, result.nodes[1].bytes, old.nodes[0].bytes);
    try std.testing.expectError(error.TrieNodeHashMismatch, api.readNodes(alloc, parent(second), &.{query}));
}

test "shadow ancestor backfill is hash-bound and never substitutes a selected height" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    defer api.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var one = genesis;
    one.number = 1;
    one.parent_hash = genesis.hash();
    var two = one;
    two.number = 2;
    two.parent_hash = one.hash();
    {
        const txn = try f.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        try branches.initialize(&f.store, txn, alloc, two);
        try snapshots.writeCheckpoint(&f.store, txn, alloc, two);
        try txn.commit();
    }
    try views.publish(alloc);
    try std.testing.expectError(error.AncestorUnavailable, api.readAncestors(alloc, parent(two), 3));
    try std.testing.expectError(error.AncestorQueryLimit, api.readAncestors(alloc, parent(two), 4));
    try std.testing.expectError(error.AncestorQueryLimit, api.readAncestors(alloc, parent(two), 0));
    var alternate_one = one;
    alternate_one.state_root = @splat(0xa1);
    var alternate_two = two;
    alternate_two.parent_hash = alternate_one.hash();
    {
        const txn = try f.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        try branches.rememberAncestors(&f.store, txn, alloc, one.hash(), &.{ genesis, one });
        try branches.rememberAncestors(&f.store, txn, alloc, alternate_one.hash(), &.{ genesis, alternate_one });
        try std.testing.expectEqual(two.hash(), (try branches.state(&f.store, txn)).?.head.hash());
        try std.testing.expectEqual(null, try branches.read(&f.store, txn, 1));
        try snapshots.writeCheckpoint(&f.store, txn, alloc, alternate_two);
        try txn.commit();
    }
    try views.publish(alloc);
    const old = try api.readAncestors(alloc, parent(two), 3);
    const alt = try api.readAncestors(alloc, parent(alternate_two), 3);
    try std.testing.expectEqual(one.hash(), keccak256(old.headers[1].bytes));
    try std.testing.expectEqual(alternate_one.hash(), keccak256(alt.headers[1].bytes));
    try std.testing.expectEqual(genesis.hash(), keccak256(old.headers[2].bytes));
    // Corruption is rejected by content hash; no fallback to another branch.
    {
        const txn = try f.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        try f.store.table(txn, .branch_headers).set(&one.hash(), alt.headers[1].bytes, .Upsert);
        try txn.commit();
    }
    try std.testing.expectError(error.InvalidBranchHeader, api.readAncestors(alloc, parent(two), 3));
}

test "shadow ancestor cache rejects disconnected chains before any insertion" {
    var f = try Fixture.init();
    defer f.deinit();
    var one = genesis;
    one.number = 1;
    one.parent_hash = @splat(0x99);
    const txn = try f.store.transaction_rw();
    defer txn.abort() catch unreachable;
    try std.testing.expectError(error.BranchParentMismatch, branches.rememberAncestors(&f.store, txn, a, one.hash(), &.{ genesis, one }));
    try std.testing.expectEqual(null, try branches.byHash(&f.store, txn, genesis.hash()));
}

test "shadow full ancestor cache remains bounded with the downloader slab allocator" {
    var f = try Fixture.init();
    defer f.deinit();
    var backing = std.heap.ArenaAllocator.init(a);
    defer backing.deinit();
    var slabs = @import("devp2p/allocator.zig").SlabAllocator.init(backing.allocator());
    var arena = std.heap.ArenaAllocator.init(slabs.allocator());
    defer arena.deinit();
    var headers: [256]types.BlockHeader = undefined;
    var last = genesis;
    const txn = try f.store.transaction_rw();
    errdefer txn.abort() catch unreachable;
    for (0..17) |_| {
        for (&headers) |*header| {
            header.* = last;
            header.number += 1;
            header.parent_hash = last.hash();
            last = header.*;
        }
        _ = arena.reset(.retain_capacity);
        try branches.rememberAncestors(&f.store, txn, arena.allocator(), last.hash(), &headers);
    }
    try std.testing.expectEqual(null, try branches.missingAncestor(&f.store, txn, last));
    var count: usize = 0;
    {
        const cursor = try f.store.table(txn, .branch_headers).cursor();
        defer cursor.deinit();
        if (try cursor.seekLowerBound(&@as([32]u8, @splat(0))) != null) {
            count = 1;
            while (try cursor.goToNext() != null) count += 1;
        }
    }
    try std.testing.expectEqual(4096, count);
    try txn.commit();
}

test "shadow RPC witnesses work after ancestor responses in a retained slab arena" {
    var f = try Fixture.init();
    defer f.deinit();
    const header = try f.write(1, 42, true);
    var eth = Eth.init(&f.store);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    defer api.deinit();
    var server: @import("rpc/jsonrpc.zig").Server = .{};
    defer server.deinit(a);
    try api.register(a, &server);
    var backing = std.heap.ArenaAllocator.init(a);
    defer backing.deinit();
    var slabs = @import("devp2p/allocator.zig").SlabAllocator.init(backing.allocator());
    var request_arena = std.heap.ArenaAllocator.init(slabs.allocator());
    defer request_arena.deinit();
    const ancestry = try std.fmt.allocPrint(a, "{f}", .{std.json.fmt(.{ .jsonrpc = "2.0", .id = 1, .method = "zevm_getStateAncestorsV1", .params = .{ parent(header), 1 } }, .{})});
    defer a.free(ancestry);
    const witness = try std.fmt.allocPrint(a, "{f}", .{std.json.fmt(.{ .jsonrpc = "2.0", .id = 1, .method = "zevm_getStateWitnessV1", .params = .{ parent(header), queries } }, .{})});
    defer a.free(witness);
    for ([_][]const u8{ ancestry, witness, ancestry, witness }) |body| {
        _ = request_arena.reset(.retain_capacity);
        const response = try server.handle(std.testing.io, request_arena.allocator(), body);
        const parsed = try std.json.parseFromSlice(std.json.Value, request_arena.allocator(), response.raw, .{});
        try std.testing.expect(parsed.value.object.get("error") == null);
        try std.testing.expect(parsed.value.object.contains("result"));
    }
}

test "shadow RPC workspace reuse preserves copied responses across failures and different parents" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    var api: Shadow = .{ .snapshots = &views, .eth = &eth, .workspace = .{ .backing_allocator = a } };
    defer api.deinit();
    const first = try f.write(1, 42, true);
    try views.publish(a);
    const original = try api.witness(std.testing.io, a, parent(first), &queries);
    defer a.free(original.raw);
    const expected = try a.dupe(u8, original.raw);
    defer a.free(expected);

    const second = try f.write(2, 84, true);
    try views.publish(a);
    const newer = try api.witness(std.testing.io, a, parent(second), &queries);
    defer a.free(newer.raw);
    try std.testing.expect(!std.mem.eql(u8, original.raw, newer.raw));
    const parsed = try std.json.parseFromSlice(Shadow.Witness, a, newer.raw, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(84, parsed.value.accounts[0].balance.number);
    try std.testing.expectEqual(84, parsed.value.accounts[0].storageProof[0].value.number);

    // Exercise both smaller workspace users between witness reads.
    const ancestry = try api.ancestors(std.testing.io, a, parent(second), 1);
    defer a.free(ancestry.raw);
    const nodes = try api.trieNodes(std.testing.io, a, parent(second), &.{.{
        .path = .{ .bytes = &.{} },
        .expectedHash = .{ .bytes = second.state_root },
    }});
    defer a.free(nodes.raw);
    try std.testing.expectError(error.StateRootMismatch, api.witness(std.testing.io, a, .{
        .blockHash = parent(first).blockHash,
        .stateRoot = parent(second).stateRoot,
    }, &queries));
    // A response allocation failure must release the workspace too.
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, api.witness(std.testing.io, failing.allocator(), parent(second), &queries));
    const repeated = try api.witness(std.testing.io, a, parent(first), &queries);
    defer a.free(repeated.raw);
    try std.testing.expectEqualSlices(u8, expected, repeated.raw);

    // Returned JSON has no workspace or DB borrow after retention evicts first.
    for (3..12) |i| {
        _ = try f.write(i, i, true);
        try views.publish(a);
    }
    try std.testing.expectError(error.StateViewUnavailable, api.witness(std.testing.io, a, parent(first), &queries));
    try std.testing.expectEqualSlices(u8, expected, original.raw);
}

test "shadow RPC scratch allocation failure releases admission and can recover" {
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    const header = try f.write(1, 42, true);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var api: Shadow = .{ .snapshots = &views, .eth = &eth, .workspace = .{ .backing_allocator = failing.allocator() } };
    defer api.deinit();
    try std.testing.expectError(error.OutOfMemory, api.witness(std.testing.io, a, parent(header), &queries));
    try std.testing.expectEqual(null, api.workspace.backing);
    api.workspace.backing_allocator = a;
    const response = try api.witness(std.testing.io, a, parent(header), &queries);
    defer a.free(response.raw);
    const parsed = try std.json.parseFromSlice(Shadow.Witness, a, response.raw, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(42, parsed.value.accounts[0].balance.number);
}

test "shadow concurrent RPC witnesses keep exact parents and response ownership separate" {
    const io = std.testing.io;
    var f = try Fixture.init();
    defer f.deinit();
    var eth = Eth.init(&f.store);
    var views: snapshots.Snapshots = .{ .io = io, .store = &f.store };
    defer views.deinit();
    const first = try f.write(1, 42, true);
    try views.publish(a);
    const second = try f.write(2, 84, true);
    try views.publish(a);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth, .workspace = .{ .backing_allocator = a } };
    defer api.deinit();
    var start: std.Io.Event = .unset;
    const Reader = struct {
        fn run(task_io: std.Io, gate: *std.Io.Event, shared: *Shadow, header: types.BlockHeader, balance: u256) !void {
            try gate.wait(task_io);
            var owned = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer owned.deinit();
            const allocator = owned.allocator();
            var responses: [16][]const u8 = undefined;
            for (&responses) |*response| {
                response.* = (try shared.witness(task_io, allocator, parent(header), &queries)).raw;
            }
            for (responses) |response| {
                const parsed = try std.json.parseFromSlice(Shadow.Witness, allocator, response, .{});
                try std.testing.expectEqual(header.hash(), parsed.value.parent.blockHash.bytes);
                try std.testing.expectEqual(header.state_root, parsed.value.parent.stateRoot.bytes);
                try std.testing.expectEqual(balance, parsed.value.accounts[0].balance.number);
                try std.testing.expectEqual(balance, parsed.value.accounts[0].storageProof[0].value.number);
            }
        }
    };
    var left = try io.concurrent(Reader.run, .{ io, &start, &api, first, 42 });
    defer left.cancel(io) catch {};
    var right = try io.concurrent(Reader.run, .{ io, &start, &api, second, 84 });
    defer right.cancel(io) catch {};
    start.set(io);
    try left.await(io);
    try right.await(io);
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
    defer api.deinit();
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
    defer api.deinit();
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
    defer api.deinit();
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
        defer api.deinit();
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
    defer api.deinit();
    try std.testing.checkAllAllocationFailures(a, readAllocationCase, .{ &api, header });
    try readAllocationCase(a, &api, header);
    try std.testing.expectEqual(header.hash(), views.status().headers[0].hash());
}

test "shadow reorg rewinds storage and accounts, preserves old leases and selects another branch" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var eth = Eth.init(&f.store);
    const base = try f.write(1, 42, true);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    const record = try f.capture(alloc, base, 84);
    const left = try f.transition(2, 84, true, base, record);
    try views.publish(a);
    const lease = try views.acquire(left.hash(), left.state_root);
    defer lease.deinit();
    {
        const txn = try f.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        const restored = try undo.rewind(&eth, txn, alloc, base.hash());
        try std.testing.expectEqual(base.hash(), restored.hash());
        try branches.select(&f.store, txn, alloc, base, &.{});
        try txn.commit();
    }
    try views.publish(a);
    try std.testing.expectEqual(base.hash(), views.status().headers[0].hash());
    try std.testing.expectEqual(2, views.status().count);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    defer api.deinit();
    try std.testing.expectEqual(42, (try api.read(alloc, parent(base), &queries)).accounts[0].storageProof[0].value.number);
    const right_record = try f.capture(alloc, base, 99);
    const right = try f.transition(2, 99, true, base, right_record);
    try views.publish(a);
    try std.testing.expectEqual(84, (try api.read(alloc, parent(left), &queries)).accounts[0].balance.number);
    try std.testing.expectEqual(99, (try api.read(alloc, parent(right), &queries)).accounts[0].balance.number);
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    try std.testing.expectEqual(84, (try eth.readAccount(lease.txn, key)).?.balance);
    const txn = try f.store.transaction_ro();
    defer txn.abort() catch unreachable;
    try std.testing.expectEqual(left.hash(), (try branches.byHash(&f.store, txn, left.hash())).?.hash());
    try std.testing.expectEqual(right.hash(), (try branches.read(&f.store, txn, 2)).?.hash());
}

test "shadow four-block reorg restores the common ancestor and preserves a losing-branch lease" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var eth = Eth.init(&f.store);
    const base = try f.write(1, 42, true);
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var left = base;
    for (2..6) |number| {
        const balance = number * 100;
        left = try f.transition(number, balance, true, left, try f.capture(alloc, left, balance));
        try views.publish(a);
    }
    const old = try views.acquire(left.hash(), left.state_root);
    defer old.deinit();
    {
        const txn = try f.store.transaction_rw();
        errdefer txn.abort() catch unreachable;
        const restored = try undo.rewind(&eth, txn, alloc, base.hash());
        try std.testing.expectEqual(base.hash(), restored.hash());
        try branches.select(&f.store, txn, alloc, base, &.{});
        try txn.commit();
    }
    try views.publish(a);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    defer api.deinit();
    const restored = (try api.read(alloc, parent(base), &queries)).accounts[0];
    try std.testing.expectEqual(42, restored.balance.number);
    try std.testing.expectEqual(1, restored.nonce.number);
    try std.testing.expectEqual(42, restored.storageProof[0].value.number);
    var right = base;
    for (2..6) |number| {
        const balance = number * 100 + 1;
        right = try f.transition(number, balance, true, right, try f.capture(alloc, right, balance));
        try views.publish(a);
    }
    const current = (try api.read(alloc, parent(right), &queries)).accounts[0];
    try std.testing.expectEqual(501, current.balance.number);
    try std.testing.expectEqual(501, current.storageProof[0].value.number);
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    try std.testing.expectEqual(500, (try eth.readAccount(old.txn, key)).?.balance);
    const txn = try f.store.transaction_ro();
    defer txn.abort() catch unreachable;
    try std.testing.expectEqual(right.hash(), (try snapshots.readCheckpoint(&f.store, txn, alloc)).?.hash());
    try std.testing.expectEqual(right.hash(), (try branches.read(&f.store, txn, 5)).?.hash());
    try std.testing.expectEqual(left.hash(), (try branches.byHash(&f.store, txn, left.hash())).?.hash());
}

test "shadow missing undo history aborts even after an earlier successful rewind" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var eth = Eth.init(&f.store);
    const base = try f.write(1, 42, true);
    const middle = try f.transition(2, 84, true, base, try f.capture(alloc, base, 84));
    const last = try f.transition(3, 123, true, middle, try f.capture(alloc, middle, 123));
    {
        const txn = try f.store.transaction_rw();
        try f.store.table(txn, .state_undo).delete(&middle.hash());
        try txn.commit();
    }
    {
        const txn = try f.store.transaction_rw();
        defer txn.abort() catch unreachable;
        try std.testing.expectError(error.StateHistoryUnavailable, undo.rewind(&eth, txn, alloc, base.hash()));
    }
    const txn = try f.store.transaction_ro();
    defer txn.abort() catch unreachable;
    try std.testing.expectEqual(last.hash(), (try snapshots.readCheckpoint(&f.store, txn, alloc)).?.hash());
    const key = types.keccakOfU160(std.mem.readInt(u160, &queries[0].address.bytes, .big));
    try std.testing.expectEqual(123, (try eth.readAccount(txn, key)).?.balance);
}

test "shadow headers reject a disconnected extension before modifying selection" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const base = try f.write(1, 42, true);
    var left = base;
    left.number += 1;
    left.parent_hash = base.hash();
    var wrong = left;
    wrong.number += 1;
    wrong.parent_hash = @splat(0xee);
    const txn = try f.store.transaction_rw();
    defer txn.abort() catch unreachable;
    try std.testing.expectError(error.BranchParentMismatch, branches.select(&f.store, txn, alloc, base, &.{ left, wrong }));
    try std.testing.expectEqual(base.hash(), (try branches.state(&f.store, txn)).?.head.hash());
    try std.testing.expect(try branches.byHash(&f.store, txn, left.hash()) == null);
}

fn rewindAllocationCase(backing: std.mem.Allocator, f: *Fixture, target: [32]u8) !void {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    var eth = Eth.init(&f.store);
    const txn = try f.store.transaction_rw();
    defer txn.abort() catch unreachable;
    _ = try undo.rewind(&eth, txn, arena.allocator(), target);
}

test "shadow rewind allocation failures leave the committed child intact" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const base = try f.write(1, 42, true);
    const child = try f.transition(2, 84, true, base, try f.capture(arena.allocator(), base, 84));
    try std.testing.checkAllAllocationFailures(a, rewindAllocationCase, .{ &f, base.hash() });
    const txn = try f.store.transaction_ro();
    defer txn.abort() catch unreachable;
    try std.testing.expectEqual(child.hash(), (try snapshots.readCheckpoint(&f.store, txn, arena.allocator())).?.hash());
}

test "shadow rejects the actual Plataberget disconnected header pair from 21 November" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const captured = try std.json.parseFromSlice([][]const u8, alloc, @embedFile("testdata/shadow-reorg-20261121.json"), .{});
    var headers: [4]types.BlockHeader = undefined;
    for (captured.value, &headers) |raw, *header| {
        const bytes = try alloc.alloc(u8, (raw.len - 2) / 2);
        _ = try std.fmt.hexToBytes(bytes, raw[2..]);
        _ = try @import("rlp").deserialize(types.BlockHeader, alloc, bytes, header);
    }
    try std.testing.expectEqual(627187, headers[1].number);
    try std.testing.expectEqual(627188, headers[2].number);
    try std.testing.expectEqual(627189, headers[3].number);
    const txn = try f.store.transaction_rw();
    defer txn.abort() catch unreachable;
    try branches.initialize(&f.store, txn, alloc, headers[1]);
    try std.testing.expectError(error.BranchParentMismatch, branches.select(&f.store, txn, alloc, headers[1], headers[2..]));
    try std.testing.expectEqual(headers[1].hash(), (try branches.state(&f.store, txn)).?.head.hash());
    try std.testing.expect(try branches.byHash(&f.store, txn, headers[2].hash()) == null);
}

test "shadow persistent undo survives database reopen and restores the parent" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const base = try f.write(1, 42, true);
    const child = try f.transition(2, 84, true, base, try f.capture(alloc, base, 84));
    var path: [1024]u8 = undefined;
    const length = try f.dir.dir.realPathFile(std.testing.io, "db", &path);
    try f.store.deinit();
    f.store = try kv.Store.initBounded(a, path[0..length], 64 << 20, 1 << 20);
    var eth = Eth.init(&f.store);
    const txn = try f.store.transaction_rw();
    errdefer txn.abort() catch unreachable;
    try std.testing.expectEqual(child.hash(), (try snapshots.readCheckpoint(&f.store, txn, alloc)).?.hash());
    _ = try undo.rewind(&eth, txn, alloc, base.hash());
    try branches.select(&f.store, txn, alloc, base, &.{});
    try txn.commit();
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    try views.publish(a);
    var api: Shadow = .{ .snapshots = &views, .eth = &eth };
    defer api.deinit();
    try std.testing.expectEqual(42, (try api.read(alloc, parent(base), &queries)).accounts[0].balance.number);
}

test "shadow journal retention is bounded and unsupported deep rewind does not commit" {
    var f = try Fixture.init();
    defer f.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const base = try f.write(1, 42, true);
    var head = base;
    for (2..38) |n| head = try f.transition(n, n, true, head, try f.capture(alloc, head, n));
    var eth = Eth.init(&f.store);
    {
        const txn = try f.store.transaction_rw();
        defer txn.abort() catch unreachable;
        try std.testing.expectError(error.StateHistoryUnavailable, undo.rewind(&eth, txn, alloc, base.hash()));
    }
    const txn = try f.store.transaction_ro();
    defer txn.abort() catch unreachable;
    try std.testing.expectEqual(head.hash(), (try snapshots.readCheckpoint(&f.store, txn, alloc)).?.hash());
    const cursor = try f.store.table(txn, .state_undo).cursor();
    defer cursor.deinit();
    var count: usize = 0;
    if (try cursor.seekLowerBound(&@as([32]u8, @splat(0))) != null) {
        count = 1;
        while (try cursor.goToNext() != null) count += 1;
    }
    try std.testing.expectEqual(undo.depth_limit, count);
}

test "shadow reselecting a retained view after ring wrap preserves all other views" {
    var f = try Fixture.init();
    defer f.deinit();
    var views: snapshots.Snapshots = .{ .io = std.testing.io, .store = &f.store };
    defer views.deinit();
    for (1..13) |n| {
        _ = try f.write(n, n, true);
        try views.publish(a);
    }
    const header = try f.write(7, 7, true);
    try views.publish(a);
    const status = views.status();
    try std.testing.expectEqual(8, status.count);
    try std.testing.expectEqual(header.hash(), status.headers[0].hash());
    try std.testing.expectEqual(12, status.headers[1].number);
}

test "shadow corrupted undo preimages cannot restore a falsely labelled parent root" {
    for (0..2) |case| {
        var f = try Fixture.init();
        defer f.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const alloc = arena.allocator();
        const base = try f.write(1, 42, true);
        const record = try f.capture(alloc, base, 84);
        if (case == 0) record.accounts[0].value.balance += 1 else record.accounts[0].slots[0].value += 1;
        const child = try f.transition(2, 84, true, base, record);
        var eth = Eth.init(&f.store);
        {
            const txn = try f.store.transaction_rw();
            defer txn.abort() catch unreachable;
            try std.testing.expectError(if (case == 0) error.UndoStateRootMismatch else error.UndoStorageRootMismatch, undo.rewind(&eth, txn, alloc, base.hash()));
        }
        const txn = try f.store.transaction_ro();
        defer txn.abort() catch unreachable;
        try std.testing.expectEqual(child.hash(), (try snapshots.readCheckpoint(&f.store, txn, alloc)).?.hash());
    }
}

test "shadow undo workspace works with the live downloader slab allocator" {
    var f = try Fixture.init();
    defer f.deinit();
    var backing = std.heap.ArenaAllocator.init(a);
    defer backing.deinit();
    var slabs = @import("devp2p/allocator.zig").SlabAllocator.init(backing.allocator());
    var arena = std.heap.ArenaAllocator.init(slabs.allocator());
    defer arena.deinit();
    const alloc = arena.allocator();
    const base = try f.write(1, 42, true);
    const record = try f.capture(alloc, base, 84);
    const child = try f.transition(2, 84, true, base, null);
    var eth = Eth.init(&f.store);
    const txn = try f.store.transaction_rw();
    errdefer txn.abort() catch unreachable;
    try undo.save(&f.store, txn, alloc, child, record);
    const restored = try undo.rewind(&eth, txn, alloc, base.hash());
    try std.testing.expectEqual(base.hash(), restored.hash());
    try txn.commit();
}
