// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Opt-in, localhost shadow qualification API. No latest/number fallback.
const std = @import("std");
const rlp = @import("rlp");
const types = @import("../types.zig");
const EthDb = @import("../db/eth.zig").Eth;
const Snapshots = @import("../db/snapshot.zig").Snapshots;
const rpc = @import("jsonrpc.zig");
const hex = @import("hex.zig");
const branches = @import("../db/branches.zig");

/// Once used, this API owns a mutex and workspace and must not be copied.
pub const Shadow = struct {
    snapshots: *Snapshots,
    eth: *EthDb,
    workspace: Workspace = .{},

    /// Stop and join every RPC caller before releasing the retained workspace.
    /// Direct typed reads use caller-owned memory and never borrow this buffer.
    pub fn deinit(self: *Shadow) void {
        self.workspace.deinit();
    }

    pub fn register(self: *Shadow, allocator: std.mem.Allocator, server: *rpc.Server) !void {
        try server.register(allocator, "zevm_getStateStatusV1", self, status);
        try server.register(allocator, "zevm_getStateWitnessV1", self, witness);
        try server.register(allocator, "zevm_getStateNodesV1", self, trieNodes);
        try server.register(allocator, "zevm_getStateAncestorsV1", self, ancestors);
    }

    pub const Parent = struct { blockHash: hex.Data(32), stateRoot: hex.Data(32) };
    pub const Query = struct { address: hex.Data(20), storageKeys: []const hex.Number(u256) };
    pub const Stamp = struct {
        blockHash: hex.Data(32),
        stateRoot: hex.Data(32),
        blockNumber: hex.Number(u64),
        databaseVersion: hex.Number(u64),
    };

    pub fn status(self: *Shadow, _: std.Io, allocator: std.mem.Allocator) !struct { protocolVersion: u8 = 1, retained: []const Stamp } {
        const s = self.snapshots.status();
        const out = try allocator.alloc(Stamp, s.count);
        for (out, 0..) |*entry, i| entry.* = stamp(s.headers[i], s.versions[i]);
        return .{ .retained = out };
    }

    fn stamp(header: types.BlockHeader, version: u64) Stamp {
        return .{
            .blockHash = .{ .bytes = header.hash() },
            .stateRoot = .{ .bytes = header.state_root },
            .blockNumber = .init(header.number),
            .databaseVersion = .init(version),
        };
    }

    const StorageProof = struct { key: hex.Number(u256), value: hex.Number(u256), proof: []const hex.Bytes };
    pub const AccountProof = struct {
        address: hex.Data(20),
        balance: hex.Number(u256),
        nonce: hex.Number(u64),
        storageHash: hex.Data(32),
        codeHash: hex.Data(32),
        accountProof: []const hex.Bytes,
        storageProof: []const StorageProof,
        code: hex.Bytes,
    };
    pub const Witness = struct { parent: Stamp, accounts: []const AccountProof };
    pub const NodeQuery = struct {
        // null selects the account trie; otherwise authenticate this account's
        // storage root before walking its raw nibble path.
        owner: ?hex.Data(20) = null,
        path: hex.Bytes,
        expectedHash: hex.Data(32),
    };
    pub const Nodes = struct { parent: Stamp, nodes: []const hex.Bytes };
    pub const Ancestors = struct { parent: Stamp, headers: []const hex.Bytes };

    pub fn trieNodes(self: *Shadow, io: std.Io, allocator: std.mem.Allocator, parent: Parent, queries: []const NodeQuery) !rpc.RawJson {
        try checkNodeQueries(queries);
        var scratch = try self.workspace.acquire(io, 4 << 20);
        defer scratch.release();
        const result = try self.readNodes(scratch.buffer.allocator(), parent, queries);
        return .{ .raw = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(result, .{})}) };
    }

    fn checkNodeQueries(queries: []const NodeQuery) !void {
        if (queries.len == 0 or queries.len > 16) return error.StateQueryLimit;
        for (queries) |q| {
            if (q.path.bytes.len > 64) return error.InvalidTrieNodePath;
            for (q.path.bytes) |nibble| if (nibble > 15) return error.InvalidTrieNodePath;
        }
    }

    pub fn readNodes(self: *Shadow, allocator: std.mem.Allocator, parent: Parent, queries: []const NodeQuery) !Nodes {
        try checkNodeQueries(queries);
        const view = try self.snapshots.acquire(parent.blockHash.bytes, parent.stateRoot.bytes);
        defer view.deinit();
        const out = try allocator.alloc(hex.Bytes, queries.len);
        for (queries, out) |query, *entry| {
            var at = try self.eth.openAccountTrie(allocator, view.txn, view.header.state_root);
            defer self.eth.closeAccountTrie(&at);
            if (query.owner) |owner| {
                const key = types.keccakOfU160(std.mem.readInt(u160, &owner.bytes, .big));
                const proof = try at.inner.prove(key);
                const encoded = proof.value orelse return error.StateAccountUnavailable;
                var account: types.Account = undefined;
                if (try rlp.deserialize(types.Account, allocator, encoded, &account) != encoded.len) return error.MalformedAccount;
                var st = try self.eth.openStorageTrie(allocator, view.txn, key, account.storage_hash);
                defer self.eth.closeStorageTrie(&st);
                entry.* = .{ .bytes = try st.inner.nodeAtPath(query.path.bytes, query.expectedHash.bytes) };
            } else entry.* = .{ .bytes = try at.inner.nodeAtPath(query.path.bytes, query.expectedHash.bytes) };
        }
        return .{ .parent = stamp(view.header, view.txn.id()), .nodes = out };
    }

    pub fn ancestors(self: *Shadow, io: std.Io, allocator: std.mem.Allocator, parent: Parent, count: u16) !rpc.RawJson {
        if (count == 0 or count > 256) return error.AncestorQueryLimit;
        var scratch = try self.workspace.acquire(io, 4 << 20);
        defer scratch.release();
        const result = try self.readAncestors(scratch.buffer.allocator(), parent, count);
        return .{ .raw = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(result, .{})}) };
    }

    /// Header cache entries are immutable by hash and may be backfilled after
    /// the state view was published. Read that cache in a fresh RO transaction,
    /// following hashes from the leased parent, never selected block numbers.
    pub fn readAncestors(self: *Shadow, allocator: std.mem.Allocator, parent: Parent, count: u16) !Ancestors {
        if (count == 0 or count > 256) return error.AncestorQueryLimit;
        const view = try self.snapshots.acquire(parent.blockHash.bytes, parent.stateRoot.bytes);
        defer view.deinit();
        if (count - 1 > view.header.number) return error.AncestorQueryLimit;
        const store = self.eth.kv_store;
        const txn = try store.transaction_ro();
        defer txn.abort() catch unreachable;
        const headers = try allocator.alloc(hex.Bytes, count);
        var header = view.header;
        for (headers, 0..) |*entry, i| {
            var encoded = std.array_list.Managed(u8).init(allocator);
            try rlp.serialize(types.BlockHeader, allocator, header, &encoded);
            if (encoded.items.len > 2048) return error.InvalidBranchHeader;
            entry.* = .{ .bytes = encoded.items };
            if (i + 1 == count) break;
            const previous = try branches.byHash(store, txn, header.parent_hash) orelse return error.AncestorUnavailable;
            if (previous.number != header.number - 1) return error.BranchParentMismatch;
            header = previous;
        }
        return .{ .parent = stamp(view.header, view.txn.id()), .headers = headers };
    }

    /// Hard bounds apply even to trusted local callers. The response is copied
    /// out before another request can reuse scratch. The DB view is never cached.
    pub fn witness(self: *Shadow, io: std.Io, allocator: std.mem.Allocator, parent: Parent, queries: []const Query) !rpc.RawJson {
        try checkQueries(queries);
        // The HTTP arena retains capacity and grows geometrically. Combining
        // this fixed workspace with an earlier ancestor response can request
        // a slab larger than its 32 MiB maximum despite a 16 MiB workspace.
        // Keep bounded scratch separate and reuse its backing. Allocating and
        // freeing 16 MiB for each tiny read touches the entire buffer in safe
        // mode. Fresh FBA state preserves the per-request cap without that cost.
        var scratch = try self.workspace.acquire(io, 16 << 20);
        defer scratch.release();
        const result = try self.read(scratch.buffer.allocator(), parent, queries);
        return .{ .raw = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(result, .{})}) };
    }

    fn checkQueries(queries: []const Query) !void {
        if (queries.len == 0 or queries.len > 16) return error.StateQueryLimit;
        var slots: usize = 0;
        for (queries) |q| {
            slots += q.storageKeys.len;
            if (slots > 128) return error.StateQueryLimit;
        }
    }

    pub fn read(self: *Shadow, allocator: std.mem.Allocator, parent: Parent, queries: []const Query) !Witness {
        try checkQueries(queries);
        const view = try self.snapshots.acquire(parent.blockHash.bytes, parent.stateRoot.bytes);
        defer view.deinit();
        const accounts = try allocator.alloc(AccountProof, queries.len);
        for (queries, accounts) |query, *out| {
            const addr = std.mem.readInt(u160, &query.address.bytes, .big);
            const addr_hash = types.keccakOfU160(addr);
            var at = try self.eth.openAccountTrie(allocator, view.txn, view.header.state_root);
            defer self.eth.closeAccountTrie(&at);
            const proof = try at.inner.prove(addr_hash);
            var account = types.EmptyAccount;
            if (proof.value) |encoded| {
                if (try rlp.deserialize(types.Account, allocator, encoded, &account) != encoded.len) return error.MalformedAccount;
            }
            const storage = try allocator.alloc(StorageProof, query.storageKeys.len);
            for (query.storageKeys, storage) |key, *entry| {
                var st = try self.eth.openStorageTrie(allocator, view.txn, addr_hash, account.storage_hash);
                defer self.eth.closeStorageTrie(&st);
                const sp = try st.inner.prove(types.keccakOfU256(key.number));
                var value: u256 = 0;
                if (sp.value) |encoded| {
                    if (try rlp.deserialize(u256, allocator, encoded, &value) != encoded.len) return error.MalformedStorage;
                }
                entry.* = .{ .key = key, .value = .init(value), .proof = try nodes(allocator, sp.nodes) };
            }
            var code: []const u8 = &.{};
            if (!std.meta.eql(account.code_hash, types.empty_code_hash)) {
                const bytes = try self.eth.kv_store.table(view.txn, .codes).get(&account.code_hash) orelse return error.CodeUnavailable;
                if (bytes.len > 128 * 1024) return error.StateCodeLimit;
                var hash: [32]u8 = undefined;
                std.crypto.hash.sha3.Keccak256.hash(bytes, &hash, .{});
                if (!std.meta.eql(hash, account.code_hash)) return error.CodeHashMismatch;
                code = try allocator.dupe(u8, bytes);
            }
            out.* = .{
                .address = query.address,
                .balance = .init(account.balance),
                .nonce = .init(@intCast(account.nonce)),
                .storageHash = .{ .bytes = account.storage_hash },
                .codeHash = .{ .bytes = account.code_hash },
                .accountProof = try nodes(allocator, proof.nodes),
                .storageProof = storage,
                .code = .{ .bytes = code },
            };
        }
        return .{ .parent = stamp(view.header, view.txn.id()), .accounts = accounts };
    }

    fn nodes(allocator: std.mem.Allocator, encoded: []const []const u8) ![]const hex.Bytes {
        const out = try allocator.alloc(hex.Bytes, encoded.len);
        for (out, encoded) |*entry, bytes| entry.* = .{ .bytes = bytes };
        return out;
    }
};

/// One bounded buffer belongs to this API, never to a snapshot or candidate.
/// JSON results must be copied to the caller's allocator while holding the
/// lease. A failed request releases the lock and the next lease starts at zero.
/// The current HTTP server is serial; the lock also protects direct RPC callers
/// and permits cancellation while waiting without resetting another request.
const Workspace = struct {
    const capacity = 16 << 20;
    backing_allocator: std.mem.Allocator = std.heap.page_allocator,
    backing: ?[]u8 = null,
    mutex: std.Io.Mutex = .init,

    fn deinit(self: *Workspace) void {
        if (self.backing) |bytes| self.backing_allocator.free(bytes);
        self.backing = null;
    }

    fn acquire(self: *Workspace, io: std.Io, limit: usize) !Lease {
        std.debug.assert(limit > 0 and limit <= capacity);
        try self.mutex.lock(io);
        errdefer self.mutex.unlock(io);
        if (self.backing == null) self.backing = try self.backing_allocator.alloc(u8, capacity);
        return .{ .owner = self, .io = io, .buffer = .init(self.backing.?[0..limit]) };
    }

    const Lease = struct {
        owner: *Workspace,
        io: std.Io,
        buffer: std.heap.FixedBufferAllocator,

        fn release(self: *Lease) void {
            self.owner.mutex.unlock(self.io);
            self.* = undefined;
        }
    };
};

test "shadow workspace preserves request limits and releases a cancelled waiter" {
    const io = std.testing.io;
    var workspace: Workspace = .{ .backing_allocator = std.testing.allocator };
    defer workspace.deinit();
    var first = try workspace.acquire(io, 4 << 20);
    const bytes = try first.buffer.allocator().alloc(u8, 4 << 20);
    @memset(bytes, 0x53);
    try std.testing.expectError(error.OutOfMemory, first.buffer.allocator().alloc(u8, 1));
    const Waiting = struct {
        fn run(ws: *Workspace, task_io: std.Io) !void {
            var lease = try ws.acquire(task_io, 16 << 20);
            defer lease.release();
            const scratch = try lease.buffer.allocator().alloc(u8, 1);
            scratch[0] = 0x99;
        }
    };
    var waiter = try io.concurrent(Waiting.run, .{ &workspace, io });
    try std.testing.expectError(error.Canceled, waiter.cancel(io));
    try std.testing.expectEqual(@as(u8, 0x53), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x53), bytes[bytes.len - 1]);
    first.release();
    var next = try workspace.acquire(io, 16 << 20);
    defer next.release();
    _ = try next.buffer.allocator().alloc(u8, 16 << 20);
    try std.testing.expectError(error.OutOfMemory, next.buffer.allocator().alloc(u8, 1));
}
