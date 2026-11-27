// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native, exact-parent state access for a constructor in the snapshot owner's
//! process. No transport, JSON types, EVM dependency, or latest-state fallback.
//!
//! Reader, Eth, Snapshots and Store must stay at stable addresses and outlive
//! every Lease. Stop/join workers and release leases before closing the store.
//! Reader admission is synchronized; each acquired Lease is move-only and used
//! by one worker at a time. Never copy a live lease or read concurrently through
//! it. A lease retains one MDBX read transaction (and its historical pages) until
//! deinit; the owner must bound session duration as well as the 32-lease cap.
//!
//! Each call uses the caller's bounded scratch allocator. Scalar values/headers
//! are owned inline; returned code/node bytes are copied into that allocator and
//! may outlive the lease. No database cursor, mapped slice, proof bundle or
//! candidate mutation escapes. A failed/cancelled read leaves the lease usable;
//! the caller resets its own scratch only after consuming any returned bytes.
const std = @import("std");
const rlp = @import("rlp");
pub const types = @import("types.zig");
pub const kv = @import("db/kv.zig");
pub const trie = @import("trie/trie.zig");
pub const AccountTrie = @import("trie/account_trie.zig").AccountTrie;
pub const StorageTrie = @import("trie/storage_trie.zig").StorageTrie;
pub const snapshot = @import("db/snapshot.zig");
pub const Eth = @import("db/eth.zig").Eth;
pub const Snapshots = snapshot.Snapshots;
const View = snapshot.View;
const branches = @import("db/branches.zig");
const A = std.mem.Allocator;
const Hash = [32]u8;

pub const Parent = struct { block_hash: Hash, state_root: Hash };
pub const Stamp = struct { block_hash: Hash, state_root: Hash, block_number: u64, database_version: u64 };
pub const NodeQuery = struct { owner: ?u160 = null, path: []const u8, expected_hash: Hash };

pub const NodeCacheOptions = struct {
    max_entries: u32 = 4096,
    /// RLP bytes only; metadata is separately bounded by max_entries. Zero
    /// retains path authorizations without caching preimages for qualification.
    max_bytes: usize = 4 << 20,
};

pub const NodeCacheStats = struct {
    enabled: bool = false,
    requests: u64 = 0,
    hits: u64 = 0,
    authorized_reads: u64 = 0,
    fallback_reads: u64 = 0,
    owner_reads: u64 = 0,
    entries: usize = 0,
    metadata_capacity_entries: usize = 0,
    retained_bytes: usize = 0,
    capacity_misses: u64 = 0,
};

/// This map is a path authorization, not a content-addressed node cache. Its
/// only roots come from this lease's header/authenticated owner accounts; child
/// edges come from hash-checked parents. No entry or backing byte crosses a
/// lease lifetime. It is single-worker like the lease and never evicts entries.
const NodeCache = struct {
    const Key = struct {
        owner: ?u160,
        path: [64]u8,
        depth: u8,

        fn init(owner: ?u160, path: []const u8) Key {
            var key: Key = .{ .owner = owner, .path = @splat(0), .depth = @intCast(path.len) };
            @memcpy(key.path[0..path.len], path);
            return key;
        }
    };
    const Entry = struct { hash: Hash, bytes: ?[]const u8 = null };

    allocator: A,
    options: NodeCacheOptions,
    entries: std.AutoHashMapUnmanaged(Key, Entry) = .empty,
    stats: NodeCacheStats = .{ .enabled = true },

    fn init(a: A, options: NodeCacheOptions) !*NodeCache {
        if (options.max_entries == 0 or options.max_entries > 32768 or options.max_bytes > 16 << 20)
            return error.InvalidNativeNodeCacheLimit;
        const self = try a.create(NodeCache);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .options = options };
        try self.entries.ensureTotalCapacity(a, options.max_entries);
        self.stats.metadata_capacity_entries = self.entries.capacity();
        return self;
    }

    fn deinit(self: *NodeCache) void {
        const allocator = self.allocator;
        var entries = self.entries.valueIterator();
        while (entries.next()) |entry| if (entry.bytes) |bytes| allocator.free(bytes);
        self.entries.deinit(allocator);
        allocator.destroy(self);
    }

    fn authorize(self: *NodeCache, key: Key, hash: Hash) !void {
        if (self.entries.get(key)) |old| {
            if (!std.meta.eql(old.hash, hash)) return error.StateRootMismatch;
            return;
        }
        if (self.entries.count() == self.options.max_entries) {
            self.stats.capacity_misses += 1;
            return;
        }
        self.entries.putAssumeCapacity(key, .{ .hash = hash });
        self.stats.entries = self.entries.count();
    }

    fn remember(self: *NodeCache, key: Key, expected: Hash, bytes: []const u8, children: trie.Trie.ChildReferences) !void {
        try self.authorize(key, expected);
        if (self.entries.getPtr(key)) |entry| if (entry.bytes == null) {
            if (bytes.len <= self.options.max_bytes - self.stats.retained_bytes) {
                const owned = try self.allocator.dupe(u8, bytes);
                entry.bytes = owned;
                self.stats.retained_bytes += owned.len;
            } else self.stats.capacity_misses += 1;
        };
        for (children.entries[0..children.count]) |child|
            try self.authorize(Key.init(key.owner, child.path[0..child.depth]), child.hash);
    }
};

pub const Reader = struct {
    pub const max_leases = 32;

    eth: *Eth,
    snapshots: *Snapshots,
    mutex: std.Io.Mutex = .init,
    active_leases: usize = 0,

    /// Only Snapshots can authorize a lease: its views are published after the
    /// verified checkpoint and corresponding state commit in one transaction.
    pub fn acquire(self: *Reader, parent: Parent) !Lease {
        if (self.eth.kv_store != self.snapshots.store) return error.NativeStateStoreMismatch;
        try self.mutex.lock(self.snapshots.io);
        defer self.mutex.unlock(self.snapshots.io);
        if (self.active_leases == max_leases) return error.NativeStateLeaseLimit;
        const view = try self.snapshots.acquire(parent.block_hash, parent.state_root);
        errdefer view.deinit();
        if (view.header.slot_number == null or view.header.block_access_list_hash == null) return error.PostGloasRequired;
        try self.snapshots.io.checkCancel();
        self.active_leases += 1;
        return .{ .owner = self, .view = view };
    }

    /// Does not own/close Eth, Snapshots or Store. This checks shutdown order.
    pub fn deinit(self: *Reader) void {
        std.debug.assert(self.active_leases == 0);
    }

    fn release(self: *Reader) void {
        self.mutex.lockUncancelable(self.snapshots.io);
        defer self.mutex.unlock(self.snapshots.io);
        std.debug.assert(self.active_leases > 0);
        self.active_leases -= 1;
    }
};

pub const Lease = struct {
    owner: *Reader,
    view: ?View,
    node_cache: ?*NodeCache = null,

    pub fn deinit(self: *Lease) void {
        if (self.view) |view| {
            self.view = null;
            if (self.node_cache) |cache| cache.deinit();
            self.node_cache = null;
            view.deinit();
            self.owner.release();
        }
    }

    /// Explicit opt-in; the uncached baseline remains the default. The caller's
    /// allocator outlives this lease. Metadata capacity is reserved once, owned
    /// RLP grows within max_bytes, and full caches fall back without eviction.
    pub fn enableNodeCache(self: *Lease, a: A, options: NodeCacheOptions) !void {
        const view = try self.checkedView();
        if (self.node_cache != null) return error.NativeNodeCacheAlreadyEnabled;
        const cache = try NodeCache.init(a, options);
        errdefer cache.deinit();
        if (!std.meta.eql(view.header.state_root, types.empty_root_hash))
            try cache.authorize(NodeCache.Key.init(null, &.{}), view.header.state_root);
        try self.owner.snapshots.io.checkCancel();
        self.node_cache = cache;
    }

    pub fn nodeCacheStats(self: *const Lease) NodeCacheStats {
        return if (self.node_cache) |cache| cache.stats else .{};
    }

    pub fn header(self: *const Lease) !types.BlockHeader {
        return (self.view orelse return error.NativeStateLeaseClosed).header;
    }

    pub fn stamp(self: *const Lease) !Stamp {
        const view = self.view orelse return error.NativeStateLeaseClosed;
        return .{
            .block_hash = view.header.hash(),
            .state_root = view.header.state_root,
            .block_number = view.header.number,
            .database_version = view.txn.id(),
        };
    }

    fn checkedView(self: *const Lease) !View {
        const view = self.view orelse return error.NativeStateLeaseClosed;
        try self.owner.snapshots.io.checkCancel();
        return view;
    }

    /// A zero account requires a proven absent path in this exact root. Flat
    /// state can reconstruct a leaf only if its encoding matches the trie hash.
    pub fn readAccount(self: *const Lease, a: A, address: u160) !types.Account {
        const view = try self.checkedView();
        var account_trie = try self.owner.eth.openAccountTrie(a, view.txn, view.header.state_root);
        defer self.owner.eth.closeAccountTrie(&account_trie);
        const encoded = try account_trie.inner.getAuthenticated(types.keccakOfU160(address)) orelse return types.EmptyAccount;
        var account: types.Account = undefined;
        if (try rlp.deserialize(types.Account, a, encoded, &account) != encoded.len) return error.MalformedAccount;
        if (self.node_cache) |cache| if (!std.meta.eql(account.storage_hash, types.empty_root_hash)) {
            try self.owner.snapshots.io.checkCancel();
            try cache.authorize(NodeCache.Key.init(address, &.{}), account.storage_hash);
        };
        return account;
    }

    pub fn readStorage(self: *const Lease, a: A, address: u160, slot: u256) !u256 {
        const account = try self.readAccount(a, address);
        if (std.meta.eql(account.storage_hash, types.empty_root_hash)) return 0;
        const view = try self.checkedView();
        var storage_trie = try self.owner.eth.openStorageTrie(a, view.txn, types.keccakOfU160(address), account.storage_hash);
        defer self.owner.eth.closeStorageTrie(&storage_trie);
        const encoded = try storage_trie.inner.getAuthenticated(types.keccakOfU256(slot)) orelse return 0;
        var value: u256 = undefined;
        if (try rlp.deserialize(u256, a, encoded, &value) != encoded.len) return error.MalformedStorage;
        return value;
    }

    /// The caller obtains this hash from an authenticated account or deployed
    /// candidate code. Hash-valid code alone never authorizes an account value.
    pub fn readCode(self: *const Lease, a: A, hash: Hash) ![]const u8 {
        const view = try self.checkedView();
        if (std.meta.eql(hash, types.empty_code_hash)) return &.{};
        const bytes = try self.owner.eth.kv_store.table(view.txn, .codes).get(&hash) orelse return error.CodeUnavailable;
        if (bytes.len > 128 * 1024) return error.StateCodeLimit;
        var actual: Hash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(bytes, &actual, .{});
        if (!std.meta.eql(actual, hash)) return error.CodeHashMismatch;
        return a.dupe(u8, bytes);
    }

    /// Supply one finalizer preimage only after authenticating its reachability
    /// at the requested nibble boundary. This is not an unrestricted DB read.
    pub fn readNode(self: *const Lease, a: A, owner: ?u160, path: []const u8, expected_hash: Hash) ![]const u8 {
        if (path.len > 64) return error.InvalidTrieNodePath;
        for (path) |nibble| if (nibble > 15) return error.InvalidTrieNodePath;
        const view = try self.checkedView();
        if (self.node_cache) |cache| {
            cache.stats.requests += 1;
            const key = NodeCache.Key.init(owner, path);
            if (cache.entries.get(key)) |entry| {
                if (!std.meta.eql(entry.hash, expected_hash)) return error.TrieNodeHashMismatch;
                if (entry.bytes) |bytes| {
                    cache.stats.hits += 1;
                    return a.dupe(u8, bytes);
                }
                cache.stats.authorized_reads += 1;
                const bytes = if (owner) |address| storage: {
                    // A storage edge can only be installed after its owner
                    // root. At capacity no new edges are admitted either.
                    const root = cache.entries.get(NodeCache.Key.init(address, &.{})).?.hash;
                    var storage_trie = try self.owner.eth.openStorageTrie(a, view.txn, types.keccakOfU160(address), root);
                    defer self.owner.eth.closeStorageTrie(&storage_trie);
                    break :storage try storage_trie.inner.nodePreimageAtPath(path, expected_hash);
                } else account: {
                    var account_trie = try self.owner.eth.openAccountTrie(a, view.txn, view.header.state_root);
                    defer self.owner.eth.closeAccountTrie(&account_trie);
                    break :account try account_trie.inner.nodePreimageAtPath(path, expected_hash);
                };
                try self.rememberNode(a, cache, key, expected_hash, bytes);
                return bytes;
            }
            cache.stats.fallback_reads += 1;
            const bytes = try self.readNodeUncached(a, view, owner, path, expected_hash);
            try self.rememberNode(a, cache, key, expected_hash, bytes);
            return bytes;
        }
        return self.readNodeUncached(a, view, owner, path, expected_hash);
    }

    fn rememberNode(self: *const Lease, a: A, cache: *NodeCache, key: NodeCache.Key, expected: Hash, bytes: []const u8) !void {
        // Parse and validate the entire edge set before publishing any of it.
        // A cancelled/OOM parse cannot grant a partially decoded path.
        const children = try trie.Trie.hashedChildReferences(a, bytes, key.path[0..key.depth]);
        try self.owner.snapshots.io.checkCancel();
        try cache.remember(key, expected, bytes, children);
    }

    fn readNodeUncached(self: *const Lease, a: A, view: View, owner: ?u160, path: []const u8, expected_hash: Hash) ![]const u8 {
        if (owner) |address| {
            const storage_root = root: {
                // A missing child edge still needs a complete storage-root walk.
                // The owner root may already be authenticated in this exact,
                // non-evicting lease even when its authorization map is full.
                if (self.node_cache) |cache| {
                    if (cache.entries.get(NodeCache.Key.init(address, &.{}))) |entry| break :root entry.hash;
                    cache.stats.owner_reads += 1;
                }
                break :root (try self.readAccount(a, address)).storage_hash;
            };
            var storage_trie = try self.owner.eth.openStorageTrie(a, view.txn, types.keccakOfU160(address), storage_root);
            defer self.owner.eth.closeStorageTrie(&storage_trie);
            return storage_trie.inner.nodeAtPath(path, expected_hash);
        }
        var account_trie = try self.owner.eth.openAccountTrie(a, view.txn, view.header.state_root);
        defer self.owner.eth.closeAccountTrie(&account_trie);
        return account_trie.inner.nodeAtPath(path, expected_hash);
    }

    pub fn readNodes(self: *const Lease, a: A, queries: []const NodeQuery) ![]const []const u8 {
        if (queries.len == 0 or queries.len > 16) return error.StateQueryLimit;
        const result = try a.alloc([]const u8, queries.len);
        for (queries, result) |query, *entry| entry.* = try self.readNode(a, query.owner, query.path, query.expected_hash);
        return result;
    }

    /// State stays on the lease. Immutable, hash-keyed ancestors may have been
    /// backfilled later, so only this header lookup opens a fresh RO transaction.
    /// Follow the leased parent's hashes and validate every height; never use
    /// selected-height lookup or a new state checkpoint to stand in for it.
    pub fn readAncestors(self: *const Lease, a: A, count: u16) ![]const types.BlockHeader {
        const view = try self.checkedView();
        if (count == 0 or count > 256 or count - 1 > view.header.number) return error.AncestorQueryLimit;
        const store = self.owner.eth.kv_store;
        const txn = try store.transaction_ro();
        defer txn.abort() catch unreachable;
        const result = try a.alloc(types.BlockHeader, count);
        var current = view.header;
        for (result, 0..) |*entry, i| {
            try self.owner.snapshots.io.checkCancel();
            entry.* = current;
            if (i + 1 == count) break;
            const previous = try branches.byHash(store, txn, current.parent_hash) orelse return error.AncestorUnavailable;
            if (!std.meta.eql(previous.hash(), current.parent_hash) or previous.number != current.number - 1) return error.BranchParentMismatch;
            current = previous;
        }
        return result;
    }
};
