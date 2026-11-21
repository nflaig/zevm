// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact-parent, bounded MVCC views for the optional shadow state reader.
//! A checkpoint is written only after complete state hashing, or atomically
//! with a BAL update whose root was checked. Header sync is not state readiness.
const std = @import("std");
const rlp = @import("rlp");
const kv = @import("kv.zig");
const types = @import("../types.zig");

const checkpoint_key = "verified-state-v1";

pub fn readCheckpoint(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator) !?types.BlockHeader {
    const encoded = try store.table(txn, .state_meta).get(checkpoint_key) orelse return null;
    var header: types.BlockHeader = undefined;
    const consumed = try rlp.deserialize(types.BlockHeader, allocator, encoded, &header);
    if (consumed != encoded.len) return error.InvalidStateCheckpoint;
    return header;
}

/// Caller must have verified the complete state root and code availability.
/// The marker and the corresponding flat/trie data share one DB transaction.
pub fn writeCheckpoint(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator, header: types.BlockHeader) !void {
    var encoded = std.array_list.Managed(u8).init(allocator);
    defer encoded.deinit();
    try rlp.serialize(types.BlockHeader, allocator, header, &encoded);
    try store.table(txn, .state_meta).set(checkpoint_key, encoded.items, .Upsert);
}

pub const View = struct {
    txn: kv.Transaction,
    header: types.BlockHeader,

    pub fn deinit(self: View) void {
        self.txn.abort() catch unreachable;
    }
};

pub const Snapshots = struct {
    pub const capacity = 8;
    io: std.Io,
    store: *kv.Store,
    mutex: std.Io.Mutex = .init,
    views: [capacity]?View = @splat(null),
    next: usize = 0,

    pub fn deinit(self: *Snapshots) void {
        for (&self.views) |*view| {
            if (view.*) |v| v.deinit();
            view.* = null;
        }
    }

    /// Open only after the writer commits. Reads clone a retained transaction;
    /// they never reopen the latest DB and label it with an older block hash.
    pub fn publish(self: *Snapshots, allocator: std.mem.Allocator) !void {
        const txn = try self.store.transaction_ro();
        errdefer txn.abort() catch unreachable;
        const header = try readCheckpoint(self.store, txn, allocator) orelse return error.StateNotReady;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.views, 0..) |view, index| if (view) |v| {
            if (std.meta.eql(v.header.hash(), header.hash())) {
                if (!std.meta.eql(v.header.state_root, header.state_root)) return error.StateRootMismatch;
                // A rewind can make a retained parent the selected checkpoint
                // again. Promote the new committed view without evicting a
                // different branch or invalidating outstanding cloned leases.
                v.deinit();
                var position = index;
                const newest = (self.next + capacity - 1) % capacity;
                while (position != newest) {
                    const following = (position + 1) % capacity;
                    self.views[position] = self.views[following];
                    position = following;
                }
                self.views[newest] = .{ .txn = txn, .header = header };
                return;
            }
        };
        if (self.views[self.next]) |old| old.deinit();
        self.views[self.next] = .{ .txn = txn, .header = header };
        self.next = (self.next + 1) % capacity;
    }

    pub fn acquire(self: *Snapshots, hash: [32]u8, root: [32]u8) !View {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.views) |view| if (view) |v| {
            if (std.meta.eql(v.header.hash(), hash)) {
                if (!std.meta.eql(v.header.state_root, root)) return error.StateRootMismatch;
                return .{ .txn = try v.txn.clone(null), .header = v.header };
            }
        };
        return error.StateViewUnavailable;
    }

    pub const Status = struct {
        headers: [capacity]types.BlockHeader = undefined,
        versions: [capacity]u64 = undefined,
        count: usize = 0,
    };

    pub fn status(self: *Snapshots) Status {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var result: Status = .{};
        for (0..capacity) |i| if (self.views[(self.next + capacity - 1 - i) % capacity]) |v| {
            result.headers[result.count] = v.header;
            result.versions[result.count] = v.txn.id();
            result.count += 1;
        };
        return result;
    }
};
