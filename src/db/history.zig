// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded, persistent hash-keyed records. Caller owns the encompassing RW txn.
const std = @import("std");
const rlp = @import("rlp");
const kv = @import("kv.zig");

pub fn History(comptime table: kv.Table, comptime capacity: usize, comptime max_bytes: usize) type {
    return struct {
        const Entry = struct { hash: [32]u8, size: u64 };
        const key = "history-v1:" ++ @tagName(table);

        pub fn put(store: *kv.Store, txn: kv.Transaction, allocator: std.mem.Allocator, hash: [32]u8, value: []const u8) !void {
            if (value.len > max_bytes) return error.StateHistoryLimit;
            const records = store.table(txn, table);
            if (try records.get(&hash)) |existing| {
                if (!std.mem.eql(u8, existing, value)) return error.StateHistoryConflict;
                return;
            }
            const meta = store.table(txn, .state_meta);
            var previous: []Entry = &.{};
            if (try meta.get(key)) |encoded| {
                if (encoded.len > capacity * 64 + 16) return error.InvalidStateHistory;
                if (try rlp.deserialize([]Entry, allocator, encoded, &previous) != encoded.len or previous.len > capacity)
                    return error.InvalidStateHistory;
            }
            var total: usize = value.len;
            for (previous) |entry| {
                if (entry.size > max_bytes or total > max_bytes * 2 - entry.size) return error.InvalidStateHistory;
                total += @intCast(entry.size);
            }
            var skip: usize = 0;
            while (total > max_bytes or previous.len - skip >= capacity) : (skip += 1) {
                if (skip == previous.len) return error.StateHistoryLimit;
                const old = previous[skip];
                try records.delete(&old.hash);
                total -= @intCast(old.size);
            }
            const next = try allocator.alloc(Entry, previous.len - skip + 1);
            @memcpy(next[0 .. next.len - 1], previous[skip..]);
            next[next.len - 1] = .{ .hash = hash, .size = value.len };
            var encoded = std.array_list.Managed(u8).init(allocator);
            defer encoded.deinit();
            try rlp.serialize([]const Entry, allocator, next, &encoded);
            try records.set(&hash, value, .Upsert);
            try meta.set(key, encoded.items, .Upsert);
        }
    };
}
