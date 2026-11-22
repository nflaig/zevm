// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const lmdbx = @import("lmdbx");

pub const Transaction = lmdbx.Transaction;
pub const Cursor = lmdbx.Cursor;

pub const Table = enum {
    accounts,
    storage,
    codes,
    account_trie,
    storage_tries,
    state_meta,
    state_undo,
    branch_headers,
    branch_numbers,

    pub fn options(self: Table) lmdbx.Database.Options {
        return switch (self) {
            .storage, .storage_tries => .{ .dup_sort = true },
            else => .{},
        };
    }
};

const table_count = std.enums.values(Table).len;

pub const Store = struct {
    env: lmdbx.Environment,
    dbis: [table_count]lmdbx.Database.DBI,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !Store {
        return initBounded(allocator, path, 8 << 40, 16 << 30);
    }

    /// Open an existing database without creating tables, starting a writer,
    /// or changing geometry/sync policy. MDBX still maintains its reader lock
    /// table; this is not a promise of zero filesystem writes. Use one Store per
    /// path per process. A separate constructor process can publish the current
    /// verified checkpoint into its own Snapshots and acquire that exact view;
    /// it cannot recover arbitrary historical views by opening this database.
    pub fn openReadOnly(allocator: std.mem.Allocator, path: []const u8) !Store {
        const init_path = try allocator.dupeSentinel(u8, path, 0);
        defer allocator.free(init_path);
        const env = try lmdbx.Environment.init(init_path, .{
            .max_dbs = table_count,
            .read_only = true,
            .no_read_ahead = true,
            .no_sticky_threads = true,
        });
        errdefer env.deinit() catch {};
        const txn = try env.transaction(.{ .mode = .ReadOnly });
        errdefer txn.abort() catch {};
        var dbis: [table_count]lmdbx.Database.DBI = undefined;
        for (std.enums.values(Table)) |t| {
            const db = try txn.database(@tagName(t), t.options());
            dbis[@backingInt(t)] = db.dbi;
        }
        // Committing a RO transaction publishes its opened DBI handles; it
        // performs no state write. Aborting would invalidate newly opened DBIs.
        try txn.commit();
        return .{ .env = env, .dbis = dbis };
    }

    pub fn initBounded(allocator: std.mem.Allocator, path: []const u8, upper_size: isize, growth_step: isize) !Store {
        if (growth_step <= 0 or growth_step > upper_size) return error.InvalidDatabaseLimit;
        const init_path = try allocator.dupeSentinel(u8, path, 0);
        defer allocator.free(init_path);

        const env = try lmdbx.Environment.init(init_path, .{
            .max_dbs = table_count,
            .safe_nosync = true,
            .sync_bytes = 256 << 20,
            .sync_period_ms = 10_000,
            .write_map = true,
            .no_read_ahead = true,
            .geometry = .{
                .lower_size = 0,
                .upper_size = upper_size,
                .growth_step = growth_step,
                .shrink_threshold = 0,
            },
            .no_sticky_threads = true,
        });
        errdefer env.deinit() catch {};

        if (lmdbx.c.mdbx_env_set_option(env.ptr, @bitCast(lmdbx.c.MDBX_opt_rp_augment_limit), 256 * 1024) != lmdbx.c.MDBX_SUCCESS)
            return error.SetOptionFailed;

        var dbis: [table_count]lmdbx.Database.DBI = undefined;

        const txn = try env.transaction(.{ .mode = .ReadWrite });
        errdefer txn.abort() catch {};

        for (std.enums.values(Table)) |t| {
            var opts = t.options();
            opts.create = true;
            const db = try txn.database(@tagName(t), opts);
            dbis[@backingInt(t)] = db.dbi;
        }

        try txn.commit();

        return .{ .env = env, .dbis = dbis };
    }

    pub fn deinit(self: *Store) !void {
        try self.env.deinit();
    }

    pub fn transaction_ro(self: *const Store) !Transaction {
        return try self.env.transaction(.{ .mode = .ReadOnly });
    }

    pub fn transaction_rw(self: *const Store) !Transaction {
        return try self.env.transaction(.{ .mode = .ReadWrite });
    }

    pub fn table(self: *const Store, txn: Transaction, t: Table) lmdbx.Database {
        return .{ .txn = txn, .dbi = self.dbis[@backingInt(t)] };
    }
};
