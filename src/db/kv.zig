// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const lmdbx = @import("lmdbx");

pub const Transaction = lmdbx.Transaction;
pub const Cursor = lmdbx.Cursor;

/// Owns one MDBX handle. Do not copy; borrow `txn` only before commit/deinit.
/// Commit consumes a valid handle on success AND failure, except the documented
/// wrong-thread rejection. A later fallible operation must never abort it again.
pub const OwnedTransaction = struct {
    txn: Transaction,
    live: bool = true,

    pub fn deinit(self: *OwnedTransaction) void {
        if (self.live) {
            self.live = false;
            self.txn.abort() catch unreachable;
        }
    }

    pub fn commit(self: *OwnedTransaction) !void {
        std.debug.assert(self.live);
        self.live = false;
        const rc = lmdbx.c.mdbx_txn_commit(self.txn.ptr);
        if (rc == lmdbx.c.MDBX_SUCCESS) return;
        // The wrapper's generic throw accepts RESULT_TRUE, but for commit this
        // means a previously broken transaction was aborted. Never publish it.
        if (rc == lmdbx.c.MDBX_RESULT_TRUE) return error.DatabaseTransactionAborted;
        if (rc == lmdbx.c.MDBX_THREAD_MISMATCH) self.live = true;
        inline for (@typeInfo(lmdbx.Error).error_set.error_names.?) |name| {
            if (@hasDecl(lmdbx.c, name)) {
                if (rc == @field(lmdbx.c, name)) return @field(lmdbx.Error, name);
            }
        }
        return switch (rc) {
            lmdbx.c.MDBX_EINVAL => error.INVAL,
            lmdbx.c.MDBX_EACCESS => error.ACCESS,
            lmdbx.c.MDBX_ENOMEM => error.NOMEM,
            lmdbx.c.MDBX_EROFS => error.ROFS,
            lmdbx.c.MDBX_ENOSYS => error.NOSYS,
            lmdbx.c.MDBX_EIO => error.IO,
            lmdbx.c.MDBX_EPERM => error.PERM,
            lmdbx.c.MDBX_EINTR => error.INTR,
            lmdbx.c.MDBX_EDEADLK => error.DEADLK,
            else => error.MDBX_UNKNOWN_ERROR,
        };
    }
};

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
        var owned: OwnedTransaction = .{ .txn = try env.transaction(.{ .mode = .ReadOnly }) };
        defer owned.deinit();
        const txn = owned.txn;
        var dbis: [table_count]lmdbx.Database.DBI = undefined;
        for (std.enums.values(Table)) |t| {
            const db = try txn.database(@tagName(t), t.options());
            dbis[@backingInt(t)] = db.dbi;
        }
        // Committing a RO transaction publishes its opened DBI handles; it
        // performs no state write. Aborting would invalidate newly opened DBIs.
        try owned.commit();
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

        var owned: OwnedTransaction = .{ .txn = try env.transaction(.{ .mode = .ReadWrite }) };
        defer owned.deinit();
        const txn = owned.txn;

        for (std.enums.values(Table)) |t| {
            var opts = t.options();
            opts.create = true;
            const db = try txn.database(@tagName(t), opts);
            dbis[@backingInt(t)] = db.dbi;
        }

        try owned.commit();

        return .{ .env = env, .dbis = dbis };
    }

    /// Shadow admission checks the existing allocation before MDBX can change
    /// geometry. One writer owns this directory; concurrent opens/geometry
    /// changes by another owner are outside the Store contract.
    pub fn initBoundedChecked(io: std.Io, allocator: std.mem.Allocator, path: []const u8, upper_size: isize, growth_step: isize) !Store {
        if (growth_step <= 0 or growth_step > upper_size) return error.InvalidDatabaseLimit;
        const dir = try std.Io.Dir.cwd().openDir(io, path, .{});
        defer dir.close(io);
        const existing: ?std.Io.File.Stat = dir.statFile(io, "mdbx.dat", .{}) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |stat| {
            if (stat.size > @as(u64, @intCast(upper_size))) return error.ShadowDatabaseAlreadyLarger;
        }
        var store = try initBounded(allocator, path, upper_size, growth_step);
        errdefer store.deinit() catch {};
        const geometry = (try store.env.info()).geo;
        if (geometry.current > @as(u64, @intCast(upper_size)) or geometry.upper > @as(u64, @intCast(upper_size)))
            return error.ShadowDatabaseLimitNotApplied;
        return store;
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
