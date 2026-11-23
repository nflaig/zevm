// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");

pub const default_database_gib: u16 = 16;
pub const maximum_database_gib: u16 = 256;
pub const database_growth_bytes: isize = 256 << 20;

/// An explicit resource admission limit, never an automatic growth policy.
pub fn parseDatabaseLimit(shadow_state: bool, requested_gib: ?[]const u8) !isize {
    if (requested_gib != null and !shadow_state) return error.ShadowStateRequired;
    const gib = if (requested_gib) |raw|
        std.fmt.parseInt(u16, raw, 10) catch return error.InvalidShadowDatabaseLimit
    else
        default_database_gib;
    if (gib == 0 or gib > maximum_database_gib) return error.InvalidShadowDatabaseLimit;
    return databaseBytes(isize, gib);
}

fn databaseBytes(comptime T: type, gib: u16) !T {
    const units = std.math.cast(T, gib) orelse return error.InvalidShadowDatabaseLimit;
    return std.math.mul(T, units, 1 << 30) catch error.InvalidShadowDatabaseLimit;
}

test "shadow database CLI limit preserves defaults and admits explicit bounded sizes" {
    try std.testing.expectEqual(@as(isize, 16 << 30), try parseDatabaseLimit(true, null));
    try std.testing.expectEqual(@as(isize, 16 << 30), try parseDatabaseLimit(false, null));
    try std.testing.expectEqual(@as(isize, 1 << 30), try parseDatabaseLimit(true, "1"));
    try std.testing.expectEqual(@as(isize, 64 << 30), try parseDatabaseLimit(true, "64"));
    try std.testing.expectEqual(@as(isize, 128 << 30), try parseDatabaseLimit(true, "128"));
    try std.testing.expectEqual(@as(isize, 129 << 30), try parseDatabaseLimit(true, "129"));
    try std.testing.expectEqual(@as(isize, 256 << 30), try parseDatabaseLimit(true, "256"));
    try std.testing.expectEqual(@as(isize, 256 << 20), database_growth_bytes);
}

test "shadow database CLI limit rejects dependency range syntax and arithmetic overflow" {
    try std.testing.expectError(error.ShadowStateRequired, parseDatabaseLimit(false, "256"));
    for ([_][]const u8{ "", "0", "257", "-1", "1.5", "64GiB", "65536", "18446744073709551615" }) |raw|
        try std.testing.expectError(error.InvalidShadowDatabaseLimit, parseDatabaseLimit(true, raw));
    try std.testing.expectError(error.InvalidShadowDatabaseLimit, databaseBytes(i32, 128));
    try std.testing.expectError(error.InvalidShadowDatabaseLimit, databaseBytes(i32, 256));
}
