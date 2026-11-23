// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only qualification tool for the native beacon target tracker.
const std = @import("std");
const consensus = @import("node/consensus.zig");
const HexHash = @import("rpc/hex.zig").Data(32);

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.ExpectedUrlUpdateCountAndTimeoutSeconds;
    const count = try std.fmt.parseInt(usize, args[2], 10);
    const seconds = try std.fmt.parseInt(u32, args[3], 10);
    if (count == 0 or count > 10000 or seconds == 0 or seconds > 600) return error.InvalidLimit;
    var buffer: [4]consensus.Update = undefined;
    var updates: std.Io.Queue(consensus.Update) = .init(&buffer);
    var tracker = try consensus.Tracker.init(init.io, init.gpa, args[1], &updates);
    defer tracker.deinit();
    const Event = union(enum) { worker: anyerror!void, update: anyerror!consensus.Update, timeout: anyerror!void };
    var events: [3]Event = undefined;
    var select: std.Io.Select(Event) = .init(init.io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.worker, consensus.Tracker.run, .{&tracker});
    try select.concurrent(.update, std.Io.Queue(consensus.Update).getOne, .{ &updates, init.io });
    try select.concurrent(.timeout, std.Io.sleep, .{ init.io, .fromSeconds(seconds), .awake });
    var out_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &out_buffer);
    for (0..count) |_| switch (try select.await()) {
        .worker => |result| {
            try result;
            return error.TrackerStopped;
        },
        .timeout => return error.ObservationTimeout,
        .update => |result| {
            const update = try result;
            try std.json.Stringify.value(.{
                .beaconAnchor = HexHash{ .bytes = update.anchor.beacon_root },
                .executionAnchor = HexHash{ .bytes = update.anchor.execution_hash },
                .executionHead = HexHash{ .bytes = update.head.hash },
                .slot = update.head.slot,
                .observedAtMs = update.observed_at_ms,
            }, .{}, &stdout.interface);
            try stdout.interface.writeByte('\n');
            try stdout.interface.flush();
            try select.concurrent(.update, std.Io.Queue(consensus.Update).getOne, .{ &updates, init.io });
        },
    };
}
