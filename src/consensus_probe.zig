// Copyright (c) 2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only qualification tool for the native beacon target tracker.
const std = @import("std");
const consensus = @import("node/consensus.zig");
const HexHash = @import("rpc/hex.zig").Data(32);

test {
    _ = consensus;
}

const Attribute = struct {
    parent: HexHash,
    beaconRoot: HexHash,
    jsonHash: HexHash,
    receivedWallMs: i64,
    receivedMonoMs: i64,
    deliveredMonoMs: i64,
};

const AttributeSink = struct {
    io: std.Io,
    queue: *std.Io.Queue(Attribute),

    fn accept(context: *anyopaque, event: consensus.AttributesEvent) bool {
        const self: *AttributeSink = @ptrCast(@alignCast(context));
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(event.json, &hash, .{});
        const row: Attribute = .{
            .parent = .{ .bytes = event.parent.hash },
            .beaconRoot = .{ .bytes = event.beacon_root },
            .jsonHash = .{ .bytes = hash },
            .receivedWallMs = event.received_wall_ms,
            .receivedMonoMs = event.received_mono_ms,
            .deliveredMonoMs = @intCast(std.Io.Clock.awake.now(self.io).toMilliseconds()),
        };
        return (self.queue.put(self.io, &.{row}, 0) catch return false) == 1;
    }

    fn invalidate(_: *anyopaque) void {}
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4 and args.len != 5) return error.ExpectedUrlUpdateCountAndTimeoutSeconds;
    const attributes = args.len == 5 and std.mem.eql(u8, args[4], "attributes");
    if (args.len == 5 and !attributes) return error.InvalidObservationKind;
    const count = try std.fmt.parseInt(usize, args[2], 10);
    const seconds = try std.fmt.parseInt(u32, args[3], 10);
    if (count == 0 or count > 10000 or seconds == 0 or seconds > 600) return error.InvalidLimit;
    var buffer: [4]consensus.Update = undefined;
    var updates: std.Io.Queue(consensus.Update) = .init(&buffer);
    var tracker = try consensus.Tracker.init(init.io, init.gpa, args[1], &updates);
    defer tracker.deinit();
    var attribute_buffer: [8]Attribute = undefined;
    var attribute_queue: std.Io.Queue(Attribute) = .init(&attribute_buffer);
    var sink: AttributeSink = .{ .io = init.io, .queue = &attribute_queue };
    if (attributes) tracker.attributes_sink = .{ .context = &sink, .accept = AttributeSink.accept, .invalidate = AttributeSink.invalidate };
    const Event = union(enum) { worker: anyerror!void, update: anyerror!consensus.Update, attribute: anyerror!Attribute, timeout: anyerror!void };
    var events: [4]Event = undefined;
    var select: std.Io.Select(Event) = .init(init.io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.worker, consensus.Tracker.run, .{&tracker});
    try select.concurrent(.update, std.Io.Queue(consensus.Update).getOne, .{ &updates, init.io });
    if (attributes) try select.concurrent(.attribute, std.Io.Queue(Attribute).getOne, .{ &attribute_queue, init.io });
    try select.concurrent(.timeout, std.Io.sleep, .{ init.io, .fromSeconds(seconds), .awake });
    var out_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &out_buffer);
    var observed: usize = 0;
    while (observed < count) switch (try select.await()) {
        .worker => |result| {
            try result;
            return error.TrackerStopped;
        },
        .timeout => return error.ObservationTimeout,
        .attribute => |result| {
            try std.json.Stringify.value(try result, .{}, &stdout.interface);
            try stdout.interface.writeByte('\n');
            try stdout.interface.flush();
            observed += 1;
            try select.concurrent(.attribute, std.Io.Queue(Attribute).getOne, .{ &attribute_queue, init.io });
        },
        .update => |result| {
            const update = try result;
            if (!attributes) {
                try std.json.Stringify.value(.{
                    .beaconAnchor = HexHash{ .bytes = update.anchor.beacon_root },
                    .executionAnchor = HexHash{ .bytes = update.anchor.execution_hash },
                    .executionHead = HexHash{ .bytes = update.head.hash },
                    .slot = update.head.slot,
                    .observedAtMs = update.observed_at_ms,
                }, .{}, &stdout.interface);
                try stdout.interface.writeByte('\n');
                try stdout.interface.flush();
                observed += 1;
            }
            try select.concurrent(.update, std.Io.Queue(consensus.Update).getOne, .{ &updates, init.io });
        },
    };
}
