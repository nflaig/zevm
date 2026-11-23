// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const jsonrpc = @import("jsonrpc.zig");
const jwt = @import("jwt.zig");

pub const HttpServer = struct {
    const Self = @This();

    const io_buf_len = 8 * 1024;
    const max_body_len = 1024 * 1024;

    io: std.Io,
    arena: std.heap.ArenaAllocator,
    rpc: *const jsonrpc.Server,
    listener: std.Io.net.Server,
    jwt_secret: ?jwt.Secret = null,

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        rpc: *const jsonrpc.Server,
        addr: std.Io.net.IpAddress,
    ) !Self {
        return .{
            .io = io,
            .arena = .init(allocator),
            .rpc = rpc,
            .listener = try addr.listen(io, .{ .reuse_address = true }),
        };
    }

    pub fn with_auth(self: Self, secret: jwt.Secret) Self {
        var s = self;
        s.jwt_secret = secret;
        return s;
    }

    pub fn deinit(self: *Self) void {
        self.listener.deinit(self.io);
        self.arena.deinit();
    }

    pub fn run(self: *Self) !void {
        while (true) try self.serveOne();
    }

    pub fn serveOne(self: *Self) !void {
        const stream = self.listener.accept(self.io) catch |e| switch (e) {
            error.Canceled, error.SocketNotListening => return e,
            else => return,
        };
        defer stream.close(self.io);
        defer _ = self.arena.reset(.retain_capacity);
        self.serve(stream) catch |e| if (e == error.Canceled) return e;
    }

    fn serve(self: *Self, stream: std.Io.net.Stream) !void {
        var in_buf: [io_buf_len]u8 = undefined;
        var out_buf: [io_buf_len]u8 = undefined;
        var reader = stream.reader(self.io, &in_buf);
        var writer = stream.writer(self.io, &out_buf);
        self.exchange(&reader, &writer) catch |e| {
            // Generic Reader/Writer erase the underlying cancellation error.
            // Io cancellation is delivered once: swallowing it here could
            // send run() back into accept and prevent shutdown from joining.
            if (reader.err) |cause| if (cause == error.Canceled) return error.Canceled;
            if (writer.err) |cause| if (cause == error.Canceled) return error.Canceled;
            return e;
        };
    }

    fn exchange(self: *Self, reader: *std.Io.net.Stream.Reader, writer: *std.Io.net.Stream.Writer) !void {
        const allocator = self.arena.allocator();
        var http = std.http.Server.init(&reader.interface, &writer.interface);

        var request = try http.receiveHead();
        if (request.head.method != .POST) {
            return request.respond("", .{ .status = .method_not_allowed, .keep_alive = false });
        }

        if (self.jwt_secret) |*secret| {
            const now = std.Io.Clock.real.now(self.io).toSeconds();
            const authorized = if (bearerToken(&request)) |token|
                jwt.verify(allocator, secret, token, now) catch {
                    return request.respond("", .{ .status = .internal_server_error, .keep_alive = false });
                }
            else
                false;
            if (!authorized) {
                return request.respond("", .{ .status = .unauthorized, .keep_alive = false });
            }
        }

        const body_reader = try request.readerExpectContinue(&.{});
        const body = body_reader.allocRemaining(allocator, .limited(max_body_len)) catch |e| switch (e) {
            error.StreamTooLong => return request.respond("", .{ .status = .payload_too_large, .keep_alive = false }),
            else => return e,
        };

        const response = self.rpc.handle(self.io, allocator, body) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return request.respond("", .{ .status = .internal_server_error, .keep_alive = false }),
        };

        try request.respond(response.raw, .{
            .keep_alive = false,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
        });
    }
};

fn bearerToken(request: *const std.http.Server.Request) ?[]const u8 {
    const prefix = "Bearer ";
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "authorization")) continue;
        if (header.value.len < prefix.len or !std.ascii.eqlIgnoreCase(header.value[0..prefix.len], prefix)) return null;
        return std.mem.trim(u8, header.value[prefix.len..], " ");
    }
    return null;
}

test "HTTP propagates handler cancellation through connection cleanup" {
    const io = std.testing.io;
    const a = std.testing.allocator;
    const API = struct {
        fn cancelled(_: *@This(), _: std.Io, _: std.mem.Allocator) error{Canceled}!void {
            return error.Canceled;
        }
    };
    var api: API = .{};
    var rpc: jsonrpc.Server = .{};
    defer rpc.deinit(a);
    try rpc.register(a, "cancelled", &api, API.cancelled);
    var server = try HttpServer.init(io, a, &rpc, try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0));
    defer server.deinit();
    var serving = io.concurrent(HttpServer.serveOne, .{&server}) catch return error.SkipZigTest;
    defer serving.cancel(io) catch {};
    const client = try server.listener.socket.address.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    });
    defer client.close(io);
    var buffer: [1024]u8 = undefined;
    var writer = client.writer(io, &buffer);
    const body =
        \\{"jsonrpc":"2.0","method":"cancelled","params":[],"id":1}
    ;
    try writer.interface.print("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body });
    try writer.interface.flush();
    try std.testing.expectError(error.Canceled, serving.await(io));
}

test "HTTP incomplete request cancellation retains its socket cause" {
    const io = std.testing.io;
    var rpc: jsonrpc.Server = .{};
    defer rpc.deinit(std.testing.allocator);
    var server = try HttpServer.init(io, std.testing.allocator, &rpc, try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0));
    defer server.deinit();
    const client = try server.listener.socket.address.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.listener.accept(io);
    defer accepted.close(io);
    // No bytes are sent. Cancel is consumed by the first socket read whether
    // requested before or after serve starts; no sleep/timing race is needed.
    var serving = io.concurrent(HttpServer.serve, .{ &server, accepted }) catch return error.SkipZigTest;
    defer serving.cancel(io) catch {};
    try std.testing.expectError(error.Canceled, serving.cancel(io));
}
