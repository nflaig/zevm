// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const clap = @import("clap");
const discv5 = @import("devp2p/discv5.zig");
const rlpx = @import("devp2p/rlpx.zig");
const proto = @import("devp2p/proto.zig");
const eth = @import("devp2p/eth.zig");
const snap = @import("devp2p/snap.zig");
const kv = @import("db/kv.zig");
const enr = @import("devp2p/enr.zig");
const bootnodes = @import("devp2p/bootnodes.zig");
const EthDb = @import("db/eth.zig").Eth;
const Dialer = @import("devp2p/dialer.zig").Dialer;
const SlabAllocator = @import("devp2p/allocator.zig").SlabAllocator;
const Record = @import("devp2p/enr.zig").Record;
const forks = @import("forks.zig");
const blockchain = @import("node/blockchain.zig");
const Blockchain = blockchain.Blockchain;
const Downloader = @import("node/downloader.zig").Downloader;
const FileStorage = @import("db/file.zig").Storage;
const EthApi = @import("rpc/eth.zig").Eth;
const EngineApi = @import("rpc/engine.zig").Engine;
const RpcServer = @import("rpc/jsonrpc.zig").Server;
const RpcHttpServer = @import("rpc/http.zig").HttpServer;
const jwt = @import("rpc/jwt.zig");
const metrics = @import("metrics.zig");
const Shutdown = @import("signals.zig").Shutdown;
const Snapshots = @import("db/snapshot.zig").Snapshots;
const ShadowApi = @import("rpc/shadow.zig").Shadow;
const consensus = @import("node/consensus.zig");
const public_intake = @import("node/public_intake.zig");
const public_intake_peer = @import("node/public_intake_peer.zig");

// A combined constructor imports this node module once. Re-exporting the
// owner's types avoids compiling a second, nominally distinct MDBX/state graph.
pub const NativeState = @import("native_state.zig");
pub const PublicHandoff = @import("node/public_handoff.zig");
pub const PublicIntake = public_intake;
pub const Consensus = consensus;
pub const BuilderOptions = struct {
    chain_id: u64,
    fee_recipient: u160,
    blobs: bool,
    output_dir: ?[]const u8,
    every_slots: u16 = 1,
};

pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = @import("log.zig").timestamped,
};

const Network = enum { glamsterdam_devnet8, mainnet, sepolia };
const shadow_limits = @import("shadow_limits.zig");

const params = clap.parseParamsComptime(
    \\-h, --help                Display this help and exit.
    \\-n, --network <network>   Network to join: glamsterdam_devnet8, mainnet, sepolia (default: glamsterdam_devnet8).
    \\-d, --datadir <str>       Data directory (default: datadir).
    \\    --port <u16>          RLPx TCP listening port (default: 30303).
    \\    --discovery-port <u16> discv5 UDP listening port (default: 33034).
    \\    --bootnode <str>...   Bootnode ENR, can be repeated. Replaces the network's default bootnodes.
    \\    --http-addr <str>     JSON-RPC HTTP listening address (default: 127.0.0.1).
    \\    --http-port <u16>     JSON-RPC HTTP listening port (default: 8545).
    \\    --authrpc-addr <str>  Authenticated (Engine API) RPC listening address (default: 127.0.0.1).
    \\    --authrpc-port <u16>  Authenticated (Engine API) RPC listening port (default: 8551).
    \\    --authrpc-jwtsecret <str> Path to the hex-encoded JWT secret; created if missing (default: <datadir>/jwt.hex).
    \\    --metrics-addr <str>  Prometheus metrics HTTP listening address (default: 127.0.0.1).
    \\    --metrics-port <u16>  Prometheus metrics HTTP listening port (default: 6060).
    \\    --shadow-state        Enable exact-parent state witness qualification.
    \\    --shadow-state-max-db-gib <str> Explicit shadow MDBX cap in GiB (1..128; default 16; requires --shadow-state).
    \\    --shadow-beacon-url <str> Follow a trusted local post-Gloas beacon node (requires --shadow-state).
    \\    --public-intake-observer Observe independent public transaction hashes/times (requires --shadow-state; never feeds construction).
    \\    --native-builder       Run an embedded shadow constructor (requires a combined binary and trusted beacon; never publishes bids).
    \\    --native-builder-fee-recipient <str> Explicit execution fee recipient for shadow construction.
    \\    --native-builder-blobs Enable verified live blob intake in the embedded constructor.
    \\    --native-builder-output-dir <str> Existing directory for bounded rotating qualification payloads.
    \\    --native-builder-every-slots <u16> Shadow duty: admit only slots divisible by this number (1..64; default 1).
    \\
);

const parsers = .{
    .str = clap.parsers.string,
    .u16 = clap.parsers.int(u16, 10),
    .network = clap.parsers.enumeration(Network),
};

const Options = struct {
    config: blockchain.Config,
    bootnodes: []const []const u8,
    datadir: []const u8,
    port: u16,
    discovery_port: u16,
    http_addr: std.Io.net.IpAddress,
    authrpc_addr: std.Io.net.IpAddress,
    authrpc_jwtsecret: ?[]const u8,
    metrics_addr: std.Io.net.IpAddress,
    shadow_state: bool,
    shadow_database_limit: isize,
    shadow_beacon_url: ?[]const u8,
    public_intake_observer: bool,
    native_builder: bool,
    builder_fee_recipient: u160,
    builder_blobs: bool,
    builder_output_dir: ?[]const u8,
    builder_every_slots: u16,

    fn parse(init: std.process.Init) !?Options {
        var diag = clap.Diagnostic{};
        const res = clap.parse(clap.Help, &params, parsers, init.minimal.args, .{
            .diagnostic = &diag,
            .allocator = init.arena.allocator(),
        }) catch |err| {
            try diag.reportToFile(init.io, std.Io.File.stderr(), err);
            std.process.exit(1);
        };

        if (res.args.help != 0) {
            try clap.helpToFile(init.io, std.Io.File.stderr(), clap.Help, &params, .{});
            return null;
        }

        const network = res.args.network orelse .glamsterdam_devnet8;
        const http_addr = res.args.@"http-addr" orelse "127.0.0.1";
        const http_port = res.args.@"http-port" orelse 8545;
        const authrpc_addr = res.args.@"authrpc-addr" orelse "127.0.0.1";
        const authrpc_port = res.args.@"authrpc-port" orelse 8551;
        const metrics_addr = res.args.@"metrics-addr" orelse "127.0.0.1";
        const metrics_port = res.args.@"metrics-port" orelse 6060;
        const shadow_database_limit = try shadow_limits.parseDatabaseLimit(res.args.@"shadow-state" != 0, res.args.@"shadow-state-max-db-gib");
        if (res.args.@"shadow-beacon-url" != null and res.args.@"shadow-state" == 0)
            return error.ShadowStateRequired;
        if (res.args.@"public-intake-observer" != 0 and res.args.@"shadow-state" == 0)
            return error.ShadowStateRequired;
        const native_builder = res.args.@"native-builder" != 0;
        if (native_builder and (res.args.@"shadow-state" == 0 or res.args.@"shadow-beacon-url" == null))
            return error.NativeBuilderRequiresTrustedState;
        if (!native_builder and (res.args.@"native-builder-fee-recipient" != null or
            res.args.@"native-builder-blobs" != 0 or res.args.@"native-builder-output-dir" != null or res.args.@"native-builder-every-slots" != null))
            return error.NativeBuilderRequired;
        const every_slots = res.args.@"native-builder-every-slots" orelse 1;
        if (every_slots == 0 or every_slots > 64) return error.InvalidBuilderDuty;
        const fee_recipient = if (res.args.@"native-builder-fee-recipient") |value| blk: {
            if (value.len != 42 or !std.mem.startsWith(u8, value, "0x")) return error.InvalidBuilderFeeRecipient;
            break :blk try std.fmt.parseInt(u160, value[2..], 16);
        } else 0;
        if (native_builder and fee_recipient == 0) return error.ExplicitBuilderFeeRecipientRequired;
        return .{
            .native_builder = native_builder,
            .builder_fee_recipient = fee_recipient,
            .builder_blobs = res.args.@"native-builder-blobs" != 0,
            .builder_output_dir = res.args.@"native-builder-output-dir",
            .builder_every_slots = every_slots,
            .shadow_state = res.args.@"shadow-state" != 0,
            .shadow_database_limit = shadow_database_limit,
            .shadow_beacon_url = res.args.@"shadow-beacon-url",
            .public_intake_observer = res.args.@"public-intake-observer" != 0,
            .config = switch (network) {
                .glamsterdam_devnet8 => blockchain.glamsterdam_devnet8_config,
                .mainnet => blockchain.mainnet_config,
                .sepolia => blockchain.sepolia_config,
            },
            .bootnodes = if (res.args.bootnode.len > 0) res.args.bootnode else switch (network) {
                .glamsterdam_devnet8 => &bootnodes.glamsterdam_devnet8,
                .mainnet => &bootnodes.mainnet,
                .sepolia => &bootnodes.sepolia,
            },
            .datadir = res.args.datadir orelse "datadir",
            .port = res.args.port orelse 30303,
            .discovery_port = res.args.@"discovery-port" orelse 33034,
            .http_addr = std.Io.net.IpAddress.parse(http_addr, http_port) catch |e| {
                std.log.err("invalid --http-addr {s}: {}", .{ http_addr, e });
                std.process.exit(1);
            },
            .authrpc_addr = std.Io.net.IpAddress.parse(authrpc_addr, authrpc_port) catch |e| {
                std.log.err("invalid --authrpc-addr {s}: {}", .{ authrpc_addr, e });
                std.process.exit(1);
            },
            .authrpc_jwtsecret = res.args.@"authrpc-jwtsecret",
            .metrics_addr = std.Io.net.IpAddress.parse(metrics_addr, metrics_port) catch |e| {
                std.log.err("invalid --metrics-addr {s}: {}", .{ metrics_addr, e });
                std.process.exit(1);
            },
        };
    }
};

fn openDataSubdir(io: std.Io, allocator: std.mem.Allocator, datadir: std.Io.Dir, sub_path: []const u8) ![]const u8 {
    var dir = try datadir.createDirPathOpen(io, sub_path, .{});
    defer dir.close(io);
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const len = try dir.realPath(io, &path);
    return allocator.dupe(u8, path[0..len]);
}

pub fn main(init: std.process.Init) !void {
    return mainWithBuilder(init, void);
}

/// Builder is a specialized native adapter, not an RPC service. Its callbacks
/// copy bounded inputs; its own joined task owns construction and intake drain.
pub fn mainWithBuilder(init: std.process.Init, comptime Builder: type) !void {
    var shutdown = try Shutdown.init();
    defer shutdown.deinit(init.io);

    const opts = try Options.parse(init) orelse return;
    if (comptime Builder == void) {
        if (opts.native_builder) return error.NativeBuilderNotLinked;
    }

    const Event = union(enum) {
        node: anyerror!void,
        signal: @typeInfo(@TypeOf(Shutdown.wait)).@"fn".return_type.?,
    };
    var buf: [2]Event = undefined;
    var select: std.Io.Select(Event) = .init(init.io, &buf);
    defer select.cancelDiscard();
    const Runner = struct {
        fn run(state: std.process.Init, options: Options) anyerror!void {
            return runNode(state, options, Builder);
        }
    };
    try select.concurrent(.node, Runner.run, .{ init, opts });
    try select.concurrent(.signal, Shutdown.wait, .{ &shutdown, init.io });

    switch (try select.await()) {
        .node => |res| try res,
        .signal => |res| {
            std.log.info("received {t}, shutting down", .{try res});
            // a second signal kills the process
            shutdown.unblock();
        },
    }
}

fn runNode(init: std.process.Init, opts: Options, comptime Builder: type) !void {
    const kp = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate(init.io);

    var slabs = SlabAllocator.init(init.arena.allocator());

    var datadir = try std.Io.Dir.cwd().createDirPathOpen(init.io, opts.datadir, .{});
    defer datadir.close(init.io);
    const static_path = try openDataSubdir(init.io, init.arena.allocator(), datadir, "static");
    const mdbx_path = try openDataSubdir(init.io, init.arena.allocator(), datadir, "mdbx");

    var fs = try FileStorage.init(init.io, slabs.allocator(), static_path);
    defer fs.deinit(init.io, slabs.allocator()) catch |e| std.log.err("closing file storage failed: {}", .{e});

    var store = if (opts.shadow_state)
        try kv.Store.initBoundedChecked(init.io, slabs.allocator(), mdbx_path, opts.shadow_database_limit, shadow_limits.database_growth_bytes)
    else
        try kv.Store.init(slabs.allocator(), mdbx_path);
    defer store.deinit() catch |e| std.log.err("closing mdbx failed: {}", .{e});
    if (opts.shadow_state) {
        const geometry = (try store.env.info()).geo;
        std.log.info("shadow database bound: configured {} bytes, current {} bytes, upper {} bytes", .{ opts.shadow_database_limit, geometry.current, geometry.upper });
    }
    var eth_db = EthDb.init(&store);

    var bc = try Blockchain.init(init.io, slabs.allocator(), opts.config, &fs, &eth_db);

    var id_filter = forks.IdFilter.init(bc.genesisHash(), &bc.cfg.fork_schedule);
    const genesis_head_header = try bc.headHeader();

    var ethproto = try eth.Provider.init(slabs.allocator());
    ethproto.hello = .{
        .status = .{
            .protocol_version = 71,
            .network_id = bc.chainId(),
            .genesis = bc.genesisHash(),
            .fork_id = id_filter.currentId(genesis_head_header.number, genesis_head_header.timestamp),
            .earliest_block = 0,
            .latest_block = (try bc.head()).number,
            .latest_block_hash = (try bc.head()).hash,
        },
    };
    var snapproto = try snap.Provider.init(slabs.allocator());
    var caps = [2]rlpx.RegisteredCapability{
        ethproto.register(),
        snapproto.register(),
    };
    var rlpx_server = try rlpx.Server.init(slabs.allocator(), init.io, kp, opts.port, &caps);
    defer rlpx_server.deinit();
    ethproto.server = &rlpx_server;
    snapproto.server = &rlpx_server;

    var rlpx_thread = try init.io.concurrent(rlpx.Server.run, .{&rlpx_server});
    defer rlpx_thread.cancel(init.io) catch {};

    var dialer = Dialer.init(&rlpx_server, &id_filter, &bc);
    defer dialer.deinit(init.io);

    var server = try discv5.Server.init(
        slabs.allocator(),
        init.io,
        kp,
        opts.discovery_port,
        try bootnodes.parse(init.arena.allocator(), opts.bootnodes),
        &dialer,
    );
    var discv_thread = try init.io.concurrent(discv5.Server.run, .{&server});
    defer discv_thread.cancel(init.io) catch {};

    var downloader = try Downloader.init(
        init.io,
        slabs.allocator(),
        &bc,
        &eth_db,
        &ethproto,
        &snapproto,
    );

    var snapshots: Snapshots = .{ .io = init.io, .store = &store };
    defer snapshots.deinit();
    var builder: ?*Builder = null;
    if (comptime Builder != void) {
        if (opts.native_builder) builder = try Builder.create(init.gpa, init.io, &eth_db, &snapshots, .{
            .chain_id = opts.config.chain_id,
            .fee_recipient = opts.builder_fee_recipient,
            .blobs = opts.builder_blobs,
            .output_dir = opts.builder_output_dir,
            .every_slots = opts.builder_every_slots,
        });
    }
    defer if (comptime Builder != void) {
        if (builder) |value| value.deinit();
    };
    var public_observer: public_intake_peer.Observer = .{ .io = init.io };
    var public_source: public_intake.Intake = .{ .allocator = init.gpa, .chain_id = opts.config.chain_id, .sink = public_observer.sink() };
    defer public_source.deinit();
    if (comptime Builder != void) {
        if (builder) |value| public_source.sink = public_intake.handoffSink(value.sink());
    }
    var public_driver: public_intake_peer.Driver = .{ .source = &public_source, .provider = &ethproto };
    if (opts.public_intake_observer or opts.native_builder) downloader.public_intake = &public_driver;
    if (opts.shadow_state) try downloader.enableShadow(&snapshots, opts.shadow_beacon_url != null);
    var shadow_api: ShadowApi = .{ .snapshots = &snapshots, .eth = &eth_db };
    defer shadow_api.deinit(); // RPC futures below are cancelled and joined first.

    var consensus_buffer: [4]consensus.Update = undefined;
    var consensus_updates: std.Io.Queue(consensus.Update) = .init(&consensus_buffer);
    var tracker: ?consensus.Tracker = if (opts.shadow_beacon_url) |url|
        try .init(init.io, init.gpa, url, &consensus_updates)
    else
        null;
    defer if (tracker) |*t| t.deinit();
    if (comptime Builder != void) {
        if (builder) |value| tracker.?.attributes_sink = value.attributesSink();
    }
    var tracker_thread: ?std.Io.Future(@typeInfo(@TypeOf(consensus.Tracker.run)).@"fn".return_type.?) = null;
    if (tracker) |*t| {
        try downloader.enableConsensus(&consensus_updates);
        tracker_thread = try init.io.concurrent(consensus.Tracker.run, .{t});
    }
    defer if (tracker_thread) |*thread| thread.cancel(init.io) catch {};

    const metrics_sources = [_]metrics.Source{
        .from(rlpx.Server, &rlpx_server),
        .from(Downloader, &downloader),
    };
    var metrics_http: metrics.HttpServer = try .init(init.io, slabs.allocator(), &metrics_sources, opts.metrics_addr);
    var metrics_thread = try init.io.concurrent(metrics.HttpServer.run, .{&metrics_http});
    defer metrics_thread.cancel(init.io) catch {};

    var eth_api: EthApi = .init(&bc, &downloader);
    var jsonrpc_server: RpcServer = .{};
    try eth_api.register(init.arena.allocator(), &jsonrpc_server);
    if (opts.shadow_state) try shadow_api.register(init.arena.allocator(), &jsonrpc_server);

    var jsonrpc_http: RpcHttpServer = try .init(init.io, slabs.allocator(), &jsonrpc_server, opts.http_addr);
    var rpc_thread = try init.io.concurrent(RpcHttpServer.run, .{&jsonrpc_http});
    defer rpc_thread.cancel(init.io) catch {};

    const jwt_secret = try jwt.loadOrCreateSecret(init.io, datadir, opts.authrpc_jwtsecret);
    var authrpc_server: RpcServer = .{};
    try eth_api.register(init.arena.allocator(), &authrpc_server);
    var engine_api: EngineApi = .init(&bc, &downloader);
    try engine_api.register(init.arena.allocator(), &authrpc_server);

    var authrpc_http = (try RpcHttpServer.init(init.io, slabs.allocator(), &authrpc_server, opts.authrpc_addr))
        .with_auth(jwt_secret);
    var authrpc_thread = try init.io.concurrent(RpcHttpServer.run, .{&authrpc_http});
    defer authrpc_thread.cancel(init.io) catch {};

    if (comptime Builder != void) {
        if (builder) |value| {
            // Observe both owners. A failed builder must not leave a seemingly
            // healthy sync process with silently stopped construction. Cancellation
            // joins both tasks before tracker callbacks and owner storage retire.
            const Event = union(enum) { sync: anyerror!void, builder: anyerror!void };
            var events: [2]Event = undefined;
            var tasks: std.Io.Select(Event) = .init(init.io, &events);
            defer tasks.cancelDiscard();
            try tasks.concurrent(.sync, Downloader.run, .{&downloader});
            try tasks.concurrent(.builder, Builder.run, .{value});
            return switch (try tasks.await()) {
                .sync => |result| result,
                .builder => |result| result,
            };
        }
    }
    try downloader.run();
}
