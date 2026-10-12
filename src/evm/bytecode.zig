// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contract code with a lazily decoded, paged threaded representation.
//!
//! The raw bytes are never trimmed: CODESIZE, CODECOPY, EXTCODECOPY and PUSH
//! immediates read them directly. Threaded function-pointer pages are decoded
//! on demand, one `page_size` byte range at a time, when sequential execution
//! or a validated jump first reaches them.
//!
//! Ownership: `init` allocates the shared metadata (page table, instruction
//! boundary bitmap, first page) with `gpa`; `deinit` must receive the same
//! allocator and frees everything, including pages added later. Frames hold
//! copies of this struct. Copies share the metadata but keep their own current
//! page view (`threaded_code`, `page_base`), so nested or reentrant frames
//! executing the same code cannot move a parent's instruction mapping. Pages
//! are allocated individually and never moved or freed before `deinit`, so
//! instruction pointers held by active frames stay valid while pages for other
//! regions are added. Page allocation failure is reported as `OutOfMemory`
//! and leaves the shared metadata and all existing pages usable.
//!
//! The shared metadata is mutated without synchronization: every copy of a
//! value must be used from the thread that owns the `State` it came from.
const std = @import("std");
const ops = @import("ops.zig");
const Opcode = @import("opcode.zig").Opcode;
const Config = @import("config.zig").Config;

pub const Bytecode = @This();

pub const InstructionPointer = [*]?ops.FnOpaquePtr;
/// Page storage element: the typed handler, viewed opaquely through
/// `threaded_code` to avoid a reference loop.
const Slot = ?ops.Fn;

/// Byte positions covered by one threaded page.
pub const page_size: usize = 256;
/// Slots appended after a page's positions so that every `next_ip` an opcode
/// in the page can produce (at most 32 PUSH data bytes past the last
/// position) lands on a dereferenceable slot holding either the page-crossing
/// handler or STOP.
pub const page_tail: usize = 33;

const Shared = struct {
    gpa: std.mem.Allocator,
    /// One entry per page. Pages are allocated lazily and never moved.
    pages: []?[]Slot,
    /// One bit per byte position, set when the position starts an instruction
    /// (not PUSH data or a consumed Amsterdam immediate): position `pc` is bit
    /// `pc % 64` of word `pc / 64`. Final for every position below `frontier`.
    boundaries: []u64,
    /// Lowest byte position not yet classified in `boundaries`. Always an
    /// instruction boundary or at least `bytes.len`.
    frontier: usize,
};

// Raw bytecode of the contract
bytes: []const u8,
// Threaded code of the current page: slots for positions
// `page_base .. page_base + positions` followed by `page_tail` extra slots.
// Uses an opaque type to avoid a reference loop.
threaded_code: []?ops.FnOpaquePtr,
// Absolute byte offset of `threaded_code[0]` for this copy.
page_base: usize,
// Allocator-owned metadata shared by every copy of this value.
shared: *Shared,

/// Creates a new Bytecode. Only the first page is decoded; the boundary bitmap
/// is sized for the whole code but filled lazily.
pub fn init(gpa: std.mem.Allocator, bytes: []const u8, comptime cfg: Config) !Bytecode {
    const shared = try gpa.create(Shared);
    errdefer gpa.destroy(shared);
    const pages = try gpa.alloc(?[]Slot, @max(1, (bytes.len + page_size - 1) / page_size));
    errdefer gpa.free(pages);
    @memset(pages, null);
    const boundaries = try gpa.alloc(u64, (bytes.len + 63) / 64);
    errdefer gpa.free(boundaries);
    @memset(boundaries, 0);
    shared.* = .{ .gpa = gpa, .pages = pages, .boundaries = boundaries, .frontier = 0 };

    var self: Bytecode = .{ .bytes = bytes, .threaded_code = &.{}, .page_base = 0, .shared = shared };
    self.threaded_code = @ptrCast(try self.decodePage(0, cfg));
    return self;
}

/// Frees all pages and metadata. `gpa` must be the allocator given to `init`.
/// Every copy of this value becomes invalid.
pub fn deinit(self: *const Bytecode, gpa: std.mem.Allocator) void {
    const shared = self.shared;
    std.debug.assert(std.meta.eql(gpa, shared.gpa));
    for (shared.pages) |maybe_page| if (maybe_page) |page| gpa.free(page);
    gpa.free(shared.pages);
    gpa.free(shared.boundaries);
    gpa.destroy(shared);
}

/// Instruction pointer for byte offset 0. Resets this copy's view to the first
/// page, which always exists after `init`.
pub fn entry(self: *Bytecode) InstructionPointer {
    self.threaded_code = @ptrCast(self.shared.pages[0].?);
    self.page_base = 0;
    return self.threaded_code.ptr;
}

/// Number of pages decoded so far across all copies.
pub fn decodedPages(self: *const Bytecode) usize {
    var count: usize = 0;
    for (self.shared.pages) |page| count += @intFromBool(page != null);
    return count;
}

/// Makes the page containing `pc` this copy's current view, decoding it on
/// first use, and returns the instruction pointer for `pc`. `pc` must be an
/// instruction boundary below `bytes.len`; callers establish that through
/// sequential flow or `isValidJumpDest`. Fails only with `OutOfMemory`, in
/// which case the view is unchanged.
pub fn activate(self: *Bytecode, pc: usize, comptime cfg: Config) std.mem.Allocator.Error!InstructionPointer {
    std.debug.assert(pc < self.bytes.len);
    const index = pc / page_size;
    const base = index * page_size;
    if (base != self.page_base) {
        const page = self.shared.pages[index] orelse try self.decodePage(index, cfg);
        self.threaded_code = @ptrCast(page);
        self.page_base = base;
    }
    std.debug.assert(self.isBoundary(pc));
    return self.threaded_code[pc - base ..].ptr;
}

// Checks if the given program counter is a valid jump destination: a JUMPDEST
// byte that starts an instruction. On success the destination page becomes
// this copy's current view. Allocation failure is a host error, not an
// invalid jump.
pub fn isValidJumpDest(self: *Bytecode, pc: u256, comptime cfg: Config) std.mem.Allocator.Error!?InstructionPointer {
    if (pc >= self.bytes.len) {
        @branchHint(.unlikely);
        return null;
    }
    const truncated_pc: usize = @intCast(pc);
    if (self.bytes[truncated_pc] != Opcode.JUMPDEST.byte()) {
        @branchHint(.unlikely);
        return null;
    }
    self.analyzeTo(truncated_pc + 1, cfg);
    if (!self.isBoundary(truncated_pc)) {
        @branchHint(.unlikely);
        return null;
    }
    return try self.activate(truncated_pc, cfg);
}

// Fills bytes read from the bytecode to the given value and clears the upper bytes that were not used
pub fn readBytesToValue(self: *const Bytecode, ip: InstructionPointer, comptime size: usize, value: *u256) void {
    comptime std.debug.assert(size <= 32);

    const start = self.programCounter(ip);
    ops.readBeSliceToU256(self.bytes[@min(start, self.bytes.len)..], size, value);
}

pub fn readByte(self: *const Bytecode, ip: InstructionPointer) u8 {
    const offset = self.programCounter(ip);
    return if (offset < self.bytes.len) self.bytes[offset] else 0;
}

pub fn safeSlice(self: *const Bytecode, index: u256, size: u64) []const u8 {
    if (index >= self.bytes.len) {
        return &[_]u8{};
    }
    const read_size = @min(self.bytes.len - index, size);
    return self.bytes[@intCast(index)..@intCast(index + read_size)];
}

/// Absolute byte offset of `ip`, which must point into this copy's current
/// page (including its tail slots and one past the end).
pub fn programCounter(self: *const Bytecode, ip: InstructionPointer) u64 {
    const offset = ip - self.threaded_code.ptr;
    std.debug.assert(offset <= self.threaded_code.len);
    return self.page_base + offset;
}

fn isBoundary(self: *const Bytecode, pc: usize) bool {
    return (self.shared.boundaries[pc / 64] >> @intCast(pc % 64)) & 1 == 1;
}

/// Classifies every position below `limit`, continuing the sequential scan
/// from the frontier. Cost is linear in the newly scanned bytes. The bits of
/// one bitmap word are accumulated in a register and merged with a single OR
/// once the scan leaves the word, so resuming inside a word keeps the bits set
/// below the frontier. The scan may stop past `limit` when an immediate
/// straddles it; the frontier then records that position.
fn analyzeTo(self: *const Bytecode, limit: usize, comptime cfg: Config) void {
    const shared = self.shared;
    var pc = shared.frontier;
    const end = @min(limit, self.bytes.len);
    while (pc < end) {
        const index = pc / 64;
        const word_end = @min(end, (index + 1) * 64);
        var word: u64 = 0;
        while (pc < word_end) {
            word |= @as(u64, 1) << @intCast(pc % 64);
            pc += instructionLength(self.bytes, pc, cfg);
        }
        shared.boundaries[index] |= word;
    }
    shared.frontier = pc;
}

const instruction_lengths: [256]u8 = blk: {
    var lengths: [256]u8 = @splat(1);
    for (Opcode.PUSH1.byte()..Opcode.PUSH32.byte() + 1) |op| {
        lengths[op] = @intCast(op - Opcode.PUSH1.byte() + 2);
    }
    break :blk lengths;
};

/// Bytes consumed by the instruction starting at `pc`, matching the runtime
/// advance of its handler: PUSH data, and under Amsterdam a valid DUPN/SWAPN/
/// EXCHANGE immediate. An invalid immediate is not consumed (the opcode becomes
/// INVALID), and a missing immediate reads as zero at runtime.
fn instructionLength(bytes: []const u8, pc: usize, comptime cfg: Config) usize {
    const op = bytes[pc];
    if (cfg.fork.isEnabled(.Amsterdam)) switch (op) {
        Opcode.DUPN.byte(), Opcode.SWAPN.byte(), Opcode.EXCHANGE.byte() => {
            if (pc + 1 < bytes.len and !invalidImmediate(op, bytes[pc + 1])) return 2;
        },
        else => {},
    };
    return instruction_lengths[op];
}

fn invalidImmediate(op: u8, imm: u8) bool {
    const inv_imm_low: u8 = if (op == Opcode.EXCHANGE.byte()) 0x52 else 0x5b;
    const inv_imm_high: u8 = 0x7F;
    return inv_imm_low <= imm and imm <= inv_imm_high;
}

fn handlerFor(comptime cfg: Config, bytes: []const u8, pc: usize) Slot {
    const jump_table = comptime ops.Ops(cfg).table();
    const op = bytes[pc];
    if (cfg.fork.isEnabled(.Amsterdam)) switch (op) {
        Opcode.DUPN.byte(), Opcode.SWAPN.byte(), Opcode.EXCHANGE.byte() => {
            if (pc + 1 < bytes.len and invalidImmediate(op, bytes[pc + 1])) return jump_table[Opcode.INVALID.byte()];
        },
        else => {},
    };
    return jump_table[op];
}

/// Decodes page `index` and publishes it in the shared page table. Positions
/// at or beyond `bytes.len` become STOP; tail slots become the page-crossing
/// handler for positions still inside the code and STOP otherwise.
fn decodePage(self: *const Bytecode, index: usize, comptime cfg: Config) std.mem.Allocator.Error![]Slot {
    const shared = self.shared;
    std.debug.assert(shared.pages[index] == null);
    const stop: Slot = comptime ops.Ops(cfg).table()[Opcode.STOP.byte()];
    const cross: Slot = ops.Ops(cfg).crossPage;
    const base = index * page_size;
    const positions = @min(page_size, self.bytes.len - base);
    self.analyzeTo(base + positions, cfg);

    const page = try shared.gpa.alloc(Slot, positions + page_tail);
    for (page[0..positions], base..) |*slot, pc| {
        slot.* = if (self.isBoundary(pc)) handlerFor(cfg, self.bytes, pc) else null;
    }
    for (page[positions..], base + positions..) |*slot, pc| {
        slot.* = if (pc < self.bytes.len) cross else stop;
    }
    shared.pages[index] = page;
    return page;
}

const Spec = @import("spec.zig").Spec;
const testing = std.testing;
const amsterdam: Config = .{ .fork = Spec.fromFork(.Amsterdam) };
const osaka: Config = .{ .fork = Spec.fromFork(.Osaka) };

const far_code_len = 64 * 1024;
const far_tail_pc = 0xffe4;

/// 64 KiB contract that immediately jumps to a routine at `far_tail_pc`. The
/// filler in between is PUSH32 words whose data bytes all look like JUMPDEST,
/// so naive byte checks would accept them.
fn farJumpCode(allocator: std.mem.Allocator, tail: []const u8) ![]u8 {
    const code = try allocator.alloc(u8, far_code_len);
    @memcpy(code[0..4], &[_]u8{ Opcode.PUSH2.byte(), 0xff, 0xe4, Opcode.JUMP.byte() });
    var pc: usize = 4;
    while (pc + 33 <= far_tail_pc) : (pc += 33) {
        code[pc] = Opcode.PUSH32.byte();
        @memset(code[pc + 1 .. pc + 33], Opcode.JUMPDEST.byte());
    }
    @memset(code[pc..], Opcode.STOP.byte());
    @memcpy(code[far_tail_pc .. far_tail_pc + tail.len], tail);
    return code;
}

/// Replaces the filler PUSH32 word containing `pc` with STOPs and plants
/// `routine` at `pc`, so that `pc` is an instruction boundary.
fn plantRoutine(code: []u8, pc: usize, routine: []const u8) void {
    const word = 4 + ((pc - 4) / 33) * 33;
    @memset(code[word .. word + 33], Opcode.STOP.byte());
    @memcpy(code[pc .. pc + routine.len], routine);
}

fn handler(comptime cfg: Config, comptime op: Opcode) ?ops.FnOpaquePtr {
    const jump_table = comptime ops.Ops(cfg).table();
    return @ptrCast(@alignCast(jump_table[op.byte()]));
}

test "far jump into the tail of 64 KiB code decodes only the reached pages" {
    const a = testing.allocator;
    const code = try farJumpCode(a, &.{ Opcode.JUMPDEST.byte(), Opcode.PC.byte(), Opcode.STOP.byte() });
    defer a.free(code);
    var counting = testing.FailingAllocator.init(a, .{});
    var bytecode = try Bytecode.init(counting.allocator(), code, amsterdam);
    defer bytecode.deinit(counting.allocator());
    const initial = counting.allocated_bytes;
    try testing.expectEqual(1, bytecode.decodedPages());
    // A page-granular representation costs a small fraction of the eager 8 bytes per code byte.
    try testing.expect(initial < far_code_len / 2);

    // JUMPDEST bytes inside PUSH data are rejected even though their byte matches,
    // and rejecting them must not allocate anything.
    try testing.expectEqual(null, try bytecode.isValidJumpDest(5, amsterdam));
    try testing.expectEqual(null, try bytecode.isValidJumpDest(page_size, amsterdam));
    try testing.expectEqual(Opcode.JUMPDEST.byte(), code[page_size]);
    try testing.expectEqual(null, try bytecode.isValidJumpDest(far_code_len, amsterdam));
    try testing.expectEqual(null, try bytecode.isValidJumpDest(1 << 70, amsterdam));
    try testing.expectEqual(initial, counting.allocated_bytes);

    const ip = (try bytecode.isValidJumpDest(far_tail_pc, amsterdam)).?;
    try testing.expectEqual(far_tail_pc, bytecode.programCounter(ip));
    try testing.expectEqual(handler(amsterdam, .JUMPDEST), ip[0]);
    try testing.expectEqual(Opcode.PC.byte(), bytecode.readByte(ip + 1));
    try testing.expectEqual(2, bytecode.decodedPages());
    try testing.expect(counting.allocated_bytes - initial < 4 * (page_size + page_tail) * 8);
}

test "sequential page boundary slots hold the crossing handler until the code ends" {
    const a = testing.allocator;
    var code: [page_size + 3]u8 = undefined;
    @memset(&code, Opcode.JUMPDEST.byte());
    // PC, PUSH32 with data extending past the end of the code.
    @memcpy(code[page_size - 2 ..], &[_]u8{ Opcode.PC.byte(), Opcode.PUSH32.byte(), 0x5b, 0x5b, 0x5b });
    var bytecode = try Bytecode.init(a, &code, amsterdam);
    defer bytecode.deinit(a);
    try testing.expectEqual(page_size + page_tail, bytecode.threaded_code.len);
    // The PUSH32 at the last position reads its data via the next page, so the
    // tail slot right after the page crosses, while slots past the code stop.
    const cross: ?ops.FnOpaquePtr = @ptrCast(@alignCast(&ops.Ops(amsterdam).crossPage));
    try testing.expectEqual(cross, bytecode.threaded_code[page_size]);
    try testing.expectEqual(cross, bytecode.threaded_code[page_size + 2]);
    try testing.expectEqual(handler(amsterdam, .STOP), bytecode.threaded_code[page_size + 3]);
    try testing.expectEqual(handler(amsterdam, .STOP), bytecode.threaded_code[page_size + page_tail - 1]);
    // PUSH data bytes are not instruction boundaries anywhere in the code.
    for (page_size..code.len) |pc| try testing.expectEqual(null, try bytecode.isValidJumpDest(pc, amsterdam));
    try testing.expect((try bytecode.isValidJumpDest(page_size - 3, amsterdam)) != null);
    // Reading past the end of the code yields zero bytes for truncated PUSH data.
    var value: u256 = 1;
    bytecode.readBytesToValue(bytecode.threaded_code[page_size..].ptr, 32, &value);
    try testing.expectEqual(@as(u256, 0x5b5b5b) << (29 * 8), value);
    // Nothing executable follows the truncated PUSH, so no second page was needed,
    // and activating a position inside the current page decodes nothing.
    try testing.expectEqual(1, bytecode.decodedPages());
    const ip = try bytecode.activate(page_size - 3, amsterdam);
    try testing.expectEqual(page_size - 3, bytecode.programCounter(ip));
    try testing.expectEqual(1, bytecode.decodedPages());
}

test "jumps across pages activate the destination page and keep absolute program counters" {
    const a = testing.allocator;
    const code = try farJumpCode(a, &.{ Opcode.JUMPDEST.byte(), Opcode.PUSH1.byte(), 4, Opcode.JUMP.byte() });
    defer a.free(code);
    @memcpy(code[4..6], &[_]u8{ Opcode.JUMPDEST.byte(), Opcode.STOP.byte() });
    plantRoutine(code, 0x8000, &.{ Opcode.JUMPDEST.byte(), Opcode.STOP.byte() });
    var bytecode = try Bytecode.init(a, code, amsterdam);
    defer bytecode.deinit(a);

    const far = (try bytecode.isValidJumpDest(far_tail_pc, amsterdam)).?;
    try testing.expectEqual(far_tail_pc, bytecode.programCounter(far));
    try testing.expectEqual(far_tail_pc / page_size * page_size, bytecode.page_base);
    // Backward jump to the first page reuses the page decoded by init.
    const back = (try bytecode.isValidJumpDest(4, amsterdam)).?;
    try testing.expectEqual(4, bytecode.programCounter(back));
    try testing.expectEqual(0, bytecode.page_base);
    try testing.expectEqual(2, bytecode.decodedPages());
    const middle = (try bytecode.isValidJumpDest(0x8000, amsterdam)).?;
    try testing.expectEqual(0x8000, bytecode.programCounter(middle));
    try testing.expectEqual(3, bytecode.decodedPages());
    // Previously decoded pages are not moved by later activations.
    try testing.expectEqual(far, (try bytecode.isValidJumpDest(far_tail_pc, amsterdam)).?);
    try testing.expectEqual(0, bytecode.programCounter(bytecode.entry()));
}

test "copies share decoded pages while each keeps its own program counter mapping" {
    const a = testing.allocator;
    const code = try farJumpCode(a, &.{ Opcode.JUMPDEST.byte(), Opcode.STOP.byte() });
    defer a.free(code);
    plantRoutine(code, 0x8000, &.{ Opcode.JUMPDEST.byte(), Opcode.STOP.byte() });
    var bytecode = try Bytecode.init(a, code, amsterdam);
    defer bytecode.deinit(a);
    var parent = bytecode;
    var child = bytecode;
    const parent_ip = (try parent.isValidJumpDest(far_tail_pc, amsterdam)).?;
    const child_ip = (try child.isValidJumpDest(0x8000, amsterdam)).?;
    try testing.expectEqual(far_tail_pc, parent.programCounter(parent_ip));
    try testing.expectEqual(0x8000, child.programCounter(child_ip));
    try testing.expectEqual(0, bytecode.programCounter(bytecode.entry()));
    try testing.expectEqual(3, bytecode.decodedPages());
    // Re-activating an existing page from another copy reuses it: pointers stay stable.
    try testing.expectEqual(parent_ip, (try child.isValidJumpDest(far_tail_pc, amsterdam)).?);
    try testing.expectEqual(3, bytecode.decodedPages());
    try testing.expectEqual(far_tail_pc, parent.programCounter(parent_ip));
}

test "Amsterdam DUPN consumes a valid immediate on the next page" {
    const a = testing.allocator;
    var code: [page_size + 4]u8 = undefined;
    @memset(&code, Opcode.PUSH0.byte());
    @memcpy(code[page_size - 1 ..], &[_]u8{ Opcode.DUPN.byte(), 0x00, Opcode.JUMPDEST.byte(), Opcode.STOP.byte(), Opcode.STOP.byte() });
    var bytecode = try Bytecode.init(a, &code, amsterdam);
    defer bytecode.deinit(a);
    try testing.expectEqual(handler(amsterdam, .DUPN), bytecode.threaded_code[page_size - 1]);
    _ = try bytecode.activate(page_size + 1, amsterdam);
    try testing.expectEqual(page_size, bytecode.page_base);
    try testing.expectEqual(null, bytecode.threaded_code[0]);
    try testing.expectEqual(handler(amsterdam, .JUMPDEST), bytecode.threaded_code[1]);
    try testing.expect((try bytecode.isValidJumpDest(page_size + 1, amsterdam)) != null);
}

test "Amsterdam DUPN with an invalid immediate is INVALID and leaves the JUMPDEST after it reachable" {
    const a = testing.allocator;
    var bytecode = try Bytecode.init(a, &.{ Opcode.DUPN.byte(), Opcode.JUMPDEST.byte(), Opcode.STOP.byte() }, amsterdam);
    defer bytecode.deinit(a);
    try testing.expectEqual(handler(amsterdam, .INVALID), bytecode.threaded_code[0]);
    try testing.expect((try bytecode.isValidJumpDest(1, amsterdam)) != null);
    // A missing immediate keeps the DUPN handler, reads as zero and falls through to STOP.
    var trailing = try Bytecode.init(a, &.{ Opcode.JUMPDEST.byte(), Opcode.DUPN.byte() }, amsterdam);
    defer trailing.deinit(a);
    try testing.expectEqual(handler(amsterdam, .DUPN), trailing.threaded_code[1]);
    try testing.expectEqual(0, trailing.readByte(trailing.threaded_code[2..].ptr));
    try testing.expectEqual(handler(amsterdam, .STOP), trailing.threaded_code[3]);
}

test "pre-Amsterdam forks decode DUPN as INVALID without consuming an immediate" {
    const a = testing.allocator;
    var pre = try Bytecode.init(a, &.{ Opcode.DUPN.byte(), 0x00, Opcode.JUMPDEST.byte() }, osaka);
    defer pre.deinit(a);
    try testing.expectEqual(handler(osaka, .INVALID), pre.threaded_code[0]);
    try testing.expectEqual(handler(osaka, .STOP), pre.threaded_code[1]);
    try testing.expect((try pre.isValidJumpDest(2, osaka)) != null);
    var post = try Bytecode.init(a, &.{ Opcode.DUPN.byte(), 0x00, Opcode.JUMPDEST.byte() }, amsterdam);
    defer post.deinit(a);
    try testing.expectEqual(handler(amsterdam, .DUPN), post.threaded_code[0]);
    try testing.expectEqual(null, post.threaded_code[1]);
    try testing.expect((try post.isValidJumpDest(2, amsterdam)) != null);
}

test "empty code decodes a single page of STOP slots" {
    const a = testing.allocator;
    var bytecode = try Bytecode.init(a, &.{}, amsterdam);
    defer bytecode.deinit(a);
    try testing.expectEqual(page_tail, bytecode.threaded_code.len);
    try testing.expectEqual(handler(amsterdam, .STOP), bytecode.entry()[0]);
    try testing.expectEqual(null, try bytecode.isValidJumpDest(0, amsterdam));
    try testing.expectEqual(0, bytecode.readByte(bytecode.entry()));
}

fn activateTail(allocator: std.mem.Allocator, code: []const u8) !void {
    var bytecode = try Bytecode.init(allocator, code, amsterdam);
    defer bytecode.deinit(allocator);
    try testing.expect((try bytecode.isValidJumpDest(far_tail_pc, amsterdam)) != null);
    try testing.expect((try bytecode.isValidJumpDest(0x8000, amsterdam)) != null);
}

test "page allocation failure is OutOfMemory, leaks nothing and leaves decoded pages usable" {
    const a = testing.allocator;
    const code = try farJumpCode(a, &.{ Opcode.JUMPDEST.byte(), Opcode.STOP.byte() });
    defer a.free(code);
    plantRoutine(code, 0x8000, &.{Opcode.JUMPDEST.byte()});
    try testing.checkAllAllocationFailures(a, activateTail, .{code});

    var failing = testing.FailingAllocator.init(a, .{ .fail_index = 4 });
    var bytecode = try Bytecode.init(failing.allocator(), code, amsterdam);
    defer bytecode.deinit(failing.allocator());
    try testing.expectError(error.OutOfMemory, bytecode.isValidJumpDest(far_tail_pc, amsterdam));
    try testing.expect(failing.has_induced_failure);
    try testing.expectEqual(0, bytecode.page_base);
    try testing.expectEqual(1, bytecode.decodedPages());
    try testing.expectEqual(0, bytecode.programCounter(bytecode.entry()));
    // The failed activation did not corrupt the analysis: the same jump succeeds later.
    failing.fail_index = std.math.maxInt(usize);
    const ip = (try bytecode.isValidJumpDest(far_tail_pc, amsterdam)).?;
    try testing.expectEqual(far_tail_pc, bytecode.programCounter(ip));
    try testing.expectEqual(2, bytecode.decodedPages());
}

/// Independent restatement of the instruction length rules, used to
/// cross-check the scan: PUSHn consumes n data bytes; under Amsterdam DUPN,
/// SWAPN and EXCHANGE consume a present, valid immediate (EIP-663 reserves
/// 0x5b..0x7f for DUPN/SWAPN and 0x52..0x7f for EXCHANGE).
fn referenceLength(bytes: []const u8, pc: usize, comptime cfg: Config) usize {
    const op = bytes[pc];
    if (op >= 0x60 and op <= 0x7f) return @as(usize, op) - 0x60 + 2;
    if (!cfg.fork.isEnabled(.Amsterdam) or pc + 1 >= bytes.len) return 1;
    const imm = bytes[pc + 1];
    return switch (op) {
        0xe6, 0xe7 => if (imm >= 0x5b and imm <= 0x7f) 1 else 2,
        0xe8 => if (imm >= 0x52 and imm <= 0x7f) 1 else 2,
        else => 1,
    };
}

/// Scalar reference scan: one bool per position, true where an instruction starts.
fn referenceBoundaries(allocator: std.mem.Allocator, bytes: []const u8, comptime cfg: Config) ![]bool {
    const marks = try allocator.alloc(bool, bytes.len);
    @memset(marks, false);
    var pc: usize = 0;
    while (pc < bytes.len) : (pc += referenceLength(bytes, pc, cfg)) marks[pc] = true;
    return marks;
}

/// Positions below the frontier must match `expected`; positions at or above
/// it, and the padding bits of the last word, must be unmarked.
fn expectBoundariesUpToFrontier(bytecode: *const Bytecode, expected: []const bool) !void {
    const frontier = bytecode.shared.frontier;
    for (expected, 0..) |mark, pc| {
        const want = pc < frontier and mark;
        if (bytecode.isBoundary(pc) != want) {
            std.debug.print("position {d} with frontier {d}: expected boundary {}\n", .{ pc, frontier, want });
            return error.TestExpectedEqual;
        }
    }
    if (expected.len % 64 != 0) {
        try testing.expectEqual(0, bytecode.shared.boundaries[expected.len / 64] >> @intCast(expected.len % 64));
    }
}

/// Code generators for the randomized scans: uniform bytes; a scan-hostile mix
/// of PUSH1, JUMPDEST, the Amsterdam immediate opcodes and their edge
/// immediates; and PUSH32-heavy code where most positions are data.
fn fillRandomCode(random: std.Random, code: []u8, flavor: usize) void {
    switch (flavor) {
        0 => random.bytes(code),
        1 => for (code) |*byte| {
            byte.* = switch (random.uintLessThan(u8, 12)) {
                0...3 => Opcode.PUSH1.byte(),
                4...6 => Opcode.JUMPDEST.byte(),
                7 => Opcode.DUPN.byte(),
                8 => Opcode.SWAPN.byte(),
                9 => Opcode.EXCHANGE.byte(),
                10 => 0x7f, // PUSH32, or the last invalid immediate
                else => 0x52, // MSTORE, or the first EXCHANGE-only invalid immediate
            };
        },
        else => for (code) |*byte| {
            byte.* = if (random.uintLessThan(u8, 4) == 0) Opcode.PUSH32.byte() else Opcode.JUMPDEST.byte();
        },
    }
}

test "randomized code scans like the scalar reference at every offset and resume limit, for both forks" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x626f756e64617279);
    const random = prng.random();
    const edge_lengths = [_]usize{ 1, 2, 33, 63, 64, 65, 127, 128, 129, page_size - 1, page_size, page_size + 1, page_size + 33, 2 * page_size + 65 };
    for (0..240) |round| {
        const len = if (round < edge_lengths.len) edge_lengths[round] else random.intRangeLessThan(usize, 1, 3 * page_size + 70);
        const code = try a.alloc(u8, len);
        defer a.free(code);
        fillRandomCode(random, code, round % 3);
        inline for (.{ osaka, amsterdam }) |cfg| {
            const expected = try referenceBoundaries(a, code, cfg);
            defer a.free(expected);

            // Monotonic resumes at random limits, including no-op limits below
            // the frontier and limits past the end of the code.
            var bytecode = try Bytecode.init(a, code, cfg);
            defer bytecode.deinit(a);
            try testing.expect(bytecode.shared.frontier >= @min(len, page_size));
            try expectBoundariesUpToFrontier(&bytecode, expected);
            var limit: usize = 0;
            while (limit < len + 40) : (limit += random.intRangeLessThan(usize, 1, 70)) {
                bytecode.analyzeTo(limit, cfg);
                try testing.expect(bytecode.shared.frontier >= @min(limit, len));
                try expectBoundariesUpToFrontier(&bytecode, expected);
            }
            bytecode.analyzeTo(len, cfg);
            try testing.expect(bytecode.shared.frontier >= len);
            for (0..len + 2) |pc| {
                const valid = pc < len and expected[pc] and code[pc] == Opcode.JUMPDEST.byte();
                try testing.expectEqual(valid, (try bytecode.isValidJumpDest(pc, cfg)) != null);
            }

            // Jumps in arbitrary order drive the scan through the public API.
            var jumping = try Bytecode.init(a, code, cfg);
            defer jumping.deinit(a);
            for (0..64) |_| {
                const pc = random.uintLessThan(usize, len + 2);
                const valid = pc < len and expected[pc] and code[pc] == Opcode.JUMPDEST.byte();
                try testing.expectEqual(valid, (try jumping.isValidJumpDest(pc, cfg)) != null);
                try expectBoundariesUpToFrontier(&jumping, expected);
            }
        }
    }
}

test "instruction lengths follow the PUSH and Amsterdam immediate rules exactly" {
    // PUSH1..PUSH32 consume their data even when it is missing.
    for (1..33) |n| {
        const op: u8 = @intCast(Opcode.PUSH1.byte() + n - 1);
        try testing.expectEqual(n + 1, instructionLength(&.{op}, 0, amsterdam));
        try testing.expectEqual(n + 1, instructionLength(&.{op}, 0, osaka));
    }
    const dupn = Opcode.DUPN.byte();
    const swapn = Opcode.SWAPN.byte();
    const exchange = Opcode.EXCHANGE.byte();
    // Valid immediates are consumed under Amsterdam only. The invalid range
    // starts at 0x5b for DUPN/SWAPN and at 0x52 for EXCHANGE.
    for ([_]u8{ 0x00, 0x51, 0x5a, 0x80, 0xff }) |imm| {
        try testing.expectEqual(2, instructionLength(&.{ dupn, imm }, 0, amsterdam));
        try testing.expectEqual(2, instructionLength(&.{ swapn, imm }, 0, amsterdam));
        try testing.expectEqual(1, instructionLength(&.{ dupn, imm }, 0, osaka));
        try testing.expectEqual(1, instructionLength(&.{ swapn, imm }, 0, osaka));
    }
    for ([_]u8{ 0x00, 0x51, 0x80, 0xff }) |imm| {
        try testing.expectEqual(2, instructionLength(&.{ exchange, imm }, 0, amsterdam));
        try testing.expectEqual(1, instructionLength(&.{ exchange, imm }, 0, osaka));
    }
    // Invalid immediates are left in place so the opcode decodes as INVALID.
    for ([_]u8{ 0x5b, 0x60, 0x7f }) |imm| {
        try testing.expectEqual(1, instructionLength(&.{ dupn, imm }, 0, amsterdam));
        try testing.expectEqual(1, instructionLength(&.{ swapn, imm }, 0, amsterdam));
        try testing.expectEqual(1, instructionLength(&.{ exchange, imm }, 0, amsterdam));
    }
    for ([_]u8{ 0x52, 0x5a }) |imm| {
        try testing.expectEqual(1, instructionLength(&.{ exchange, imm }, 0, amsterdam));
        try testing.expectEqual(2, instructionLength(&.{ dupn, imm }, 0, amsterdam));
    }
    // A missing immediate is not consumed.
    try testing.expectEqual(1, instructionLength(&.{ Opcode.JUMPDEST.byte(), dupn }, 1, amsterdam));
    try testing.expectEqual(1, instructionLength(&.{exchange}, 0, amsterdam));
    // The reference used by the randomized test agrees for every opcode and immediate.
    for (0..256) |op| for ([_]u8{ 0x00, 0x51, 0x52, 0x5a, 0x5b, 0x7f, 0x80, 0xff }) |imm| {
        const pair = [_]u8{ @intCast(op), imm };
        inline for (.{ osaka, amsterdam }) |cfg| {
            try testing.expectEqual(referenceLength(&pair, 0, cfg), instructionLength(&pair, 0, cfg));
            try testing.expectEqual(referenceLength(pair[0..1], 0, cfg), instructionLength(pair[0..1], 0, cfg));
        }
    };
}

test "resuming a scan inside a word keeps the bits set below the frontier" {
    const a = testing.allocator;
    // Page 1 is JUMPDESTs except a PUSH1 whose data byte opens word 5 and a
    // PUSH32 whose data crosses from word 5 into word 6.
    var code: [2 * page_size]u8 = @splat(Opcode.JUMPDEST.byte());
    code[319] = Opcode.PUSH1.byte();
    code[370] = Opcode.PUSH32.byte();
    var bytecode = try Bytecode.init(a, &code, amsterdam);
    defer bytecode.deinit(a);
    const expected = try referenceBoundaries(a, &code, amsterdam);
    defer a.free(expected);
    try testing.expectEqual(page_size, bytecode.shared.frontier);

    // Stop inside word 4, then resume inside it: bits 0..10 must survive.
    bytecode.analyzeTo(267, amsterdam);
    try testing.expectEqual(267, bytecode.shared.frontier);
    try testing.expectEqual(0x7ff, bytecode.shared.boundaries[4]);
    bytecode.analyzeTo(319, amsterdam);
    try testing.expectEqual(319, bytecode.shared.frontier);
    try testing.expectEqual(std.math.maxInt(u64) >> 1, bytecode.shared.boundaries[4]);
    try expectBoundariesUpToFrontier(&bytecode, expected);
    // The PUSH1 at 319 completes word 4 and overshoots the limit into word 5,
    // whose first position is data, so nothing is written to word 5 yet.
    bytecode.analyzeTo(320, amsterdam);
    try testing.expectEqual(321, bytecode.shared.frontier);
    try testing.expectEqual(std.math.maxInt(u64), bytecode.shared.boundaries[4]);
    try testing.expectEqual(0, bytecode.shared.boundaries[5]);
    // The data byte looks like a JUMPDEST but is rejected without decoding anything.
    try testing.expectEqual(null, try bytecode.isValidJumpDest(320, amsterdam));
    try testing.expectEqual(321, bytecode.shared.frontier);
    try testing.expectEqual(1, bytecode.decodedPages());
    bytecode.analyzeTo(322, amsterdam);
    try testing.expectEqual(0b10, bytecode.shared.boundaries[5]);
    // A limit inside PUSH32 data: the scan runs to the instruction after it,
    // leaving word 6 untouched because that instruction is not marked yet.
    bytecode.analyzeTo(373, amsterdam);
    try testing.expectEqual(403, bytecode.shared.frontier);
    try testing.expectEqual(((@as(u64, 1) << 51) - 1) & ~@as(u64, 1), bytecode.shared.boundaries[5]);
    try testing.expectEqual(0, bytecode.shared.boundaries[6]);
    try expectBoundariesUpToFrontier(&bytecode, expected);
    try testing.expectEqual(null, try bytecode.isValidJumpDest(372, amsterdam));
    // A valid jump decodes page 1, which completes the scan of the page.
    try testing.expect((try bytecode.isValidJumpDest(403, amsterdam)) != null);
    try testing.expectEqual(2, bytecode.decodedPages());
    try testing.expectEqual(2 * page_size, bytecode.shared.frontier);
    try testing.expectEqual(std.math.maxInt(u64), bytecode.shared.boundaries[7]);
    try expectBoundariesUpToFrontier(&bytecode, expected);
    try testing.expect((try bytecode.isValidJumpDest(2 * page_size - 1, amsterdam)) != null);
}

test "a truncated PUSH leaves its data unmarked and parks the frontier past the code" {
    const a = testing.allocator;
    for ([_]usize{ 1, 4, 7, 63, 64, 65, 200, page_size + 1 }) |len| {
        const code = try a.alloc(u8, len);
        defer a.free(code);
        @memset(code, Opcode.JUMPDEST.byte());
        const push = len -| 4;
        code[push] = Opcode.PUSH32.byte();
        inline for (.{ osaka, amsterdam }) |cfg| {
            var bytecode = try Bytecode.init(a, code, cfg);
            defer bytecode.deinit(a);
            const expected = try referenceBoundaries(a, code, cfg);
            defer a.free(expected);
            try testing.expectEqual(push + 33, bytecode.shared.frontier);
            try expectBoundariesUpToFrontier(&bytecode, expected);
            for (push + 1..len) |pc| try testing.expectEqual(null, try bytecode.isValidJumpDest(pc, cfg));
            // Further limits, including far past the code, change nothing.
            bytecode.analyzeTo(len + 1000, cfg);
            bytecode.analyzeTo(std.math.maxInt(usize), cfg);
            try testing.expectEqual(push + 33, bytecode.shared.frontier);
            try expectBoundariesUpToFrontier(&bytecode, expected);
        }
    }
}

test "short final words are fully marked without touching padding bits" {
    const a = testing.allocator;
    for ([_]usize{ 1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 255, 256, 257, 300, 2 * page_size + 63 }) |len| {
        const code = try a.alloc(u8, len);
        defer a.free(code);
        @memset(code, Opcode.JUMPDEST.byte());
        var bytecode = try Bytecode.init(a, code, amsterdam);
        defer bytecode.deinit(a);
        try testing.expectEqual((len + 63) / 64, bytecode.shared.boundaries.len);
        try testing.expect((try bytecode.isValidJumpDest(len - 1, amsterdam)) != null);
        try testing.expectEqual(len, bytecode.shared.frontier);
        for (0..len) |pc| try testing.expect(bytecode.isBoundary(pc));
        const last = bytecode.shared.boundaries[bytecode.shared.boundaries.len - 1];
        const used = len % 64;
        try testing.expectEqual(if (used == 0) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(used)) - 1, last);
    }
}

test "scans resume across page boundaries after immediates overshoot them" {
    const a = testing.allocator;
    var code: [3 * page_size]u8 = @splat(Opcode.JUMPDEST.byte());
    code[page_size - 1] = Opcode.PUSH32.byte();
    code[2 * page_size - 1] = Opcode.PUSH1.byte();
    var bytecode = try Bytecode.init(a, &code, amsterdam);
    defer bytecode.deinit(a);
    const expected = try referenceBoundaries(a, &code, amsterdam);
    defer a.free(expected);
    // Decoding page 0 scanned through the PUSH32 data in page 1.
    try testing.expectEqual(page_size + 32, bytecode.shared.frontier);
    try testing.expectEqual(1, bytecode.decodedPages());
    try expectBoundariesUpToFrontier(&bytecode, expected);
    for (page_size..page_size + 32) |pc| try testing.expectEqual(null, try bytecode.isValidJumpDest(pc, amsterdam));
    try testing.expectEqual(1, bytecode.decodedPages());
    // Activating page 1 scans it completely; its last PUSH1 overshoots into page 2.
    try testing.expect((try bytecode.isValidJumpDest(page_size + 32, amsterdam)) != null);
    try testing.expectEqual(2, bytecode.decodedPages());
    try testing.expectEqual(2 * page_size + 1, bytecode.shared.frontier);
    try expectBoundariesUpToFrontier(&bytecode, expected);
    try testing.expectEqual(null, try bytecode.isValidJumpDest(2 * page_size, amsterdam));
    try testing.expectEqual(2, bytecode.decodedPages());
    try testing.expect((try bytecode.isValidJumpDest(2 * page_size + 1, amsterdam)) != null);
    try testing.expectEqual(3, bytecode.decodedPages());
    try testing.expectEqual(3 * page_size, bytecode.shared.frontier);
    try expectBoundariesUpToFrontier(&bytecode, expected);
}
