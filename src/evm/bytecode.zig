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
    /// (not PUSH data or a consumed Amsterdam immediate). Final for every
    /// position below `frontier`.
    boundaries: []u8,
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
    const boundaries = try gpa.alloc(u8, (bytes.len + 7) / 8);
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
    return (self.shared.boundaries[pc >> 3] >> @intCast(pc & 7)) & 1 == 1;
}

/// Classifies every position below `limit`, continuing the sequential scan
/// from the frontier. Cost is linear in the newly scanned bytes.
fn analyzeTo(self: *const Bytecode, limit: usize, comptime cfg: Config) void {
    const shared = self.shared;
    var pc = shared.frontier;
    const end = @min(limit, self.bytes.len);
    if (pc >= end) return;
    while (pc < end) {
        shared.boundaries[pc >> 3] |= @as(u8, 1) << @intCast(pc & 7);
        pc += instructionLength(self.bytes, pc, cfg);
    }
    shared.frontier = pc;
}

/// Bytes consumed by the instruction starting at `pc`, matching the runtime
/// advance of its handler: PUSH data, and under Amsterdam a valid DUPN/SWAPN/
/// EXCHANGE immediate. An invalid immediate is not consumed (the opcode becomes
/// INVALID), and a missing immediate reads as zero at runtime.
fn instructionLength(bytes: []const u8, pc: usize, comptime cfg: Config) usize {
    const op = bytes[pc];
    switch (op) {
        Opcode.PUSH1.byte()...Opcode.PUSH32.byte() => return op - Opcode.PUSH1.byte() + 2,
        Opcode.DUPN.byte(), Opcode.SWAPN.byte(), Opcode.EXCHANGE.byte() => if (cfg.fork.isEnabled(.Amsterdam)) {
            if (pc + 1 < bytes.len and !invalidImmediate(op, bytes[pc + 1])) return 2;
        },
        else => {},
    }
    return 1;
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
