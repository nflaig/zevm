// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

pub const Config = struct {
    fork: @import("spec.zig").Spec,
    tracing_enabled: bool = false,
};
