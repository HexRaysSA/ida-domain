// license_checker.zig
// A sample binary for the IDA Domain API workshop
//
// This program validates a license key against the machine's hardware ID.
// Compile and strip to create the analysis target:
//
//   zig build-exe license_checker.zig -target x86_64-linux -O ReleaseSafe -fno-PIE
//   strip --strip-all license_checker
//

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const posix = std.posix;

// Constants that will be visible in the binary analysis
const XOR_CONSTANT: u32 = 0xDEADBEEF;
const TRIAL_DAYS: i64 = 30;
const MAGIC_CHECK: u32 = 0x12345678;

pub fn main() !void {
    const stdout = std.fs.File.stdout();
    const writer = stdout.deprecatedWriter();
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Get machine fingerprint
    const machine_id = getMachineId();
    const fingerprint = hashId(machine_id);

    // Check for license key argument
    if (args.len > 1) {
        const license_key = args[1];
        if (validateLicense(license_key, fingerprint)) {
            try writer.print("License Valid - Full Mode\n", .{});
            return;
        }
    }

    // Fall back to trial check
    if (checkTrialStatus()) |days_left| {
        try writer.print("Trial Mode - {d} days remaining\n", .{days_left});
    } else {
        try writer.print("License Invalid\n", .{});
        std.process.exit(1);
    }
}

/// Reads the machine ID from /etc/machine-id
/// Returns a fixed fallback if the file doesn't exist
fn getMachineId() [16]u8 {
    var buffer: [16]u8 = undefined;

    const file = fs.openFileAbsolute("/etc/machine-id", .{}) catch {
        // Fallback for systems without machine-id
        @memcpy(&buffer, "0000000000000000");
        return buffer;
    };
    defer file.close();

    _ = file.read(&buffer) catch {
        @memcpy(&buffer, "0000000000000000");
        return buffer;
    };

    return buffer;
}

/// Hashes the machine ID into a 32-bit fingerprint
/// Uses XOR and bit rotation - a pattern to find during analysis
fn hashId(id: [16]u8) u32 {
    var result: u32 = 0;

    for (id) |byte| {
        result = result ^ @as(u32, byte);
        result = std.math.rotl(u32, result, 5);
    }

    // XOR with constant - this is what we want to find in the binary
    return result ^ XOR_CONSTANT;
}

/// Parses a license key in format XXXX-XXXX-XXXX-XXXX
/// Returns null if format is invalid
fn parseLicenseKey(key: []const u8) ?u32 {
    // Expected format: XXXX-XXXX-XXXX-XXXX (16 hex chars + 3 dashes = 19 chars)
    if (key.len != 19) return null;

    var result: u32 = 0;
    var hex_count: usize = 0;

    for (key) |c| {
        if (c == '-') continue;

        const digit = std.fmt.charToDigit(c, 16) catch return null;
        result = (result << 4) | @as(u32, digit);
        hex_count += 1;
    }

    if (hex_count != 16) return null;
    return result;
}

/// Validates a license key against the hardware fingerprint
/// This is the main decision point - the branch to find
fn validateLicense(key: []const u8, fingerprint: u32) bool {
    const parsed = parseLicenseKey(key) orelse return false;

    // License key should XOR with fingerprint to produce magic value
    // This is the check that can be "patched"
    const check = parsed ^ fingerprint;
    return check == MAGIC_CHECK;
}

/// Checks if the trial period is still valid
/// Creates a trial file on first run, then checks expiration
fn checkTrialStatus() ?i64 {
    const home = posix.getenv("HOME") orelse return null;

    var path_buf: [256]u8 = undefined;
    const trial_path = std.fmt.bufPrint(&path_buf, "{s}/.license_trial", .{home}) catch return null;

    const file = fs.openFileAbsolute(trial_path, .{}) catch {
        // No trial file exists - create one with current timestamp
        const new_file = fs.createFileAbsolute(trial_path, .{}) catch return null;
        defer new_file.close();

        const timestamp = std.time.timestamp();
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{timestamp}) catch return null;
        new_file.writeAll(ts_str) catch return null;

        return TRIAL_DAYS;
    };
    defer file.close();

    // Read existing trial start timestamp
    var buf: [20]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch return null;

    const start_time = std.fmt.parseInt(i64, buf[0..bytes_read], 10) catch return null;
    const current_time = std.time.timestamp();
    const days_elapsed = @divFloor(current_time - start_time, 86400);

    if (days_elapsed >= TRIAL_DAYS) {
        return null; // Trial expired
    }

    return TRIAL_DAYS - days_elapsed;
}
