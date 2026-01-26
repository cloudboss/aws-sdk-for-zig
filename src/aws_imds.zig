//! IMDS (Instance Metadata Service) client for EC2 instances.
//!
//! This module provides a reusable client for accessing EC2 instance metadata
//! via the Instance Metadata Service (IMDS). It supports IMDSv2 with token
//! management and caching.
//!
//! ## Usage
//!
//! ```zig
//! var client = try ImdsClient.init(allocator, .{});
//! defer client.deinit();
//!
//! // Get any metadata path
//! const ami_id = try client.get("/latest/meta-data/ami-id");
//! defer allocator.free(ami_id);
//!
//! // Or use convenience methods
//! const region = try client.getRegion();
//! defer allocator.free(region);
//! ```
//!
//! ## Environment Variables
//!
//! - `AWS_EC2_METADATA_SERVICE_ENDPOINT` - Custom endpoint URL
//! - `AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE` - "IPv4" or "IPv6"
//! - `AWS_EC2_METADATA_DISABLED` - Set to "true" to disable IMDS

const std = @import("std");
const auth = @import("aws_authentication.zig");

const scoped_log = std.log.scoped(.aws_imds);

/// Specifies logging level. This should not be touched unless the normal
/// zig logging capabilities are inaccessible (e.g. during a build)
pub var log_level: std.log.Level = .debug;

/// Turn off logging completely
pub var logs_off: bool = false;

const log = struct {
    pub fn err(comptime format: []const u8, args: anytype) void {
        if (!logs_off and @intFromEnum(std.log.Level.err) <= @intFromEnum(log_level))
            scoped_log.err(format, args);
    }

    pub fn warn(comptime format: []const u8, args: anytype) void {
        if (!logs_off and @intFromEnum(std.log.Level.warn) <= @intFromEnum(log_level))
            scoped_log.warn(format, args);
    }

    pub fn info(comptime format: []const u8, args: anytype) void {
        if (!logs_off and @intFromEnum(std.log.Level.info) <= @intFromEnum(log_level))
            scoped_log.info(format, args);
    }

    pub fn debug(comptime format: []const u8, args: anytype) void {
        if (!logs_off and @intFromEnum(std.log.Level.debug) <= @intFromEnum(log_level))
            scoped_log.debug(format, args);
    }
};

/// IMDS endpoint modes
pub const EndpointMode = enum {
    ipv4, // http://169.254.169.254
    ipv6, // http://[fd00:ec2::254]

    pub fn toEndpoint(self: EndpointMode) []const u8 {
        return switch (self) {
            .ipv4 => "http://169.254.169.254",
            .ipv6 => "http://[fd00:ec2::254]",
        };
    }
};

/// IMDS client configuration options
pub const Options = struct {
    /// Custom endpoint URL. If set, overrides endpoint_mode.
    endpoint: ?[]const u8 = null,
    /// Endpoint mode (IPv4 or IPv6). Ignored if endpoint is set.
    endpoint_mode: EndpointMode = .ipv4,
    /// Token TTL in seconds. Default is 6 hours (21600 seconds).
    token_ttl_seconds: u32 = 21600,
};

/// IMDS error types
pub const ImdsError = error{
    /// Failed to acquire IMDSv2 token
    TokenAcquisitionFailed,
    /// Requested metadata was not found (404)
    MetadataNotFound,
    /// IMDS service is unavailable
    ServiceUnavailable,
    /// Response from IMDS was invalid or unexpected
    InvalidResponse,
    /// Could not connect to IMDS endpoint
    ConnectionFailed,
    /// IMDS is disabled via environment variable
    ImdsDisabled,
    /// HTTP request failed
    HttpFailure,
    /// Out of memory
    OutOfMemory,
};

/// Cached IMDSv2 token
pub const Token = struct {
    value: []const u8,
    /// Unix timestamp when the token expires
    expires_at: i64,

    pub fn isValid(self: Token) bool {
        const now = std.time.timestamp();
        // Refresh 120 seconds before expiration
        return now < (self.expires_at - 120);
    }
};

/// IMDS client for accessing EC2 instance metadata.
pub const ImdsClient = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    endpoint_owned: bool,
    token: ?Token,
    token_ttl_seconds: u32,
    http_client: std.http.Client,

    const Self = @This();

    /// Initialize a new IMDS client.
    ///
    /// Returns `ImdsError.ImdsDisabled` if IMDS is disabled via
    /// the `AWS_EC2_METADATA_DISABLED` environment variable.
    pub fn init(allocator: std.mem.Allocator, options: Options) ImdsError!Self {
        // Check if IMDS is disabled
        if (isImdsDisabled(allocator)) {
            log.info("IMDS is disabled via AWS_EC2_METADATA_DISABLED environment variable", .{});
            return ImdsError.ImdsDisabled;
        }

        const endpoint_result = resolveEndpoint(allocator, options);
        const endpoint = endpoint_result.endpoint catch |e| {
            log.err("Failed to resolve IMDS endpoint: {}", .{e});
            return ImdsError.OutOfMemory;
        };

        return Self{
            .allocator = allocator,
            .endpoint = endpoint,
            .endpoint_owned = endpoint_result.owned,
            .token = null,
            .token_ttl_seconds = options.token_ttl_seconds,
            .http_client = std.http.Client{ .allocator = allocator },
        };
    }

    /// Clean up resources.
    pub fn deinit(self: *Self) void {
        if (self.token) |t| {
            self.allocator.free(t.value);
        }
        if (self.endpoint_owned) {
            self.allocator.free(self.endpoint);
        }
        self.http_client.deinit();
    }

    /// Fetch metadata at the given path.
    ///
    /// The path should start with "/" and typically begins with "/latest/".
    /// For example: "/latest/meta-data/ami-id"
    ///
    /// Returns the metadata value. Caller owns the returned memory.
    pub fn get(self: *Self, path: []const u8) ImdsError![]const u8 {
        const token = try self.ensureToken();

        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.endpoint, path }) catch {
            return ImdsError.OutOfMemory;
        };
        defer self.allocator.free(url);

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const req = self.http_client.fetch(.{
            .method = .GET,
            .location = .{ .url = url },
            .extra_headers = &[_]std.http.Header{
                .{ .name = "X-aws-ec2-metadata-token", .value = token },
            },
            .response_writer = &aw.writer,
        }) catch {
            return ImdsError.ConnectionFailed;
        };

        if (req.status == .not_found) {
            return ImdsError.MetadataNotFound;
        }
        if (req.status == .service_unavailable) {
            return ImdsError.ServiceUnavailable;
        }
        if (req.status != .ok) {
            log.warn("Bad status code from IMDS: {}", .{@intFromEnum(req.status)});
            return ImdsError.HttpFailure;
        }

        if (aw.written().len == 0) {
            return ImdsError.InvalidResponse;
        }

        return aw.toOwnedSlice() catch {
            return ImdsError.OutOfMemory;
        };
    }

    /// Get the AWS region from instance placement metadata.
    ///
    /// Returns the region string (e.g., "us-east-1"). Caller owns the returned memory.
    pub fn getRegion(self: *Self) ImdsError![]const u8 {
        return self.get("/latest/meta-data/placement/region");
    }

    /// Get the EC2 instance ID.
    ///
    /// Returns the instance ID string. Caller owns the returned memory.
    pub fn getInstanceId(self: *Self) ImdsError![]const u8 {
        return self.get("/latest/meta-data/instance-id");
    }

    /// Get the IAM role name associated with the instance.
    ///
    /// Returns the role name or `MetadataNotFound` if no role is attached.
    /// Caller owns the returned memory.
    pub fn getRoleName(self: *Self) ImdsError![]const u8 {
        const iam_info = self.get("/latest/meta-data/iam/info") catch |e| {
            if (e == ImdsError.MetadataNotFound) {
                log.info("No IAM role associated with this instance", .{});
            }
            return e;
        };
        defer self.allocator.free(iam_info);

        const IamInfoResponse = struct {
            Code: []const u8,
            LastUpdated: []const u8,
            InstanceProfileArn: []const u8,
            InstanceProfileId: []const u8,
        };

        const parsed = std.json.parseFromSlice(IamInfoResponse, self.allocator, iam_info, .{}) catch |e| {
            log.err("Failed to parse IAM info response: {} - Response was: {s}", .{ e, iam_info });
            return ImdsError.InvalidResponse;
        };
        defer parsed.deinit();

        const role_arn = parsed.value.InstanceProfileArn;
        const first_slash = std.mem.indexOf(u8, role_arn, "/") orelse {
            log.err("Could not find role name in ARN: {s}", .{role_arn});
            return ImdsError.InvalidResponse;
        };

        return self.allocator.dupe(u8, role_arn[first_slash + 1 ..]) catch {
            return ImdsError.OutOfMemory;
        };
    }

    /// Get IAM credentials for the specified role.
    ///
    /// Returns credentials that can be used for AWS API requests.
    pub fn getCredentials(self: *Self, role_name: []const u8) ImdsError!auth.Credentials {
        const path = std.fmt.allocPrint(
            self.allocator,
            "/latest/meta-data/iam/security-credentials/{s}/",
            .{role_name},
        ) catch {
            return ImdsError.OutOfMemory;
        };
        defer self.allocator.free(path);

        const creds_json = try self.get(path);
        defer self.allocator.free(creds_json);

        const CredsResponse = struct {
            Code: []const u8,
            LastUpdated: []const u8,
            Type: []const u8,
            AccessKeyId: []const u8,
            SecretAccessKey: []const u8,
            Token: []const u8,
            Expiration: []const u8,
        };

        const parsed = std.json.parseFromSlice(CredsResponse, self.allocator, creds_json, .{}) catch |e| {
            log.err("Failed to parse credentials response: {} - Response was: {s}", .{ e, creds_json });
            return ImdsError.InvalidResponse;
        };
        defer parsed.deinit();

        const access_key = self.allocator.dupe(u8, parsed.value.AccessKeyId) catch {
            return ImdsError.OutOfMemory;
        };
        errdefer self.allocator.free(access_key);

        const secret_key = self.allocator.dupe(u8, parsed.value.SecretAccessKey) catch {
            return ImdsError.OutOfMemory;
        };
        errdefer self.allocator.free(secret_key);

        const session_token = self.allocator.dupe(u8, parsed.value.Token) catch {
            return ImdsError.OutOfMemory;
        };

        log.debug("IMDS credentials acquired", .{});

        return auth.Credentials.init(self.allocator, access_key, secret_key, session_token);
    }

    /// Ensure we have a valid token, acquiring a new one if necessary.
    fn ensureToken(self: *Self) ImdsError![]const u8 {
        if (self.token) |t| {
            if (t.isValid()) {
                return t.value;
            }
            // Token expired, free it
            self.allocator.free(t.value);
            self.token = null;
        }

        // Acquire new token
        const new_token = try self.acquireToken();
        self.token = new_token;
        return new_token.value;
    }

    /// Acquire a new IMDSv2 token.
    fn acquireToken(self: *Self) ImdsError!Token {
        const url = std.fmt.allocPrint(self.allocator, "{s}/latest/api/token", .{self.endpoint}) catch {
            return ImdsError.OutOfMemory;
        };
        defer self.allocator.free(url);

        var ttl_buf: [16]u8 = undefined;
        const ttl_str = std.fmt.bufPrint(&ttl_buf, "{d}", .{self.token_ttl_seconds}) catch {
            return ImdsError.OutOfMemory;
        };

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const req = self.http_client.fetch(.{
            .method = .PUT,
            .location = .{ .url = url },
            .payload = "",
            .extra_headers = &[_]std.http.Header{
                .{ .name = "X-aws-ec2-metadata-token-ttl-seconds", .value = ttl_str },
            },
            .response_writer = &aw.writer,
        }) catch {
            log.warn("Failed to connect to IMDS for token acquisition", .{});
            return ImdsError.ConnectionFailed;
        };

        if (req.status != .ok) {
            log.warn("Bad status code from IMDS token endpoint: {}", .{@intFromEnum(req.status)});
            return ImdsError.TokenAcquisitionFailed;
        }

        if (aw.written().len == 0) {
            log.warn("Empty response from IMDS token endpoint", .{});
            return ImdsError.TokenAcquisitionFailed;
        }

        const token_value = aw.toOwnedSlice() catch {
            return ImdsError.OutOfMemory;
        };

        const now = std.time.timestamp();
        const expires_at = now + @as(i64, @intCast(self.token_ttl_seconds));

        log.debug("Acquired IMDS token (expires in {d} seconds)", .{self.token_ttl_seconds});

        return Token{
            .value = token_value,
            .expires_at = expires_at,
        };
    }

    const EndpointResult = struct {
        endpoint: error{OutOfMemory}![]const u8,
        owned: bool,
    };

    /// Resolve the IMDS endpoint based on options and environment variables.
    fn resolveEndpoint(allocator: std.mem.Allocator, options: Options) EndpointResult {
        // 1. Check explicit endpoint option
        if (options.endpoint) |endpoint| {
            return .{ .endpoint = endpoint, .owned = false };
        }

        // 2. Check environment variable for custom endpoint
        if (std.process.getEnvVarOwned(allocator, "AWS_EC2_METADATA_SERVICE_ENDPOINT") catch null) |endpoint| {
            return .{ .endpoint = endpoint, .owned = true };
        }

        // 3. Check environment variable for endpoint mode
        if (std.process.getEnvVarOwned(allocator, "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE") catch null) |mode_str| {
            defer allocator.free(mode_str);
            if (std.ascii.eqlIgnoreCase(mode_str, "IPv6")) {
                return .{ .endpoint = EndpointMode.ipv6.toEndpoint(), .owned = false };
            }
            // Default to IPv4 for any other value
        }

        // 4. Use the configured mode
        return .{ .endpoint = options.endpoint_mode.toEndpoint(), .owned = false };
    }
};

/// Check if IMDS is disabled via environment variable.
fn isImdsDisabled(allocator: std.mem.Allocator) bool {
    const disabled = std.process.getEnvVarOwned(allocator, "AWS_EC2_METADATA_DISABLED") catch return false;
    defer allocator.free(disabled);
    return std.ascii.eqlIgnoreCase(disabled, "true");
}

// Tests
test "EndpointMode.toEndpoint returns correct URLs" {
    try std.testing.expectEqualStrings("http://169.254.169.254", EndpointMode.ipv4.toEndpoint());
    try std.testing.expectEqualStrings("http://[fd00:ec2::254]", EndpointMode.ipv6.toEndpoint());
}

test "Token.isValid checks expiration with buffer" {
    const now = std.time.timestamp();

    // Token that expires in 5 minutes - should be valid
    const valid_token = Token{
        .value = "test",
        .expires_at = now + 300,
    };
    try std.testing.expect(valid_token.isValid());

    // Token that expires in 60 seconds - should be invalid (within 120 second buffer)
    const expiring_token = Token{
        .value = "test",
        .expires_at = now + 60,
    };
    try std.testing.expect(!expiring_token.isValid());

    // Token that already expired - should be invalid
    const expired_token = Token{
        .value = "test",
        .expires_at = now - 100,
    };
    try std.testing.expect(!expired_token.isValid());
}

test "resolveEndpoint uses options.endpoint first" {
    const allocator = std.testing.allocator;
    const result = ImdsClient.resolveEndpoint(allocator, .{
        .endpoint = "http://custom-endpoint",
        .endpoint_mode = .ipv6,
    });
    try std.testing.expectEqualStrings("http://custom-endpoint", result.endpoint catch unreachable);
    try std.testing.expect(!result.owned);
}

test "resolveEndpoint uses endpoint_mode when no override" {
    const allocator = std.testing.allocator;
    const result = ImdsClient.resolveEndpoint(allocator, .{
        .endpoint_mode = .ipv6,
    });
    try std.testing.expectEqualStrings("http://[fd00:ec2::254]", result.endpoint catch unreachable);
    try std.testing.expect(!result.owned);
}
