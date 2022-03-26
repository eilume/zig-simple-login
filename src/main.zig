const std = @import("std");

const io = std.io;
const crypto = std.crypto;
const stdin = io.getStdIn().reader();
const stdout = io.getStdOut().writer();
const print = stdout.print;

// TODO: figure out how to not need this everywhere
const maxConsoleInputLength: u8 = 64;

const User = struct {
    username: [maxConsoleInputLength]u8,
    salt: []const u8,
    password_hashed: []const u8,
};

const Command = struct {
    name: []const u8,
    description: []const u8,
};

// TODO: find out how to get passed args
// TODO: if args work, add auto-loop mode bool
const skipStartup = false;
const applicationAsciiArtEnabled = true;
const applicationAsciiArtRaw =
    \\   _____            __      __            _       |   
    \\  / __(_)_ _  ___  / /__   / / ___  ___ _(_)__    |   {s}
    \\ _\ \/ /  ' \/ _ \/ / -_) / /_/ _ \/ _ `/ / _ \   |   {s}
    \\/___/_/_/_/_/ .__/_/\__/ /____|___/\_, /_/_//_/   |   {s}
    \\           /_/                    /___/           |   
;

const applicationAsciiArt = std.fmt.comptimePrint(applicationAsciiArtRaw, .{ applicationName, applicationDescription, applicationVersion });

const applicationName = "Simple Login, by eilume";
const applicationVersion = "Status: In-progress";
const applicationDescription = "A simple and very fake console login system.";

const commandList = [_]Command{
    Command{
        .name = "newuser",
        .description = "Creates a new user",
    },
    Command{
        .name = "help",
        .description = "Displays list of commands",
    },
    Command{
        .name = "exit",
        .description = "Quits the application",
    },
};

fn stringTrim(string: []const u8) []const u8 {
    var lastZeroIndex: usize = string.len - 1;

    for (string) |character, index| {
        if (character == 0 or character == 32) {
            lastZeroIndex = index;
        }
    }

    return string[0..lastZeroIndex];
}

// TODO: support arbitrary array lengths
fn stringPad(string: []const u8, output: *[8]u8) void {
    for (string) |character, index| {
        output[index] = character;
    }

    var i: usize = string.len;

    while (i < output.len) {
        // TODO: this doesn't work correctly
        // output[i] = 0x20; // Space in utf-8
        output[i] = ' ';
        i += 1;
    }
}

fn getConsoleInput(buffer: *[maxConsoleInputLength]u8) !void {
    try getConsoleInputWithMessage(&buffer.*, "");
}

fn getConsoleInputWithMessage(buffer: *[maxConsoleInputLength]u8, text: []const u8) !void {
    buffer.* = undefined;

    try print("{s}", .{text});

    const amount = try stdin.read(&buffer.*);

    if (amount == buffer.len) {
        std.log.err("input went over max length, {}, so input will be trimmed", .{maxConsoleInputLength});
    }

    buffer.*[amount - 1] = 0;
}

fn usernameIsValid(username: *[maxConsoleInputLength]u8) !bool {
    try print("\nDEBUG: testing if username: '{s}' is valid and not taken...\n\n", .{username.*});

    return true;
}

fn registerUser(username: *[maxConsoleInputLength]u8, password: *[maxConsoleInputLength]u8) !bool {
    var salt: [32]u8 = undefined;
    crypto.random.bytes(&salt);

    var saltedPassword = [_]u8{undefined} ** (maxConsoleInputLength + 32);
    _ = try std.fmt.bufPrint(&saltedPassword, "{s}{s}", .{ salt, password.* });

    var password_hash: [64]u8 = undefined;
    crypto.hash.sha2.Sha512.hash(saltedPassword[0..], &password_hash, crypto.hash.sha2.Sha512.Options{});

    var user: User = User{ .username = username.*, .salt = salt[0..], .password_hashed = password_hash[0..] };

    try print("\n-=: Created user :=-\n\n", .{});

    try print("username: {s}\n", .{user.username});
    try print("salt: {s}\n", .{user.salt});
    try print("password_hash: {}\n", .{std.fmt.fmtSliceHexLower(user.password_hashed)});

    return true;
}

fn createUser() !void {
    try print("\n-=: Create User :=-\n", .{});

    var createUserLoop: bool = true;

    var username: [maxConsoleInputLength]u8 = undefined;
    var password: [maxConsoleInputLength]u8 = undefined;
    var password_confirm: [maxConsoleInputLength]u8 = undefined;

    while (createUserLoop) {
        try print("\n", .{});

        try getConsoleInputWithMessage(&username, "Username:           ");

        if (try usernameIsValid(&username)) {
            try getConsoleInputWithMessage(&password, "Password:           ");
            try getConsoleInputWithMessage(&password_confirm, "Password (confirm): ");

            var passwordEqual: bool = std.mem.eql(u8, password[0..], password_confirm[0..]);

            if (passwordEqual) {
                if (try registerUser(&username, &password)) {
                    createUserLoop = false;
                }
            }

            if (!passwordEqual) {
                try print("\nFailed: Passwords not equal\n", .{});
            }
        } else {
            try print("\nFailed: Username is not valid\n", .{});
        }
    }
}

fn startup() !void {
    if (applicationAsciiArtEnabled) {
        try print("\n{s}\n", .{applicationAsciiArt});
    } else {
        try print("\n{s}\n{s}\n{s}\n", .{ applicationName, applicationDescription, applicationVersion });
    }
    try print("\nType 'help' for list of commands\n", .{});
}

fn help() !void {
    try print("\nList of commands:\n\n", .{});

    var namePadded: [8]u8 = undefined;

    for (commandList) |command| {
        stringPad(command.name, &namePadded);
        try print("{s} | {s}\n", .{ namePadded, command.description });
    }
}

pub fn main() anyerror!void {
    var running: bool = true;

    var input_buffer: [maxConsoleInputLength]u8 = undefined;

    if (!skipStartup) try startup();

    while (running) {
        try print("\n", .{});

        try getConsoleInputWithMessage(&input_buffer, "Enter Command: ");

        if (std.mem.eql(u8, stringTrim(input_buffer[0..]), "newuser")) {
            try createUser();
        } else if (std.mem.eql(u8, stringTrim(input_buffer[0..]), "help") or std.mem.eql(u8, stringTrim(input_buffer[0..]), "?")) {
            try help();
        } else if (std.mem.eql(u8, stringTrim(input_buffer[0..]), "exit") or std.mem.eql(u8, stringTrim(input_buffer[0..]), "quit")) {
            return;
        } else {
            try print("Unknown command '{s}'\n", .{input_buffer[0..]});
        }
    }
}
