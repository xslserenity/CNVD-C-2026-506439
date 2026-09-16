-- Security helpers for TPDDNS command construction.
--
-- This module is intentionally compatible with Lua 5.1. It performs the
-- checks at the command-execution boundary so that values already persisted
-- in UCI cannot bypass validation.

local M = {}

M.MAX_USERNAME_BYTES = 255

function M.validate_username(value)
    if type(value) ~= "string" then
        return nil, "username must be a string"
    end

    if #value == 0 then
        return nil, "username must not be empty"
    end

    if #value > M.MAX_USERNAME_BYTES then
        return nil, "username is too long"
    end

    -- NUL, CR/LF, DEL, and other control bytes have no valid role in a cloud
    -- account identifier and complicate downstream logging and IPC handling.
    if string.find(value, "%c") then
        return nil, "username contains a control character"
    end

    -- Quoting prevents shell metacharacter injection. This additional check
    -- prevents the username from being interpreted as an option by the
    -- getDomainList program itself.
    if string.sub(value, 1, 1) == "-" then
        return nil, "username must not begin with '-'"
    end

    return true
end

function M.shell_quote(value)
    local valid, err = M.validate_username(value)
    if not valid then
        return nil, err
    end

    -- POSIX shell single-quote encoding. A literal apostrophe is represented
    -- by closing the quote, emitting an escaped apostrophe, and reopening it.
    return "'" .. string.gsub(value, "'", "'\\''") .. "'"
end

function M.build_get_domain_list_command(username)
    local quoted, err = M.shell_quote(username)
    if not quoted then
        return nil, err
    end

    return "getDomainList " .. quoted
end

return M

