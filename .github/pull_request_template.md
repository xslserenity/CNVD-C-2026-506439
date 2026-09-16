## Security fix summary

Fixes `CNVD-C-2026-506439`, a stored second-order command injection in the TPDDNS domain-list lookup flow of `TL-R483G V4.0 20240514_2.2.1`.

## Affected component

- Product: TP-LINK TL-R483G V4.0
- Firmware: 20240514_2.2.1
- Component: `usr/lib/lua/luci/controller/admin/tpddns.lua`
- Sink: `d.fork_exec("getDomainList " .. username)`

## Root cause

The cloud username is persisted by the bind operation and later concatenated into a command passed to `/bin/sh -c`. A stored value containing shell metacharacters can therefore be evaluated when the domain-list operation runs.

## Remediation

- Validate the username before persistence.
- Revalidate data read from UCI at the execution sink.
- Encode the username as one POSIX shell argument.
- Reject control bytes, oversized values, and leading option characters.

## Verification

- [x] Lua 5.1 module execution tests pass.
- [x] POSIX shell boundary tests pass.
- [x] Command substitution, separators, pipelines, redirection, backticks, apostrophes, glob characters, spaces, Unicode, and boundary lengths are covered.
- [x] Malicious values remain one literal argument and create no sentinel file.
- [ ] Verified on a physical TL-R483G V4.0 test device.
- [ ] Rebuilt and smoke-tested in the vendor firmware build environment.

## Compatibility and risk

The change is local to the TPDDNS username path and does not modify the global behavior of `luci.sys.fork_exec`. Normal email, phone-number, Unicode, space, and apostrophe-containing identifiers remain supported. Usernames beginning with `-`, containing control bytes, or exceeding 255 bytes are rejected.

## Disclosure

- CNVD ID: `CNVD-C-2026-506439`
- No credentials, session tokens, device addresses, or proof-of-concept output are included in this PR.

