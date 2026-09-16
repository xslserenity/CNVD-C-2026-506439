## Security fix summary

This PR fixes `CNVD-C-2026-506439`, a stored second-order command injection in the TPDDNS domain-list lookup flow of `TL-R483G V4.0 20240514_2.2.1`.

## Root cause

`cloud_config.bind.username` is persisted to UCI and later concatenated into `getDomainList` before execution through `/bin/sh -c`. Shell metacharacters in a stored value can consequently be evaluated by the second request.

## Changes

- Validate the cloud username before persistence.
- Revalidate the stored value immediately before command construction.
- Encode the value as exactly one POSIX shell argument.
- Reject control bytes, values longer than 255 bytes, and leading option characters.
- Add Lua 5.1 and real POSIX shell regression coverage.

## Verification

All eight automated test cases pass. The shell-boundary suite covers command substitution, backticks, separators, pipelines, redirection, apostrophes, glob characters, whitespace, Unicode, maximum length, and invalid input types. Every accepted value remains one literal argument, and no sentinel file is created.

Device and vendor-build verification remain unchecked because the submission package does not contain a physical router or the complete proprietary firmware source tree.

## Security metadata

- CNVD ID: `CNVD-C-2026-506439`
- Affected product: TP-LINK TL-R483G V4.0
- Affected firmware: 20240514_2.2.1
- Weakness: stored second-order OS command injection

