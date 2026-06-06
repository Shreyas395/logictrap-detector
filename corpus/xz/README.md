# corpus/xz

XZ Utils backdoor artifacts (CVE-2024-3094). Useful as a demonstration
case: the Ed448 signature gate is information-theoretically
uncrackable, so the analyzer should report
`bypass_difficulty: crypto-hard` rather than attempt symbolic solving.

## Artifacts to add

- The malicious `liblzma.so.5.6.0` or `5.6.1` build artifacts. Source
  these from public hashed IOC advisories rather than pulling from
  live tarballs.
- `bad-3-corrupt_lzma2.xz` and `good-large_compressed.lzma` from the
  injection payload.

## Ground truth

| Gate                              | Kind     | Bypass difficulty |
|-----------------------------------|----------|-------------------|
| Ed448 signature verification      | crypto   | crypto-hard       |
| `argv[0]` ends with `/sshd`       | process  | env-controllable  |
| `TERM` unset                      | env      | env-controllable  |
| `LD_DEBUG` / `LD_PROFILE` unset   | env      | env-controllable  |
| `LANG` set                        | env      | env-controllable  |
| Debugger absent                   | process  | env-controllable  |

## `manifest.json`

Add a manifest mirroring `corpus/synthetic/manifest.json` once the
artifacts are in place.
