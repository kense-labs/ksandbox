# KSandbox end-to-end test matrix

Authoritative catalog of **true end-to-end (L2)** and **release assurance (L3)**
scenarios for KSandbox. Claims in [`THREAT_MODEL.md`](../THREAT_MODEL.md) and
[`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) must map to rows here. Unit and
host-only integration tests remain in Gate modules; they are not listed as E2E
unless a guest command runs under the OS boundary.

This document does not close residuals by prose. A row marked `GAP` needs a
live guest test before the surface may stay claimed. A row marked `RESIDUAL`
must stay fail-closed or explicitly documented as unclaimed.

## Definitions

| Tier | Meaning | Counts as E2E here? |
| --- | --- | --- |
| L0 unit | decide / digest / validate / caps / parse | No |
| L1 host integration | Mediators, CLI, policy API without guest fence proof | No (reusable setup) |
| **L2 true E2E** | Guest command under Seatbelt / bwrap(+netns) / AppContainer; assert allow, deny, or raw bypass | **Yes** |
| L3 release assurance | Soak ≥256, WSL native-FS, SBOM, evidence scripts | Yes (release gate subset) |

**Default profile under test:** `SandboxPolicy::kbash_baseline()` with mediation
off. Mediation, grants, and secrets scenarios enable those features explicitly
and run only on platforms where [`BackendCapabilities`](../src/policy/capabilities.rs)
claims the surface. Unclaimed platforms must **fail closed** at construct or
validate time.

**Platform codes:** `D` = all supported OS; `M` / `L` / `W` = macOS / Linux /
Windows only; `FC` = unclaimed → fail-closed; `N/A` = not applicable.

**Evidence codes:** path or test name when covered; `GAP` when missing;
`RESIDUAL` when intentionally not claimed closed.

```text
Host harness → NativeSandbox / CLI → SandboxPolicy → OS backend → Guest
                                                      ↓
                                         allow | deny | raw-bypass assert
```

## How to run

```sh
# PR / CI (all claimed L2 that already exist)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets

# Longer soak (local / release evidence)
GATE7_SOAK_ROUNDS=256 cargo test --all-targets gate7_soak

# WSL2: native Linux FS only (refuse /mnt/<drive>)
./scripts/run-wsl-ga-tests.sh

# Release evidence bundle
./scripts/collect-release-evidence.sh
# Windows: scripts/collect-release-evidence.ps1
```

CI matrix: `ubuntu-latest`, `macos-14`, `windows-latest`. New L2 tests land in
`src/policy/gateN_integration.rs` when possible. Platform pipeline details may
stay in `src/platform/*`, but every claim must cross-link from this matrix.

---

## A. Lifecycle and probe

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-LIFE-01 | Probe succeeds and reports backend | D | Valid workspace dir | `NativeSandbox::new` → `probe` → `capability_report` | Probe ok; backend matches compile-time native | `src/tests.rs` `native_sandbox_canonicalizes_workspace_and_reports_backend` |
| E2E-LIFE-02 | Invalid workspace fails closed | D | Missing path or non-dir | Construct or probe | Error; no unsandboxed exec | `native_sandbox_rejects_invalid_workspaces_and_requests` |
| E2E-LIFE-03 | Capabilities / CLI list unavailable surfaces | D | Baseline sandbox | `capabilities` API or CLI | JSON lists backend + unavailable mediation | `gate6_capability_report_*`; `tests/cli_gate6.rs` |
| E2E-LIFE-04 | CLI `exec` runs inside sandbox | D | Built `ksandbox` bin | `ksandbox exec -- …` | stdout from guest; exit mirrors command | `cli_exec_runs_command_in_sandbox` |
| E2E-LIFE-05 | Missing launcher fails; never bare-exec | D | Absent bwrap / sandbox-exec / pwsh7 (fixture or manual) | Construct / probe / exec | Error; host does not run command unsandboxed | L: `gate7_linux_missing_bwrap_override_fails_closed`; M/W: host binary absence still manual/CI-env residual |
| E2E-LIFE-06 | Overlapping same-workspace executes stay isolated | D | One workspace, two concurrent execs | Overlap `execute` | Distinct outputs; no cross-talk | `gate7_same_workspace_overlapping_executes_stay_isolated` |
| E2E-LIFE-07 | Concurrent workspaces isolated | D | Two workspace dirs | Parallel execs | No shared scratch / output bleed | `native_backend_keeps_concurrent_workspaces_isolated` |

---

## B. Filesystem and credentials

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-FS-01 | Ordinary workspace file writable | D | Baseline | Guest write under workspace | Success | Gate 0 write path in `src/tests.rs` |
| E2E-FS-02 | Protected paths not writable | D | `.git` / credentials / agent metadata present | Guest write attempt | Denied | Gate 0 / `PROTECTED_WORKSPACE_*` |
| E2E-FS-03 | Symlink to outside secret not readable | unix; W equiv | Plant symlink to outside file | Guest read via link | Denied / no leak | Gate 0 + `gate7_direct_symlink_*` |
| E2E-FS-04 | Preexisting hardlink escape denied | D | Hardlink into outside secret | Guest read | Denied | unix Gate 0; `windows_backend_blocks_preexisting_hardlink_escape` |
| E2E-FS-05 | Credential hardlinks in dependency trees denied | D | Alias under package store | Guest read | Denied | `native_backend_blocks_credential_hardlinks_*` |
| E2E-FS-06 | Case-variant control metadata protected | Case-sensitive FS | Variant casing of protected names | Guest write | Denied | `native_backend_protects_case_variant_control_metadata` |
| E2E-FS-07 | Between-exec TOCTOU symlink | unix | After exec1 plant symlink | exec2 read | No outside secret leak | `gate7_tocu_symlink_planted_between_executes_*` |
| E2E-FS-08 | In-command symlink swap during sleep | unix | Guest sleeps; host swaps link | Continue / read | No leak | `gate7_in_command_symlink_swap_*` |
| E2E-FS-09 | Readonly mount: read ok, write fail | D (where mounts claimed) | RO mount configured | Guest read + write | Read ok; write fail | `gate3_native_sandbox_reads_readonly_mount_*` |
| E2E-FS-10 | Outside workspace RW mount refused | D | Policy with outside RW mount | Construct / validate | Fail closed | gate3 |
| E2E-FS-11 | Linux ephemeral scratch (tmpfs) | L; M/W=FC | Ephemeral session mode | Construct + guest write scratch | L accepts; M/W refuse | gate3 ephemeral tests |
| E2E-FS-12 | Workspace path with spaces | D | Path containing spaces | Exec | Succeeds | `native_backend_handles_workspace_paths_with_spaces` |
| E2E-FS-13 | Package-store hardlink to arbitrary outside file | D | Pre-planted link under `node_modules`/`target` | Guest read | **Not bulk-denied** today | **RESIDUAL** — see SECURITY.md; do not claim closed |

---

## C. Environment, output, and resource ceilings

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-ENV-01 | Injection env vars scrubbed | D | Hostile env on host | Guest dump env | Injection keys absent | Gate 0 sanitize |
| E2E-ENV-02 | HOME/TMP re-homed to scratch | D | Baseline | Guest print HOME/TMP | Under scratch | Gate 0 |
| E2E-ENV-03 | Invalid explicit env refused | D | NUL / malformed entries | `execute` with env | Pre-spawn error | `native_backend_rejects_invalid_explicit_environment_entries` |
| E2E-OUT-01 | Oversized streams truncated | D | Guest floods stdout/stderr | Capture | Cap at policy / 100 KiB | gate2 + Gate 0 output limit |
| E2E-OUT-02 | OutputObserver deltas match final summary | D | Observer attached | Exec | Live + final accounting agree | Gate 0 observer test |
| E2E-OUT-03 | Timeout kills full descendant tree | D | Guest spawns child then hangs | Short timeout | Tree dead; `timed_out` | `native_backend_sanitizes_environment_and_kills_timed_out_descendants` |
| E2E-RES-01 | Memory ceiling stops over-alloc | L/W; M=FC | `max_memory_bytes` set | Guest allocate | L/W stop; M refuse at policy | gate2_resources |
| E2E-RES-02 | Process limit blocks extra children | W; unix=FC | Job process limit | Guest spawn extras | W blocked; unix FC at policy | gate2 |
| E2E-RES-03 | Policy timeout ceiling caps request | D | Request timeout > policy ceiling | Exec | Effective timeout ≤ ceiling | gate2 |

---

## D. Default network deny-all

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-NET-01 | IPv4 TCP egress fails | D | Baseline (mediation off) | Guest connect IPv4 | Fail | `native_backend_blocks_ip_and_host_unix_socket_communication` |
| E2E-NET-02 | IPv6 egress fails | D | Baseline | Guest connect/bind IPv6 | Fail | `native_backend_blocks_ip_and_host_unix_socket_communication` (explicit IPv6 probe on unix + Windows) |
| E2E-NET-03 | Host Unix-domain connect fails | unix; W=N/A | Host UDS listener | Guest connect | Fail | Gate 0 network |
| E2E-NET-04 | Linux seccomp: socket → EPERM without mediation | L | Baseline | Guest `socket` | EPERM | Gate 0 + linux seccomp units |
| E2E-NET-05 | Default profile keeps mediation off | D | `kbash_baseline` | Inspect features | `mediated_network` / socks false | `gate7_release_invariants` |

---

## E. Mediated HTTP CONNECT (claiming OS only)

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-HTTP-01 | Allow: guest CONNECT bytes reach upstream | M/L/W | Mediation on + allow rule | Guest CONNECT | Upstream receives payload | `gate4_{macos,linux,windows}_sandbox_mediator_tunnels_*` (+ platform windows private twin) |
| E2E-HTTP-02 | Deny: never reaches upstream | M/L/W | Mediation on + deny | Guest CONNECT | No upstream hit | Same; Windows covered in `gate4_windows_*` |
| E2E-HTTP-03 | Raw direct connect bypass fails | M/L/W | Mediation on | Guest TCP to upstream IP:port | Fail | Same gate4 live tests (incl. Windows raw-blocked) |
| E2E-HTTP-04 | Non-CONNECT method rejected | D (host + claiming OS) | Mediator up | Send GET/etc. | Rejected | `gate7_connect_mediator_rejects_non_connect_method` |
| E2E-HTTP-05 | `path_prefix` never authorizes tunnels | D | Path-prefix allow rule | CONNECT attempt | Denied for opaque tunnel | gate7 |
| E2E-HTTP-06 | `localhost` ≉ `127.0.0.1` alias | D | Allow one form only | CONNECT other form | Denied | decide unit + `gate7_guest_connect_does_not_alias_localhost_to_loopback_ip` (M/L guest) |
| E2E-HTTP-07 | `NO_PROXY=*` / proxy env cannot bypass fence | M/L/W | Mediation on; hostile proxy env | Guest egress | Still fenced | `gate7_{macos,linux,windows}_explicit_no_proxy_cannot_bypass_mediator_fence` |
| E2E-HTTP-08 | DNS / literal host swap bypass | M/L (+ decide D) | Allow literal; CONNECT `localhost` (or reverse) | Guest CONNECT | Denied per non-alias rules | `gate7_guest_connect_does_not_alias_*` + decide units; Windows guest alias live still thinner |
| E2E-HTTP-09 | Unclaimed OS enabling mediation fails closed | FC | Unsupported target | Construct with mediated_network | Error | gate4 refuse tests |

---

## F. Mediated SOCKS5

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-SOCKS-01 | Allow tunnel succeeds | M/L; W=FC | mediated_socks + allow | Guest SOCKS CONNECT | Upstream ok | `gate5_{macos,linux}_sandbox_socks_tunnels_allowed_connect` (+ `linux_socks_bridge_wire_*`) |
| E2E-SOCKS-02 | Deny never reaches upstream | M/L | Deny rule | Guest SOCKS | No upstream | `gate5_linux_sandbox_socks_denies_forbidden_and_blocks_raw_egress` (+ platform twin) |
| E2E-SOCKS-03 | Raw egress still fails | M/L | Mediation on | Direct TCP | Fail | Same linux deny/raw test; macOS covered via Seatbelt fence in socks allow path |
| E2E-SOCKS-04 | BIND / UDP rejected | D | Mediator | BIND/UDP cmds | Rejected | `gate7_socks_mediator_rejects_bind_command` |
| E2E-SOCKS-05 | Hostname allow ≠ literal IP | D | Hostname allowlisted | SOCKS to literal IP | Denied | gate7 |
| E2E-SOCKS-06 | Windows SOCKS enable → fail-closed | W | Policy with mediated_socks | Construct / validate | Error | caps + gate5 windows |

---

## G. Unix-socket allowlist

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-UX-01 | Listed path connectable | M; L/W=FC | Exact allow rule | Guest connect listed UDS | Success | `gate5_macos_allows_listed_unix_socket_*` |
| E2E-UX-02 | Unlisted path denied | M | Second socket outside list | Guest connect | Denied | Same |
| E2E-UX-03 | Non-macOS allow rules refused | L/W | Policy with unix allow | Construct | Fail closed | gate5 |

---

## H. Secrets and grants

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-SEC-01 | Child env sees sentinel only | D (mediation on) | `execute_with_secrets` | Guest dump env | Sentinel present; secret bytes absent | gate8 |
| E2E-SEC-02 | Secrets without mediation refuse pre-spawn | D | Mediation off + secrets | Execute | Error before spawn | gate8 |
| E2E-SEC-03 | Egress reinjection: upstream gets secret; guest never holds it | M/L/W | Mediation + injection rules | Guest HTTP via mediator | Upstream header has secret; guest env/output clean | `gate8_egress_reinjection_*` + `gate8_windows_egress_reinjection_*` |
| E2E-SEC-04 | Audit / digest / capture never contain secret bytes | D | Secrets session | Snapshot audit + digest | No secret material | gate8 |
| E2E-GR-01 | Deny → grant → same command allowed via mediation | M/L/W | Baseline then `apply_network_grant` | Exec before/after | Denied then allowed | `grant_loop_unblocks_a_denied_command_end_to_end` (M/L/W) |
| E2E-GR-02 | Stale digest grant refused and audited | D | Wrong/old digest | `apply_network_grant` | Error + audit | grant_integration |
| E2E-GR-03 | Idempotent regrant | D | Same grant twice | Apply twice | Same digest; single rule | grant_integration |

---

## I. Policy monotonicity

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-POL-01 | `replace_policy` refuses silent broaden / mediation on | D | Baseline sandbox | Replace with broader / mediation | Error | gate6 / gate7 |
| E2E-POL-02 | Narrow without opt-in; re-broaden needs opt-in | D | After narrow | Re-broaden | Second widen requires opt-in | gate7 |
| E2E-POL-03 | Unenforceable policy fails at construct | D | Feature beyond caps | `with_policy` / replace | Error | gate1 |

---

## J. Platform-specific

| ID | Scenario | Platform | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| E2E-OS-M01 | Seatbelt profile denies network; size constrained | M | Baseline / mediated | Compile profile + live guest | Network deny; profile compiles | `src/platform/macos.rs` + live tunnels |
| E2E-OS-L01 | Drop all process capabilities before bash | L | Baseline | Guest check caps | Empty effective set | `linux_backend_drops_all_process_capabilities_before_bash` |
| E2E-OS-L02 | Missing `ksandbox-relay` fails closed for mediation | L | Mediation on; `K_SANDBOX_RELAY` → missing path | Guest mediated CONNECT | Error; no raw egress grant | `gate7_linux_missing_relay_fails_closed_for_mediation` |
| E2E-OS-W01 | AppContainer + Job; PS progress suppressed | W | Baseline | Exec | Isolated; no progress noise | Gate 0 windows tests |
| E2E-OS-W02 | ACL serialization under multi-exec | W | Shared ancestors | Many sequential/parallel execs | No ACL hang / mutual corruption | concurrent + WINDOWS_WSL_GA notes |
| E2E-OS-W03 | WSL2 native Linux FS full claimed suite | L-on-WSL | Native ext4/xfs home (not `/mnt/*`) | `./scripts/run-wsl-ga-tests.sh` | Green | `scripts/run-wsl-ga-tests.sh` |

---

## K. Release / soak (L3)

| ID | Scenario | Preconditions | Steps | Expect | Evidence |
| --- | --- | --- | --- | --- | --- |
| E2E-REL-01 | Soak ≥64 in CI; ≥256 local evidence | Built tree | `GATE7_SOAK_ROUNDS` + collectors | Stable baseline execs | gate7 soak + `collect-release-evidence.*` |
| E2E-REL-02 | Baseline / CONNECT p50 under budget | Warm host | Benchmark tests | p50 within gate7 budgets | gate7 benchmark tests |
| E2E-REL-03 | SBOM names ksandbox | Scripts present | `./scripts/generate-sbom.sh` | CycloneDX includes crate | `tests/sbom_gate7.rs` |
| E2E-REL-04 | Claims ≡ `BackendCapabilities` | All OS | Release invariant tests | Matrix match; default mediation off | `gate7_release_invariants` |

---

## Claim ↔ evidence summary

Aligned with [`THREAT_MODEL.md`](../THREAT_MODEL.md) and
[`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md).

| Surface | macOS | Linux | Windows | Primary E2E IDs |
| --- | --- | --- | --- | --- |
| Network deny-all | claimed | claimed | claimed | NET-01…05, LIFE-*, FS-*, ENV-*, OUT-* |
| Mediated HTTP CONNECT | claimed | claimed | claimed | HTTP-01…03 (`gate4_*` all three OS) |
| Mediated SOCKS5 | claimed | claimed | fail-closed | SOCKS-01…06 |
| Unix-socket allowlist | claimed | fail-closed | fail-closed | UX-01…03 |
| Ephemeral scratch | fail-closed | claimed | fail-closed | FS-11 |
| Secret reinjection at mediator | claimed (live) | claimed (live) | claimed (live) | SEC-03 |
| Grant loop (deny→grant→allow) | claimed (live) | claimed (live) | claimed (live) | GR-01 |
| Proxy-env bypass resistance | claimed (live) | claimed (live) | claimed (live) | HTTP-07 |
| Package-store arbitrary hardlink | residual | residual | residual | FS-13 |

---

## Implementation phases

### P0 — claim consistency — done

1. `gate4_windows_sandbox_mediator_tunnels_allow_deny_and_blocks_raw_egress` — HTTP-01…03
2. `gate7_{linux,windows}_explicit_no_proxy_cannot_bypass_mediator_fence` — HTTP-07
3. `gate8_windows_egress_reinjection_delivers_secret_without_landing_it` — SEC-03
4. `grant_loop_unblocks_a_denied_command_end_to_end` on M/L/W — GR-01
5. Explicit IPv6 probe in Gate 0 network test — NET-02

### P1 — bypass depth — done (thin residuals remain)

- Guest localhost≠127.0.0.1 on M/L — HTTP-08 (`gate7_guest_connect_does_not_alias_*`)
- `gate5_linux_sandbox_socks_*` naming — SOCKS-01…03
- `gate7_linux_missing_relay_fails_closed_for_mediation` — OS-L02
- `gate7_linux_missing_bwrap_override_fails_closed` — LIFE-05 (Linux); macOS/Windows launcher absence still env-dependent

### P2 — residual honesty

- FS-13 remains **RESIDUAL** (monitor or doc-only; do not claim fixed)
- Defaulting mediation still requires [`INDEPENDENT_REVIEW.md`](INDEPENDENT_REVIEW.md)
  sign-off; a green matrix alone does not authorize default mediation
- Windows guest HTTP-08 alias live and macOS/Windows missing-launcher fixtures remain thinner than Linux
## Placement rules for new tests

1. Prefer `src/policy/gateN_integration.rs` with `E2E-*` ID in the test doc
   comment.
2. Keep OS-private plumbing in `src/platform/*` when necessary; add a gateN
   wrapper or matrix cross-link so threat-model evidence is discoverable.
3. Unclaimed surfaces: assert fail-closed; do not skip silently.
4. Update this matrix's Evidence column in the same PR that lands the test.
