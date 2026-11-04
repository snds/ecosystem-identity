# Decision 0003 · The handshake on Windows, and the key types locked out of swap

- **Status:** Proposed
- **Date:** 2026-11-04
- **Builds on:** [decision 0002](0002-identity-handshake.md) (the local handshake, its transports and verifiers) and [decision 0001](0001-identity-crate.md) (the typed keys)
- **Decided elsewhere:** Lockdown decisions D33 (the handshake socket and the process-identity check), D314 (secret pages kept out of swap in Lockdown) and D378 (these two gaps get a pull request here, for Sean to merge, since the crate ships to Mailbird and Synapse too), in `snds/lockdown` `docs/plan/decisions.md`. Lockdown's `docs/plan/28-pq-signatures.md` §9 lists the ML-DSA key as outside D314.

## Decision

Two gaps close, both additive to the public API.

1. **Windows gets a handshake transport and a peer identity.** `PeerIdentity::Windows` and `handshake::windows::NamedPipeTransport` are added, and `ProcessIdentityVerifier` checks a Windows peer by the same rules it applies on Linux and macOS.
2. **The crate's own secret key types sit on pages locked out of swap.** The new `memlock` module does this, and `memlock::report()` counts what was locked and what the system refused.

### 1. The Windows transport and peer

**Transport: a named pipe, not AF_UNIX.** Decision 0002 and `verify.rs` already named a pipe for Windows. Lockdown's own Windows channel (`snds/lockdown` `crates/pipe`) is one, and its browser host already speaks to it. A pipe gives what the Unix socket's file modes give, and more, all on the object itself:

- a security descriptor;
- refusing remote clients;
- refusing a second server on the same name;
- the client's process id from the kernel.

AF_UNIX on Windows has none of those as first-class calls. Its socket file's ACL would need setting separately, and Rust's standard library has no Windows `UnixStream`.

| Step | Platform call | Why |
|---|---|---|
| Name | `\\.\pipe\snds-identity-handshake-<16 hex>`, from SHA-256 of the lower-cased root path (`pipe_name_for`) | Both apps that share a root meet without telling each other. Two roots never collide. |
| Server, first instance | `CreateNamedPipeW` with `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, byte mode, `FILE_FLAG_OVERLAPPED` | A program that already holds the name makes `listen` fail ("another program already holds the pipe"), so nothing can sit in front of the running app. Only local clients. Every wait has a timeout. |
| Server DACL | `D:P(A;;GA;;;<this user's SID>)` via `ConvertStringSecurityDescriptorToSecurityDescriptorW` | Protected, one entry: this user only. This is the `0600` socket inside the `0700` root. |
| Client | `CreateFileW` with `SECURITY_SQOS_PRESENT \| SECURITY_IDENTIFICATION` | The server can learn who the client is but can never act as it. |
| Peer pid | `GetNamedPipeClientProcessId` (server side), `GetNamedPipeServerProcessId` (client side) | The kernel's answer, not the peer's. |
| Peer process | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, held open for the channel's life | While the handle is open, the pid cannot be reused by another process. |
| Peer user | `OpenProcessToken` → `GetTokenInformation(TokenUser)` → `ConvertSidToStringSidW` | Becomes `PeerIdentity::Windows.sid`. |
| Peer image | `QueryFullProcessImageNameW(PROCESS_NAME_WIN32)` | Becomes `PeerIdentity::Windows.exe`. |
| Frames | 4-byte big-endian length, 64 KiB cap (`wire`) | The same as the Unix socket. |

**The peer type has the same shape as the Unix one.** Each variant carries what the kernel said, and the verifier compares it with this process:

- Unix: `pid`, `uid`, `gid`, `exe`.
- Windows: `pid`, `sid`, `exe`.

`PeerIdentity` is `#[non_exhaustive]`, so the new variant breaks no match in an app.

**The same refusals on all three platforms**, each as `Error::PeerUntrusted`, before any key material moves:

| Refusal | Linux / macOS | Windows |
|---|---|---|
| Another user | uid ≠ `getuid()` | SID ≠ this process's token SID, or the token couldn't be read |
| Executable couldn't be read | `/proc/<pid>/exe` or `proc_pidpath` failed | `QueryFullProcessImageNameW` failed |
| Not an installed ecosystem app | path not in the allow-list (canonicalized) | the same, compared without case |
| Couldn't be hashed | the image didn't read | the same |
| Not the binary the ecosystem installed | SHA-256 differs | the same |
| The channel didn't say which process | `PeerIdentity::Unknown` / `InProcess` | the same |

On Windows the hash is read at the image path. Windows refuses to overwrite or delete a running image, and the process is held open for the whole check.

### 2. The key types locked out of swap

`memlock` is Lockdown's D314 mechanism, in this crate:

- `mlock` on Unix and `VirtualLock` on Windows, applied to the pages a secret sits on.
- One page table per process with a count per page. A page several secrets share is locked once and unlocked only when the last one goes, because the kernel does not stack locks on a page.
- A refused lock (`RLIMIT_MEMLOCK` on Linux and macOS, the minimum working set on Windows) is counted, and the secret works as before. It is still wiped on drop; it may reach swap. A refusal is never an error and never a panic.
- On drop, each secret is wiped first and its pages are unlocked after. Field order gives this order, and a test checks it.

**Now locked:**

| Where | Type | What it holds |
|---|---|---|
| `keys` | `Irk`, `PersonaKey`, `AppDataKey`, `CrownJewelKey`, `DeviceUnlockKey`, `AccountUnlockKey`, `KitKey`, `PeerWrapKey` | every 256-bit key in the tree, including the one `kdf::account_unlock_key` returns |
| `kem` | `KemSecretKey`, `SharedSecret` | the receiving key's seed (device and persona, both schemes); the encapsulated secret |
| `kit` | `SecretKey`, `RecoveryCode` (inside `RecoveryKit`) | the kit's two secrets |
| `attach` | the ISK an open `Identity` holds, now `memlock::Locked<SigningKey>` | the Ed25519 Identity Signing Key (wiped by `ed25519_dalek` on drop) |
| `keystore` | `FileKeystore`'s three seeds, now on a locked heap block | the device unlock key and the Ed25519 and receiving-key seeds; **now also wiped on drop**, which they weren't before, and the file's bytes are wiped after reading and writing |

**Exposed to apps:**

- `ecosystem_identity::memlock::report()` returns a `MemoryReport` (also re-exported at the crate root, `Serialize`) with these fields:
  - `supported`
  - `page_size`
  - `pages_locked`
  - `pages_locked_ever`
  - `pages_unlocked_ever`
  - `refused`
- `is_locked()` on each type above, on `RecoveryKit` and on `FileKeystore`, and `Identity::keys_locked()`.
- `memlock::PageLock::{of, of_value}` and `memlock::Locked<T>`, for an app that locks its own secrets through the same page table (see Consequences).

**Not locked, and why:**

- **Values that live for one call on the stack.** These are the 32-byte outputs of `kdf::stretch` and `kdf::subkey` before they become a typed key, the expanded X-Wing decapsulation key during one `decapsulate`, and the `SigningKey` that `FileKeystore::sign` rebuilds for one signature. Each is wiped by its own type. Locking a stack page would lock whatever else shares it, and the page is hot for the call's whole life.
- **Argon2id's working memory.** At the desktop floor it is 64 MiB, eight times Linux's usual 8 MiB limit. The `argon2` crate wipes it.
- **Copies made before a value became a locked type.** Moving a value into a `Box`, the by-value `[u8; 32]` passed to `from_bytes`, and the intermediate CBOR values `cbor::to_canonical` builds all leave such copies behind.

**The ML-DSA key (Lockdown doc 28 §9).** This crate holds no ML-DSA key. It is Lockdown's: `lockdown-crypto`'s `PqSigningKey`, derived in `lockdown-vault` from this crate's root key under Lockdown's own label.

- **Where it lives:** `Box<ml_dsa::ExpandedSigningKey<MlDsa65>>`, one contiguous heap block. That struct holds `rho`, `K`, `tr` and the vectors `s1`, `s2`, `t0`, their NTT forms, and the expanded matrix `A_hat`, all inline as fixed arrays. That is 64 polynomials of 256 `u32` coefficients, about 64 KiB. This is far more than the "about 4 KB" doc 28 gives, which is the encoded key size.
- **Can it be locked?** Yes, because it is one block that does not move. `ml-dsa` wipes the secret parts in its `Drop`. Lockdown can lock it by holding it as `ecosystem_identity::memlock::Locked<ExpandedSigningKey<MlDsa65>>` (or a `PageLock::of_value` beside its `Box`). That costs about 16 pages of 4 KiB, well inside the usual limits. That change belongs to Lockdown, not this crate.

## API

Everything is additive:

- a new `PeerIdentity` variant on a `#[non_exhaustive]` enum;
- new modules (`memlock`, `handshake::windows`), types and methods;
- `MemoryReport` at the crate root;
- `windows-sys` 0.61 as a Windows-only dependency (MIT OR Apache-2.0, already in the lock file through `tempfile`).

No signature changed. No `Error` variant was added, because `Error` is not `non_exhaustive` and a new variant would break an app's exhaustive match. Private fields changed representation (`Identity.isk`, `FileKeystore.keys`, the key newtypes). `FileKeystore` gained a `Drop`, through its private `DeviceKeyFile`; with only private fields, no app can move out of it.

## Proposed as Lockdown decisions (numbers to be assigned in Lockdown's log)

- **Proposed: the identity crate's Windows handshake is a named pipe at `\\.\pipe\snds-identity-handshake-<16 hex of SHA-256(root)>` with a user-only protected DACL**, and its peer is checked by process identity: same SID, image path, SHA-256. That is D33 on Windows. The code-signature check (Authenticode, and the MSIX package family where packaged) stays declared in `CodeSignatureVerifier` and refuses every peer until it is built. Lockdown's `lockdown-codesign` Windows module is where it would come from.
- **Proposed: D314 extends to the identity crate's own keys**, through `memlock`. The process keeps one page table: an app that locks its own secrets calls `memlock::PageLock` rather than its own `mlock`, so neither can unlock a page the other still needs.

## Out of scope here

- The Authenticode / MSIX verifier for Windows, and the XPC transport and audit-token verifier for Apple.
- Core dumps and Windows Error Reporting. That is process policy, which Lockdown's `harden_process` sets, and it is not a library's call.
- Locking Argon2id's working memory.
- Moving Lockdown's own pipe crate or page lock onto this crate (see Consequences).

## Verification

Gates, each run before each push:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings` on Linux, and with `--target x86_64-pc-windows-msvc` and `--target aarch64-apple-darwin`
- `cargo test`

CI runs `fmt`, `clippy` and `test` on `ubuntu-latest`, `macos-latest` and now `windows-latest`, with `fail-fast: false`. The pull request lists the counts.

New tests:

- **`memlock` unit tests.** Locks and unlocks are counted per page, with a page released only with its last secret (and `VmLck` checked on Linux). A refused lock is counted and nothing is held. A value behind `Locked` is dropped while its page is still locked.
- **`keys`, `kem` and `kit` unit tests.** Every type is locked or counted as refused. A forced refusal (per thread, test builds only) leaves each key working through wrap and unwrap, decapsulation, and reading the kit.
- **`tests/memlock.rs`: zeroize on drop proven.** The test binary's global allocator searches every block freed during a drop for the secret's bytes, the last moment they are readable without undefined behaviour. A plain `Box` is caught holding its secret. Every key type, both KEM seeds, the shared secret, the kit, `Locked<SigningKey>` and `FileKeystore` are freed clean.
- **Real refusals.** The memlock tests were also run on Linux with `ulimit -l 0` and `CAP_IPC_LOCK` dropped, where every lock is refused. They pass.
- **`verify` unit tests.** A Windows peer of another user, or with no SID, is refused on every platform. On Windows: the path compares without case; another user, an unreadable image, another path and a wrong hash are each refused by name.
- **`tests/windows_pipe.rs` (Windows).** In a round trip, the server reads the client's pid, SID and image and the client the server's, both sides trust this binary by path and hash, and a 64 KiB frame arrives whole. On a live pipe, the wrong image, the wrong hash and another user are refused. A second listener on a held name is refused. Accept times out, and a later client still gets through. Two clients are served one after another. With nobody listening, connect fails at once. Silence and a gone peer are reported.
- **`tests/handshake.rs` (Windows).** The full handshake end to end over the pipe, with process identity on both sides. The new device is enrolled, and a non-installed peer is refused on both sides with nothing written.

## Consequences

**Lockdown**

1. Bump the pin. Nothing else is required: no call site changes.
2. To share one page table, re-point `lockdown-crypto`'s `locked::PageLock` at `ecosystem_identity::memlock::PageLock` (keep `harden_process`). Settings can then add `memlock::report()`, or show it in place of its own report. Until then, Lockdown's table and this crate's can each unlock a page the other still counts as locked when a key of each shares a page. Those keys stay wiped on drop; they just may reach swap.
3. Lock the ML-DSA expanded key with `Locked`, which closes doc 28 §9's secret-pages gap.
4. `lockdown-pipe` can report `PeerIdentity::Windows` through this crate's pipe, or keep its own channel and `BoundVerifier`. Its `\\.\pipe\snds-lockdown-browser-…` name and its browser host are unaffected either way.

**Mailbird and Synapse**

1. Bump the pin.
2. On Windows, use `NamedPipeTransport::for_root(&root)` with a `ProcessIdentityVerifier` listing the installed binaries, as Linux and macOS use `UnixSocketTransport::for_root`.
3. Optionally show `memlock::report().refused` in a diagnostics screen.
