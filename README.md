# Argus Vault

An offline password manager for Windows, written in Rust with a native [Slint](https://slint.dev)
interface. It has **no network code at all**: your vault is one encrypted file on your disk, and
nothing is ever sent anywhere.

> **Status: pre-release, not audited.** Argus Vault is under active development, has not had an
> independent security review, and its file format is **not frozen yet** (it may still change before
> the first release). Do not rely on it as your only copy of passwords you cannot lose. See
> [Security model and limitations](#security-model-and-limitations).

## Why

Most password managers are large, cloud-connected programs. Argus Vault goes the other way: the
smallest attack surface that is still pleasant to use.

- **No network.** No sync, no telemetry, no update checks, no favicon downloads. The dependency
  policy bans network libraries (`cargo deny`).
- **Small trusted core.** All cryptography and vault logic lives in `argus-core`, which contains no
  UI, no network and no `unsafe` code (`#![forbid(unsafe_code)]`). The only crate allowed to use
  `unsafe` is `argus-platform` (Windows API calls), one operation per block, each with a `// SAFETY:`
  comment enforced by lints.
- **Auditable format.** A simple, strictly validated binary format built on RustCrypto primitives.
  The parser is fuzzed and property-tested.

## Features

- Two kinds of entry: **Server** (host, user, password; one click copies the password, straight
  from the list) and **Website** (URL, user, password). Optional notes.
- Search by title, host, username or URL, entirely in memory (passwords and notes are never searched).
- Password and passphrase **generator** (EFF large wordlist), with an entropy estimate.
- **Keyfile** as an optional second factor. Generate one from the app.
- **Protected clipboard:** copies are excluded from Windows clipboard history and cloud sync, and are
  cleared automatically (default 20 s), only if the clipboard still holds Argus's copy.
- **Auto-lock** after inactivity, on minimize, when Windows locks, and on sleep or hibernate.
- **Screen-capture protection:** the window is hidden from screenshots and screen recordings
  (`WDA_EXCLUDEFROMCAPTURE`).
- **One window per vault:** a second instance refuses to open the same file.
- **Import** from KeePass/KeePassXC CSV and unencrypted Bitwarden JSON.
- **Bundled site icons** for 50 well-known sites and self-hosted tools (GitLab, Vault, Portainer…),
  compiled into the program; nothing is downloaded.
- Revealed passwords hide themselves after 10 seconds.

## Cryptography

| | |
|---|---|
| Key derivation | **Argon2id** v1.3, 4 lanes. Costs are chosen **per machine** when a vault is created: at least 512 MiB and 4 passes, scaled up (to 2 GiB) when the machine has the free memory and the time budget (about 1.5 s per unlock), and reduced, with a warning, on machines short of memory |
| Inputs | `BLAKE2b(password)` ‖ `BLAKE2b(keyfile)`; the password is Unicode **NFC**-normalized first, so the same text typed with different input methods opens the same vault |
| Encryption | **XChaCha20-Poly1305**, 256-bit key, fresh random 24-byte nonce on every save |
| Integrity | The whole 83-byte header (including the KDF costs) is authenticated data, so a tampered or downgraded header fails to decrypt |
| Padding | The plaintext is padded to 4 KiB blocks, which hides the exact vault size |
| Writes | Atomic, with a `.bak` copy. Changing the master password replaces the backup, so the old password stops opening any file Argus keeps |

Opening a vault never calibrates: the costs are read from the header, and Argus checks there is enough
free memory before deriving the key.

## Security model and limitations

What it is designed to resist: an attacker who gets a copy of the `.argus` file (a stolen laptop, an
intercepted file, a cloud backup). They learn that it is an Argus vault, its KDF costs and its
approximate size, and can try passwords offline. **Everything then depends on the master password**:
a weak one falls, a long random one (for example six words from the built-in generator) does not,
and adding a keyfile that the attacker does not also have makes guessing infeasible.

Known limitations, stated plainly:

- **Not audited.** The design uses standard primitives and no home-made cryptography, but nobody
  independent has reviewed the code yet.
- **Memory.** While the vault is unlocked its contents live in the process's memory. Secrets that
  pass through the Slint UI live in `SharedString`s, which are not wiped when freed. Memory can end
  up in swap, hibernation files or crash dumps; Argus asks Windows not to include the heap in error
  reports, which is a layer, not a guarantee. Use BitLocker.
- **Clipboard.** If the process is killed abruptly (crash, power loss) nobody clears the copied
  password. A running clipboard monitor can still read it during the 20 seconds.
- **A compromised PC wins.** Malware that can read process memory or log keystrokes is outside what a
  password manager can defend against.
- **Dependencies.** The GUI toolkit brings roughly 250 crates, versus about 35 for the core. Slint
  forces image and SVG decoding and a clipboard and browser helper into the binary even though
  Argus uses none of them for untrusted data. See the notes on this in the plan.
- **Windows only** (x64, Windows 10 or 11). On Windows older than 10 version 2004 the window can only
  be shown black in captures instead of being hidden from them.
- **Icons** are trademarks of their owners; see [`crates/argus-app/icons/ICONS.txt`](crates/argus-app/icons/ICONS.txt).

The full threat model, requirements and the list of open risks are in
[`docs/IMPLEMENTATION_PLAN_PRD.md`](docs/IMPLEMENTATION_PLAN_PRD.md).

## Build

Requirements: Windows 10 or 11 (x64) and [rustup](https://rustup.rs). The compiler version is pinned
in `rust-toolchain.toml` and installs itself on first use; dependency versions are pinned by
`Cargo.lock`, so always pass `--locked`.

```powershell
git clone <this repository>
cd "Argus Vault"
cargo build --release --locked
.\target\release\argus-app.exe
```

Everything CI checks can be run locally:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check licenses bans sources      # needs `cargo install cargo-deny`
```

Notes:

- The key derivation is very slow without optimizations, so the `dev` profile builds the crypto
  crates with `opt-level = 3`.
- A few opt-in tests run real Argon2id at full size, for example `cargo test -p argus-core --release
  calibrate::tests::measure -- --ignored --nocapture` shows what the calibration picks on your PC.
- **Debug builds only:** `ARGUS_ALLOW_CAPTURE=1` turns off screen-capture protection and
  `ARGUS_AUTOLOCK_SECS=N` replaces the auto-lock time, so the UI can be driven by screenshot tools.
  Release builds ignore both.
- Headless screenshots of every screen (no window or desktop session needed):
  `ARGUS_SNAPSHOT_DIR=<folder> cargo test -p argus-app snapshots`.
- Fuzzing uses `cargo-fuzz` and nightly; see [`fuzz/`](fuzz).

## Repository layout

```
crates/
  argus-core/       Cryptography, file format, entries, generator, search, import.  No unsafe, no network.
  argus-platform/   Windows API: clipboard, capture protection, idle and session events, file dialogs,
                    single instance, memory status.  The only crate allowed to use unsafe.
  argus-app/        The Slint GUI.
fuzz/               cargo-fuzz targets for the file parser, the inner decoder and the TOTP parser.
docs/               Requirements and threat model (PRD) and the implementation plan with current status.
```

## Documentation

- [`docs/IMPLEMENTATION_PLAN_PRD.md`](docs/IMPLEMENTATION_PLAN_PRD.md) — what Argus Vault must do and
  why: requirements, threat model, format and design decisions (English).
- [`docs/PLAN_DE_IMPLEMENTACION.md`](docs/PLAN_DE_IMPLEMENTACION.md) — how it is built and where it
  stands: phases, acceptance criteria, measured findings and open items (Spanish; the single source
  of truth for progress).

## Contributing and reporting security issues

Issues and pull requests are welcome once the project settles. Please do not report a vulnerability
in a public issue: use the repository's private security advisory feature (or contact the maintainer
directly) with enough detail to reproduce it.

## License

[GPL-3.0-only](LICENSE). The GPL is also the licence under which Slint is used here.

The bundled icons come from [Simple Icons](https://simpleicons.org) (CC0 1.0); the logos themselves
remain trademarks of their respective owners, and Argus Vault is not affiliated with or endorsed by
any of them.
