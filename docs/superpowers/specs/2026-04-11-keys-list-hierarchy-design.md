# Keys List Hierarchy & Expired Key Handling

**Status:** Design — awaiting review
**Date:** 2026-04-11
**Author:** brainstorming session

## Goal

Make the Keys settings screen show primary keys with their subkeys nested beneath them, hide expired keys by default (with an opt-in toggle), and give users a privacy-aware way to refresh expired keys from `keys.openpgp.org` so an extended upstream expiry automatically heals the local keyring.

## Why

Today:
- `parseColonKeyListing` throws away every subkey record. Users can't see what signing/encryption subkeys their keys actually contain, and the single capabilities string on the primary doesn't tell them which capabilities live on which subkey.
- Expired keys clutter the list with no remediation path. The only signal is a red "EXPIRED" badge; the user has no in-app way to pull a renewed version from the keyserver.
- The toolbar "Refresh" button re-reads the local keyring. There's no concept of refreshing a key's *material* from the network.

Users who rotate subkeys yearly or who travel between networks with different trust levels have no in-app story for either problem.

## Non-Goals

Explicitly out of scope for this spec. These are captured in `TODO.md` under
"Future / Deferred":

- Full key detail view (creation time, flags, trust, per-subkey stats)
- "Cleanup" action to prune revoked/expired material from the keyring
- Per-subkey refresh from the keyserver (keys are atomic from HKP's perspective)
- WKD (Web Key Directory) lookup alongside HKP
- Tor / anonymity routing for keyserver fetches
- Revocation certificate management

## User-Visible Behavior

### Default state

- The Keys table shows only non-expired primary keys. Each primary row has a
  disclosure triangle that expands to show its subkeys indented beneath.
- Subkey rows show: `sub` badge, capability icons (sign / encrypt / auth),
  subkey fingerprint (short form), expiry date. User ID and keyserver columns
  are blank on subkey rows.
- Revoked subkeys render with a strikethrough regardless of the toggle state.

### Showing expired keys

- A toolbar toggle labelled "Hide expired" / "Show all" flips between states.
- State persists in `@AppStorage("showExpiredKeys")` and defaults to **hidden**.
- When the user reveals expired keys, a banner appears above the table:
  > ⚠ 3 expired keys. Alp can check keys.openpgp.org for updates.
  > `[ Check now ]` (i tooltip: "Alp will send the fingerprints of your
  > expired keys to keys.openpgp.org over a certificate-pinned TLS connection.")
- The banner's button triggers a batch refresh. While the batch runs, the
  banner swaps to a progress variant with a `[ Cancel ]` button.
- Per-row context menu on primary rows offers "Refresh from keyserver",
  "Copy fingerprint", and "Reveal in keys.openpgp.org…". The refresh entry is
  disabled with a tooltip if the key isn't published on the keyserver.

### Opt-in automatic refresh

- A new Preferences setting, "Automatically check keyserver when showing
  expired keys", defaults to **off**. Stored in
  `@AppStorage("autoRefreshExpiredOnShow")`.
- When enabled, flipping the "Show expired" toggle immediately triggers the
  batch refresh without the banner button step.

### Toolbar button rename

- The current toolbar "Refresh" button is renamed to "Reload" with a tooltip
  "Re-read keys from the local keyring." The word "Refresh" is reserved for
  actions that hit the keyserver.

## Architecture

### Data Model

`Shared/GPGKeyInfo.swift`:

```swift
struct GPGSubkey: Codable, Sendable, Identifiable, Hashable {
    let fingerprint: String        // 40-char hex
    let capabilities: String       // "e", "s", "sca", etc.
    let expiryDate: Date?
    let algorithm: String?         // "RSA 3072", "Ed25519", etc.
    let isRevoked: Bool

    var id: String { fingerprint }
    var isExpired: Bool { expiryDate.map { $0 < .now } ?? false }

    /// SF Symbol names for each capability flag.
    var capabilityIcons: [String] { /* s→signature, e→lock, a→person.badge.key */ }
}

struct GPGKeyInfo: Codable, Sendable, Identifiable, Hashable {
    let fingerprint: String
    let userIDs: [String]
    let capabilities: String
    var hasSecretKey: Bool
    var expiryDate: Date?
    var subkeys: [GPGSubkey]       // new; empty allowed
    // ... existing display helpers unchanged
}
```

Pre-release means no backward-compat shims: the existing custom `init(from:)`
that treats `hasSecretKey` as optional is **removed**. Swift-synthesized
`Codable` is sufficient.

### Parser

`GPGHelper.parseColonKeyListing` is rewritten as a small state machine:

```
pub/sec  → flush current primary; start new primary
fpr      → primary.fingerprint ?? = value if primary has none
           else (if inSubkey) subkey.fingerprint = value
uid      → primary.userIDs.append(value)
sub/ssb  → flush any pending subkey; start a new subkey
             capture capabilities (fields[11])
             capture expiry (fields[6] as unix timestamp)
             capture algorithm (fields[3] algo id + fields[2] bits)
             mark isRevoked if fields[1] == "r"
EOF      → flush pending subkey, then flush primary
```

Algorithm mapping (RFC 4880 + gpg's extensions): 1 → "RSA", 16 → "ElGamal",
17 → "DSA", 18 → "ECDH", 19 → "ECDSA", 22 → "EdDSA". Bits come from fields[2]
for RSA/DSA/ElGamal. ECC keys use the curve name from fields[16] when present,
otherwise fall back to the algorithm string.

### Keyserver Refresh Flow

New component `KeyserverRefreshService` lives in `Alp/Sources/` alongside
`SettingsViewModel` — the refresh flow is driven entirely from the settings
UI in the main app, not from the extension.

```
refreshFromKeyserver(fingerprint expected: String) async throws -> RefreshOutcome
  1. Build https://keys.openpgp.org/vks/v1/by-fingerprint/{expected}
     via URLComponents.percentEncodedPath (same pattern as ComposeView.fetch).
  2. Fetch via KeyserverSession.shared (pinned TLS).
  3. On 404 → return .notPublished
  4. On 200 → HelperXPCClient.shared.previewKey(data) → [GPGKeyInfo]
  5. guard previewed.first?.fingerprint == expected
            else throw .fingerprintMismatch
  6. HelperXPCClient.shared.importKey(data) → GPGImportResult
  7. if result.updatedSignatures || result.newSubkeys → .updated
     else → .alreadyCurrent
```

The preview-before-import step is the security guarantee. Certificate pinning
prevents in-transit tampering, and fingerprint verification catches the
remaining case where somehow an unexpected key is returned for the requested
fingerprint.

### XPC Protocol Change

`importKey` gains a richer reply. Pre-release means we change the signature in
place — no new method.

```swift
struct GPGImportResult: Codable, Sendable {
    let fingerprint: String?
    let newKey: Bool              // IMPORT_OK reason bit 0 (value 1)
    let newUserIDs: Bool          // IMPORT_OK reason bit 1 (value 2)
    let updatedSignatures: Bool   // IMPORT_OK reason bit 2 (value 4)
    let newSubkeys: Bool          // IMPORT_OK reason bit 3 (value 8)
}

func importKey(
    armoredKey: Data,
    reply: @escaping @Sendable (Data?, NSError?) -> Void  // Data = JSON(GPGImportResult)
)
```

The helper runs `gpg --import --status-fd 2 --batch --yes`, parses stderr for
`IMPORT_OK <reason> <fingerprint>` (documented in gpg's `doc/DETAILS`), and
encodes the result as JSON.

Callers that already use `importKey` get the new return value:

- `KeySettingsView.importKeyFromFile` — shows "New key imported" vs
  "Key already up to date" in a toast. This is a small free win from the
  protocol change.
- `HelperXPCClient.importKey` and `GPGXPCClient.importKey` wrappers are
  re-typed to return `GPGImportResult` via `withCheckedThrowingContinuation`.

### Batch Refresh With Concurrency Cap

```swift
@MainActor
final class ExpiredKeyRefresher: ObservableObject {
    enum RowState: Equatable {
        case idle, fetching, updated, alreadyCurrent, notPublished, failed(String)
    }

    @Published private(set) var rowState: [String: RowState] = [:]
    @Published private(set) var isRunning = false
    private var currentTask: Task<Void, Never>?

    func start(keys: [GPGKeyInfo], via service: KeyserverRefreshService) {
        guard !isRunning else { return }
        currentTask = Task { await self.run(keys, via: service) }
    }

    func cancel() { currentTask?.cancel() }
    // ... concurrency-capped TaskGroup implementation ...
}
```

Concurrency cap of 4 parallel requests, enforced with a small `AsyncSemaphore`
helper in `Shared/`. Cancellation propagates cleanly through `Task.isCancelled`
checks before each XPC call. Row state is re-written as each request finishes
so the table updates progressively.

### UI

`KeySettingsView.swift`:

1. **Hierarchical table** via `Table(data, children: \.subkeysForOutline, ...)`
   where `subkeysForOutline` returns `nil` for leaf subkey rows and the
   subkey array for primary rows. A wrapper enum `KeyRow` unifies primary and
   subkey rows so the `Table` API has one homogeneous element type.

2. **Columns:**
   - Type: `KeyTypeLabel` for primaries (`pub+sec` / `pub` / `EXPIRED`);
     muted `sub` badge for subkeys.
   - User ID: `displayName` for primaries; empty for subkeys.
   - Capabilities *(new)*: SF Symbols row (`signature`, `lock`,
     `person.badge.key`, `checkmark.seal`).
   - Fingerprint: short-form 16-char for both.
   - Expires: existing `ExpiryLabel`.
   - keys.openpgp.org: existing `KeyserverStatusLabel` on primaries only.

3. **Toolbar:**
   - Rename existing "Refresh" to **"Reload"** with `arrow.clockwise`.
   - New **"Import Key…"** (already exists).
   - New **"Show all / Hide expired"** toggle with `eye` / `eye.slash` icon.

4. **Banner** above the table: a `VStack` conditionally rendered when
   `showExpired && expiredPublishedCount > 0 && !refresher.isRunning`,
   swapped for a progress variant while `refresher.isRunning`.

5. **Per-row context menu** on primary rows:
   - "Refresh from keyserver" (disabled if not published)
   - "Copy fingerprint"
   - "Reveal in keys.openpgp.org…"

   Subkey rows get only "Copy fingerprint".

6. **Row state during refresh**: the Type column shows a small
   `ProgressView().controlSize(.mini)` when
   `refresher.rowState[fingerprint] == .fetching`, replacing the badge.
   On failure, a red `xmark.circle` appears next to the badge with the error
   as a tooltip.

### Preferences

New row in `GeneralSettingsView` under a "Keys" sub-section (the settings
UI is currently flat under three tabs — General / Keys / Helper — and
feature flags like this one live in General so they're discoverable next
to the setup checklist):

```
Keys
  [ ] Automatically check keyserver when showing expired keys
       When enabled, Alp will fetch updates from keys.openpgp.org whenever
       you reveal expired keys. Uses a pinned TLS connection.
       Default: off.
```

Backed by `@AppStorage("autoRefreshExpiredOnShow")`.

## Error Handling

| Error                                   | User sees                                                     |
|-----------------------------------------|---------------------------------------------------------------|
| Network / TLS failure                   | "Couldn't reach keys.openpgp.org" + error-detail tooltip      |
| HTTP 404 (not on keyserver)             | "Not on keyserver" — row status, not a failure                |
| `fingerprintMismatch`                   | "Keyserver returned an unexpected key" — **red**              |
| gpg import error                        | "Couldn't import — gpg said: \(stderr tail)"                  |
| User cancelled                          | Banner returns to idle, no row-level error                    |

Errors surface in the banner for banner-triggered batches, and in the row's
Type column for per-row actions. `helperError` remains the global toast channel
for genuinely unexpected failures.

## Testing

**Parser tests** (`Tests/GPGHelperTests.swift` or a new `ColonParserTests`):

- Primary key with 0, 1, 2, 3 subkeys — verify fingerprints, capabilities,
  expiry, algorithm per subkey.
- Revoked subkey (`sub r:...`) → `isRevoked == true`.
- Expired subkey under valid primary → primary stays valid, subkey marked.
- Stub secret key (`sec#` + `ssb#`) — smartcard case, `hasSecretKey` stays true.
- Subkey record encountered before any `uid` line (ordering robustness).
- Algorithm mapping for at least RSA (1), ElGamal (16), ECDH (18), Ed25519 (22).

**Keyserver refresh tests:**

- `ExpiredKeyRefresher` unit test with an injected mock fetcher; verifies
  4-way parallelism, cancellation mid-flight, and row state transitions
  (`idle → fetching → updated / notPublished / failed`).
- **Security test:** given a fetched key whose preview fingerprint differs
  from the requested fingerprint, `refreshFromKeyserver` throws
  `.fingerprintMismatch` and does **not** call `importKey`.

**Import-result tests:**

- Parse `IMPORT_OK 0 ABC…` → all flags false.
- Parse `IMPORT_OK 1 ABC…` → `newKey=true`.
- Parse `IMPORT_OK 2 ABC…` → `newUserIDs=true`.
- Parse `IMPORT_OK 4 ABC…` → `updatedSignatures=true`.
- Parse `IMPORT_OK 8 ABC…` → `newSubkeys=true`.
- Parse `IMPORT_OK 12 ABC…` → `updatedSignatures=true && newSubkeys=true`
  (combined flags).
- Missing `IMPORT_OK` → throws the underlying `GPGError.processError`.

**UI / view-model tests:**

- `KeysViewModel.filteredKeys(showExpired: false)` hides expired primaries,
  keeps valid primaries even when all their subkeys are expired.
- `KeysViewModel.filteredKeys(showExpired: true)` returns everything.
- `KeysViewModel.expiredPublishedCount` counts only primaries where
  `isExpired && keyserverStatus == .found`.

## Migration / Cleanup

Because nothing has shipped, this spec does cleanups alongside the changes
instead of preserving compat scaffolding:

- Remove `GPGKeyInfo`'s custom `init(from:)` now that `hasSecretKey` is always
  encoded.
- Remove the "EXPIRED" string handling from `KeyTypeLabel` that overrides the
  badge text (replace with a dedicated `KeyStateBadge` that enumerates
  `pub / pub+sec / expired / revoked`).
- The existing `sortedKeys` logic gains a filter step; its sort semantics stay
  the same so there's no behavioral drift for non-expired keys.

## Risks

- **Table children API on macOS 26.** `Table(children:)` is relatively new;
  sort-column behavior with hierarchical rows has edges. The plan is to verify
  during the first implementation checkpoint that sort + disclosure compose
  correctly; if they don't, fall back to a flat table with indent-based
  visual nesting and ungrouped sort. This risk belongs in the implementation
  plan, not in the spec.
- **IMPORT_OK flag bits.** The documented bit mapping should be pinned to
  gpg's `doc/DETAILS` file during implementation; any mismatch surfaces as a
  failing parse test, not a production bug.
- **Keyserver rate limiting.** 4-way parallelism with an instant batch when
  the toggle is flipped could trigger rate limits against a large keyring.
  Mitigation: cancellation is always available, and the batch is opt-in.

## Open Questions

None after the brainstorming pass. All user-facing decisions are locked:

- Refresh-only remediation (no delete).
- Minimal subkey columns (cap icons + fingerprint + expiry).
- "Reload" for toolbar, "Refresh from keyserver" for rows.
- Privacy-aware manual batch with opt-in auto mode.
- Revoked subkeys shown with strikethrough.
