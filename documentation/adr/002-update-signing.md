# ADR 002: Sign release manifests with an offline Ed25519 key

- Status: Deferred (owner decision 2026-10-23; revisit after 1.2.0). Drafted 2026-10-23 by security-blue.
- Backlog: WPB-3 (scope item 6, acceptance criterion 7); "Update-channel signing" in Later.
- Analysis: [security/update-signing.md](../security/update-signing.md)

## Context

Installed sites update from GitHub releases. `Updater` fetches `releases/latest/download/update.json`, checks that the package URL belongs to this repository's release downloads, downloads the zip and compares its SHA-256 with the one in `update.json`. The hash and the zip come from the same release, so anyone who can write a release can replace both: the maintainer's GitHub account or session, a token, the release workflow, or a third-party action or dev dependency running inside it. Every install with auto-updates on would then run their code within about 12 hours. The SHA-256 protects against corruption, not against a compromised origin.

Constraints: PHP 7.4, WordPress 5.8, no runtime dependencies, one maintainer, a few releases a year.

## Decision

1. Each release gets a new asset, `update.signed.json`: a base64 payload (today's manifest plus `slug` and `repository`) and one or more Ed25519 signatures over `"WP-Bouncer-Update-v1\n" . payload`.
2. The plugin embeds the trusted public keys as a constant (`Updater::TRUSTED_KEYS`, a map from `keyid` to key), with no filter, option or constant override. It verifies with `sodium_crypto_sign_verify_detached()`, which is native, or comes from the `sodium_compat` that WordPress 5.2+ bundles.
3. **Fail closed.** No valid signature means no update is offered or installed. The admin sees why on the Tools tab and in an admin notice, and an `alert` row is logged. There's no fallback to the unsigned `update.json` and no "allow unsigned" switch. Uploading a zip by hand is the deliberate escape hatch.
4. **Signing is offline**, by the maintainer, with a passphrase-encrypted primary key that never goes to GitHub or CI. A second, backup key is embedded from day one and kept offline separately, for rotation after loss or compromise. CI publishes a *draft* release. The maintainer reproduces the build, signs, uploads the signature and publishes.
5. **Migration:** the legacy `update.json` keeps being published on every release so 1.1.x sites still update. The first signed-capable version (proposed: 1.2.0) reaches them through the old SHA-256 path. Its key fingerprints are announced in the release before it (1.1.2) and in the README and SECURITY.md. From that version on, only `update.signed.json` is read.
6. Not adopted: CI-held signing keys (the secret is about as exposed as the repo when there's only one maintainer), WordPress core's `verify_file_signature`/`wp_trusted_keys` (a global key list, wordpress.org hosts only, soft-fail by default), Sigstore as the plugin's check (no small PHP verifier, and it trusts the repo identity). Sigstore attestations may be added for people who install by hand.

## Consequences

- To install malicious code an attacker now needs both the GitHub release *and* the offline key.
- Each release needs a manual signing step (a few minutes) and someone to look after the keys. If both keys are lost, every site needs one manual update.
- Sites still on 1.1.x stay exposed until they update. We can't fix that after the fact.
- New code: `Update\SignedManifest` (pure, unit-tested), changes to `Updater`, `scripts/sign-release.php` and `scripts/verify-release.php`, a split `release.yml`, and a scheduled job that checks the signature on the latest release.
- Depends on the release-pipeline hardening in [security/recommendations.md](../security/recommendations.md) (SB-08, SB-10, SB-13) for its full value.

## Owner decisions needed

1. Offline signing (recommended) or CI signing (weaker; see the analysis).
2. Which version first carries verification (proposed: 1.2.0, with fingerprints announced in 1.1.2).
3. Where the backup key is kept, and who else, if anyone, can reach it if the maintainer is unavailable.
4. Whether to add an `expires` field (freeze protection). Recommended: not yet.
