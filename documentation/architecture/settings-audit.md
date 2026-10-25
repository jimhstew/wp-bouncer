# WPB-8: Settings audit outside the admin UI (1.2.1)

Closes the S13 gap (`security-fixes.md` §S13). From 1.2.1 every write to `wp_bouncer_settings` made through the options API is audited in one place, whoever makes it: the UI, WP-CLI, `wp eval`, cron or another plugin. **No schema change**: rows go into the existing `bouncer_log` (`ip`, `method` and `uri` are `NOT NULL DEFAULT ''`, so empty values are valid), and no new option is added.

## Classes (new `src/Audit/`)
| Class | Layer | Responsibility |
|---|---|---|
| `Audit\SettingsChange` | Decision core (pure) | `static from( mixed $old_raw, mixed $new_raw, bool $deleted = false ): ?self`. Normalises each side with `( new Settings( is_array( $x ) ? $x : array() ) )->to_array()`, the same merge the firewall applies on load (`merge_defaults` stays private). Junk keys are dropped, partial writes are filled in, and the clamps are applied. When `$deleted` is true, or the new value isn't an array, it adds the path `settings`. Returns `null` when nothing changed. Read-only props: `old`, `new`, `changes`, `risky`. `reason( string $actor ): string` wraps `SettingsDiff::describe()`. |
| `Audit\AuditActor` | Decision core (pure) | `static resolve( ?string $login, array $ctx ): string`. `$ctx` holds the flags `upgrade`, `cli`, `cron`, `rest` and `ajax`. Rules below. |
| `Audit\SettingsAuditor` | Integration (adapter) | Registers the hooks, collects context from WordPress, writes the row, queues the alert, reloads settings and fires the action. Also provides `record_row( string $reason )`, the single audit-row writer that AdminController's "log cleared" row uses too, and `actor()`. |

`SettingsDiff` gains two things. `safe_paths( array $paths ): array` strips every character outside `[A-Za-z0-9_.-]` (a path left empty becomes `?`), caps each path at 64 characters and keeps at most 20 paths, adding `+N more`. `settings` joins `RISKY_KEYS`. `SettingsChange` runs `safe_paths()` on both `changes` and `risky`, so the row, the email and the action all carry the same clean paths.

**Actor rules (`AuditActor`).** The login is never request-derived. It comes from `wp_get_current_user()`, has control characters stripped and is capped at 60 characters. The context label is the first set flag in this order: `upgrade`, `cli`, `cron`, `rest`, `ajax`, else none. With both a login and a label the actor is `login (label)`, for example `jim (cli)` under `wp --user=jim`. With only a login it is `login` (a UI save reads exactly as in 1.2.0). With only a label it is the label. With neither it is `unknown`. Nothing comes from `$_SERVER`, POSIX or headers. Docs: `cli` and `unknown` mean "no authenticated WordPress user", not "trusted".

**Adapter context.** `ctx()` reads `self::$upgrade_depth > 0`, `defined( 'WP_CLI' ) && WP_CLI`, `wp_doing_cron()`, `defined( 'REST_REQUEST' ) && REST_REQUEST` and `wp_doing_ajax()`. The login comes from `function_exists( 'wp_get_current_user' ) && wp_get_current_user()->exists()`. Unit tests cover the full matrix through `AuditActor`. Only the WordPress reads are left to the integration tests.

## Hook wiring (`Plugin::register()`)
`( new SettingsAuditor( $this ) )->register()` is called next to `alerts()->register()`, outside the `is_disabled()` branch: a write made while `WP_BOUNCER_DISABLE` is on must still be audited. `register()` only makes four `add_action()` calls. It reads no option, builds no service and runs no query:
- `update_option_wp_bouncer_settings` (3 args): `on_write( $old, $new )`.
- `add_option_wp_bouncer_settings` (2 args): `on_write( Settings::defaults(), $value )`. This also covers `update_option()` on a missing option, which core turns into an add.
- `delete_option` (generic, fires before the delete): if `$option === Settings::OPTION`, it stores the raw `get_option()` keyed by `get_current_blog_id()`. That read comes from alloptions, so no query. For any other option the cost is one string comparison.
- `delete_option_wp_bouncer_settings`: `on_write( stash, defaults, deleted: true )`.

No `pre_update_option_`, `pre_option_` or `option_` filters are used: they fire before the write or on every read.

**`on_write()` order.** 1. `SettingsChange::from()`; return if `null`. 2. `record_row( $change->reason( actor ) )` writes an `alert` row, rule `settings`, through `log_writer()` (alert rows bypass the budget). When `ms_is_switched()` it writes through a fresh `new BlockLog( $wpdb )`, because the cached writer is bound to the original blog's prefix. The IP, method and URI come from `current_request()`, or `''` when absent. The country is looked up only when the IP is not empty. 3. If `risky` is not empty, it calls `alerts()->on_risky_settings_change( $risky, $changes, $new, $old )`. 4. It calls `plugin->reload_settings()` unless `ms_is_switched()`, since the in-memory copy belongs to the original blog. 5. `do_action( 'wp_bouncer_settings_changed', $changes, $old, $new, $actor )`. The services are built lazily inside the callback, which runs only on a real write.

**Internal writers.** Decision: **log, never silence.** `Installer::activate()` only calls `add_option( defaults )` when the option is absent, which diffs as empty, so no row. No upgrade migration writes settings today. A future migration that does must wrap its write in `SettingsAuditor::as_upgrade( callable )`, which raises a static depth counter and decrements it in `finally`; the row then reads `upgrade`. `uninstall.php` runs while the plugin is inactive, so its hooks are not loaded, and the tables are dropped before `delete_option()`. No guard is needed. There is no `WP_UNINSTALL_PLUGIN` check, because that constant is also defined during other plugins' uninstalls.

## Changes to `AdminController::save()`
`save()` becomes: `preserve_privileged` (unchanged), `update_option( Settings::OPTION, $values, true )`, `reload_settings()`. The reload is idempotent, a cached read, and keeps the UI correct even if the auditor were unhooked. `audit()` and the `do_action` call are deleted. `write_audit_row()` and `actor()` delegate to the auditor (the "log cleared" row keeps its text). Result: one row per UI save, from the hook. A no-change save stops at core's early return (`$value === $old`). A save that differs only in raw form (for example, filling in a key a newer version added) diffs as empty after normalisation, so no row.

## Alert and action gating
- `AlertNotifier::on_risky_settings_change()` gains an optional 4th parameter `?array $old_settings = null`. When it is given, `wants( 'firewall_changes' )` and the base recipients read `$old_settings['alerts']`, not `plugin->settings()`, which can be stale under CLI or belong to another blog. A change that switches alerts off, or redirects them, therefore still alerts the old recipients, plus the new ones as today. The email body lists key paths only. Calls with three arguments behave as before.
- `wp_bouncer_settings_changed` fires once per real change, from every source. Its 4th argument, `$actor`, is new and backward compatible. `$old` and `$new` are now the normalised arrays. They hold values: the developer guide must say listeners must not log them. The plugin adds nothing to `error_log()` or exceptions.
- Extension point: other plugins that change our settings should call `update_option()`. They get auditing for free.

## Multisite
`wp_bouncer_settings` is a per-site option and the hooks fire per blog. The row goes to the current blog's `{prefix}bouncer_log`, also inside `switch_to_blog()` (see the fresh writer above). The diff uses the hook's own `$old` and `$new`. There is no network option (`update_site_option`); one added later needs `update_site_option_*` hooks. Known limit: in a single-process `switch_to_blog()` loop the alert queue is flushed once, at `shutdown`, against the blog that is current then. Recipients are fixed per event, so the mail reaches the right people, but the email budget is charged to that one blog. The usual `wp site list | xargs wp --url=…` runs one process per site and is unaffected.

## Risks and tradeoffs
- Detection only (SB-01): direct SQL bypasses every hook, and PHP code can `remove_action()` the auditor. This goes in the risk register (product-manager) and gets one sentence in the readme (docs-writer).
- The generic `delete_option` hook runs on every option delete, including transient deletes on sites without an object cache. Its cost is one string comparison; this was accepted over trusting the in-memory settings.
- The action now fires inside `update_option()`, before `save()` returns. A listener that writes the option again would recurse: it gets audited again, and core's equality check ends the recursion.

## Security recommendations (`documentation/security/wpb-8-settings-audit.md`)
| Item | Decision |
|---|---|
| SB-01 | Adopted: scope as stated; residual risk recorded, readme sentence. |
| SB-02 | Adopted: `update_option_{option}`; core's early return plus a `null` `SettingsChange` as the second guard. |
| SB-03 | Adopted: add and delete hooks; the delete's old value is stashed from the generic `delete_option`, because core passes no value. |
| SB-04 | Adopted, through the public `Settings` constructor (same merge); a non-array value adds the path `settings`. |
| SB-05 | Adopted, single-path design; no request-scoped flag. |
| SB-06 | Adopted: `$old` is passed into `AlertNotifier`; reload happens after auditing, skipped when the blog is switched. |
| SB-07 | Adopted the "log as `upgrade`" branch; declined the silencer (no internal writer produces a non-empty diff). |
| SB-08 | Adopted, extended: the context suffix applies to any labelled context with a login, not only CLI. |
| SB-09 | Adopted: empty IP, method and URI allowed by the schema; geo skipped for an empty IP; test with `$_SERVER` stripped. |
| SB-10 | Adopted: `SettingsDiff::safe_paths()`; actor sanitised in `AuditActor`; `esc_html` on output unchanged. |
| SB-11 | Adopted: values only in the in-process action; documented in the developer guide. |
| SB-12 | Adopted, including the deviation from the backlog (hooks always registered, work done lazily). |
| SB-13 | Adopted, plus switched-blog handling of the writer and the reload. |
| SB-14 | Adopted: `settings` in `RISKY_KEYS`; alert keys stay risky. |
| SB-15 | Adopted as the test plan below. |
| SB-16 | Adopted (docs-writer): Security changelog entry, severity only; Upgrade Notice. |

## Test plan
**Unit (no WordPress).**
- `SettingsChangeTest`: no change gives `null`; a partial write; a junk scalar gives `settings`; a delete gives `settings` plus the diff from defaults; activation defaults give `null`.
- `AuditActorTest`: the full flag and login matrix, never blank, control characters stripped.
- `SettingsDiffTest`: `safe_paths()` (hostile keys, the 64-character cap, the 20-path cap) and `settings` counted as risky.
- `AlertNotifierTest`: when old alerts are off and new are on, nothing is sent; when old alerts are on and new are off, the alert is queued to the old recipients.

**Integration (`make integration`, MySQL and MariaDB; SB-15 a to h):**
- (a) `update_option()` with user 0: exactly one `settings` row, actor `unknown`, or `cli` with `WP_CLI` defined.
- (b) A UI toggle POST through `save()`: one row, one queued `firewall_changes` alert.
- (c) A no-change `update_option()` gives no row, and a raw-only difference gives no row.
- (d) `delete_option()` then `add_option( mode => monitor )`: two rows, a `firewall_changes` alert, and the action fires.
- (e) Written IPs and patterns never appear in `reason` or the email; hostile array keys are sanitised; also run with `$_SERVER` stripped.
- (f) Multisite: an `update_option()` inside `switch_to_blog( 2 )` writes a row to site 2's table only, and the main site's in-memory settings are unchanged.
- (g) A read-only front-end request issues the same `$wpdb->num_queries` with the auditor registered as without it.
- (h) The e2e suite (`run.sh`, SQLite) runs `wp option patch update wp_bouncer_settings mode monitor` and asserts one row with actor `cli`.
