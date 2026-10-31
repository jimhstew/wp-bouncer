# WPB-12: Detect settings changes made while the plugin wasn't loaded (1.3.0)

Owner: architect, 2026-10-30, branch `release/1.3.0`. Inputs: the WPB-12 section of `documentation/backlog.md` (AC 1 to 16, owner decisions of 2026-10-30) and `documentation/security/wpb-12-settings-drift.md` (SB12-01 to SB12-19). Builds on WPB-8 (`documentation/architecture/settings-audit.md`).

**In one paragraph.** Every audited write of `wp_bouncer_settings` stores a *sealed fingerprint record*: one keyed HMAC per settings leaf (the same key paths `SettingsDiff` reports), sealed by a further HMAC, with the key derived from `wp_salt( 'auth' )`. The daily maintenance cron and a throttled `admin_init` check rebuild the fingerprint from the stored option and compare. A difference writes one `alert` row (rule `settings`, actor `unknown`), queues the `firewall_changes` email, fires `wp_bouncer_settings_changed`, and then replaces the record (auto re-baseline). It adds no schema change: `Installer::DB_VERSION` stays `'4'` (WPB-11's), there is no upgrade step, and the baseline is set the first time it is needed. This is tamper evidence, not tamper prevention (SB12-05).

## 1. Classes

Pure PHP (no WordPress calls, unit-tested), in `src/Audit/`:

| Class | Responsibility |
|---|---|
| `FingerprintKey` | Built from a secret string (the adapter passes `wp_salt( 'auth' )`) and a site id. Derives the MAC key `K = hash_hmac( 'sha256', 'wp_bouncer_fp_key_v1', $secret, true )`. Exposes `kid(): string`, `leaf( string $path, string $canonical ): string` and `seal( array $fields ): string`. Never exposes or stores `K`. |
| `SettingsFingerprint` | `record( mixed $raw, bool $present, FingerprintKey $key, int $logged ): FingerprintRecord`. Walks the leaves (`SettingsDiff::leaves()`), encodes each one canonically (§2.2), adds the shape leaf `settings`, and seals the result. |
| `FingerprintRecord` | Immutable value: `v`, `kid`, `logged`, `leaves`, `seal`. `to_array()`, `static from_stored( mixed ): ?self` (null when missing, not an array, wrong `v` or malformed), `seal_valid( FingerprintKey ): bool`, `equals( self ): bool`. |
| `DriftDetector` | `compare( ?FingerprintRecord $stored, FingerprintRecord $current, FingerprintKey $key, bool $marker ): DriftVerdict`. The decision table in §3. No I/O. |
| `DriftVerdict` | Immutable value: `kind` (`match`, `schema`, `baseline`, `changed`, `fingerprint_missing`, `fingerprint_altered`, `keys_changed`), `paths` (already passed through `SettingsDiff::safe_paths()`), `reportable(): bool`, `forces_alert(): bool` (§9), `reason( string $found_by ): string` (§8, at most 255 characters), `mail_detail( string $found_by, bool $row_written ): string`. |

WordPress-facing:

| Class | Responsibility |
|---|---|
| `Audit\SettingsDriftMonitor` (new adapter) | The check (`check( string $trigger )`), the admin entry point (`on_admin_init()`), and the save-path pair `before_audited_write()` / `after_audited_write()` (§6). It owns the lock, writes the row through `SettingsAuditor::record_row()`, calls `AlertNotifier::on_settings_drift()`, and fires the hooks. Every public method catches `\Throwable` (§5). |
| `Audit\FingerprintStore` (new repository) | `load(): mixed` (raw record), `load_fresh(): mixed` (the record read again, bypassing the runtime cache), `save( FingerprintRecord ): bool`, `marker(): ?int`, `set_marker( int )`, `claim_lock(): bool`, `release_lock()`, `throttle_open(): bool` and `close_throttle()`. Only options and transients. Storage details are for the data-engineer (§19). |

Changed:

| File | Change |
|---|---|
| `src/SettingsDiff.php` | New `public static function leaves( mixed $raw ): array<string, array{0: bool, 1: mixed}>`. It walks `Settings::defaults()` with the same rules as `walk()` (it descends only into named-key schema arrays, treats each `LIST_PATHS` entry as one leaf, and never makes a path from an unknown key). It returns `path => [present, value]` read from the **raw** option, where `present` is false when the path is missing or a parent is not an array. The existing methods do not change. |
| `src/Audit/SettingsAuditor.php` | `on_write()` brackets the WPB-8 work with the monitor (§6). `on_add()` passes "old value absent". `on_delete()` passes "new value absent". `record_row()` gains `bool $request_details = true`; drift rows pass `false` (§8). `register()` does not change ("no reads, no queries"). |
| `src/Alerts/AlertNotifier.php` | New `on_settings_drift( bool $forced, string $detail, array $current_settings ): void` (§9). The event carries `drift => true`: it uses no throttle counter stored in the database, only a per-request cap of 3 (RT-02). Throttle counters, the uncapped list and the notice lists are also ignored when out of range or when their stored timeout is missing or more than an hour and a minute ahead (RT-02). |
| `src/Plugin.php` | Lazy `drift_monitor(): SettingsDriftMonitor`. In `register()`: `if ( is_admin() && ! wp_doing_ajax() ) add_action( 'admin_init', array( $this, 'check_settings_drift' ) )`. `check_settings_drift()` is one line that delegates to `drift_monitor()->on_admin_init()`. In `daily_maintenance()`: `$this->drift_monitor()->check( SettingsDriftMonitor::TRIGGER_CRON )` after `maybe_remind_disabled()`. Both sit outside the `is_disabled()` branch, like the auditor. |
| `src/Admin/LogListTable.php` | Rows with rule `settings` whose reason starts with one of the `DriftVerdict::HEADS` show a translated label, `__( 'Changed outside WP Bouncer', 'wp-bouncer' )`, before the reason (AC 2). The stored reason stays English, like every other row, including WPB-8's. |
| `uninstall.php` | Deletes the new options and the transient (§14). |
| `Installer.php`, `PrivacyTools.php` | **No change.** `DB_VERSION` stays `'4'`. |

## 2. Fingerprint format and storage

### 2.1 Leaves

- The leaves are every path `SettingsDiff::leaves()` returns for the current schema: 63 today (8 top-level, 8 `alerts.*`, 4 `traffic.*`, 43 `rules.*`). Each list in `LIST_PATHS` counts as one leaf.
- The leaf `settings` holds the shape of the raw option: `array`, `missing` (`get_option()` returned false) or `other` (a non-array value). This leaf is what turns a deleted or corrupted option into drift (AC 2). Its name matches the `settings` path that `SettingsChange` already uses for that case.

### 2.2 Canonical encoding and MAC

```
canon(leaf) = present ? 'v:' . json_encode( ksort_recursive( value ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR )
                      : 'absent'
              (on JsonException, for example invalid UTF-8: 'p:' . serialize( ksort_recursive( value ) ))
mac(path)   = substr( hash_hmac( 'sha256', "wp_bouncer_fp_v1\n" . path . "\n" . canon, K ), 0, 32 )   // 128 bits
kid         = substr( hash_hmac( 'sha256', 'wp_bouncer_fp_kid_v1', K ), 0, 8 )
seal        = substr( hash_hmac( 'sha256', "wp_bouncer_fp_seal_v1\n" . v . "\n" . kid . "\n" . blog_id . "\n" . logged . "\n" . json_encode( ksorted leaves ), K ), 0, 32 )
```

- `ksort_recursive` sorts the keys of non-list arrays only. List order is kept, so a reordered allowlist counts as a change, as it does in `SettingsDiff` (strict `!==`).
- **The fingerprint covers raw values, not normalised ones** (a deliberate departure from SB12-01's wording; see §18). The raw value is read at each schema path, so key order and junk keys still make no difference. A later release that changes a default or adds a clamp in `Settings::merge_defaults()` will not make every site report drift once. Types are kept: `"1"` and `true` are different values, as they are in `SettingsDiff`.
- `blog_id` is in the seal. A record copied from site A to site B together with A's settings is therefore "altered" on B.

### 2.3 Stored record

The option `wp_bouncer_fp` (per site, not autoloaded, about 5 KB):

```
array(
  'v'       => 2,
  'kid'     => '8 hex',
  'logged'  => 0,            // time of the last drift row (SB12-10 hourly gate); 0 = never
  'leaves'  => array( 'allowlist' => '32 hex', 'alerts.enabled' => '32 hex', ..., 'settings' => '32 hex', 'wp.admin_email' => '32 hex', 'wp.network_admin_email' => '32 hex' ),
  'pending' => array(),      // RT-03: or array( 'kind' => 'changed', 'paths' => array( ... ) ); sealed
  'seal'    => '32 hex',
)
```

**Format 2 (WPB12-RT-03, RT-07).**

- `pending` records a drift whose Activity Log row could not be written during a save. The save path writes the new record with `pending` set. The next check reports a valid record that has `pending` (under the same hourly gate) and clears it only after a row is written. A new `changed` drift merges its paths with a pending `changed` one.
- Two extra leaves, `wp.admin_email` (the site `admin_email` option) and `wp.network_admin_email` (the network option, multisite only; absent elsewhere), make a changed recipient address a named, alert-forcing drift. There is no sealed copy of the recipients themselves.
- The seal of format 2 also covers `pending`. Format 1 records are still read (their seal has no `pending`). Because the two email leaves are missing from a format 1 record, `DriftDetector` treats a missing email leaf of a format 1 record as a schema difference (rule 6): the first check or save rewrites the record in format 2 silently, with no false drift.
- The record text is read with a prepared SELECT and never through `get_option()`, so a planted serialized object is never unserialized (RT-08). `save()` and `set_marker()` first delete a row that does not look like what the plugin writes, so `update_option()` never reads it as the old value.

The option `wp_bouncer_fp_since` (per site, not autoloaded) holds the time of the first baseline. It is the SB12-06 "baseline established" marker. It is read only when the record is missing or cannot be parsed, so a normal check never reads it.

The record is written only on an audited write whose result differs from the stored record, on drift handling, and on the baseline (AC 10). A check that finds a match writes nothing.

## 3. Decision rules (`DriftDetector`)

In order:

| # | Stored record | Result | Row and alert | New record |
|---|---|---|---|---|
| 1 | missing or unparsable, marker **not** set | `baseline` | none (AC 7) | written; marker set |
| 2 | missing or unparsable, marker set | `fingerprint_missing` | yes, no paths | written, but on the check path only when the row was written (RT-04) |
| 3 | parsable, `kid` ≠ current | `keys_changed` | yes, no paths | written, but on the check path only when the row was written (RT-04) |
| 4 | parsable, seal invalid | `fingerprint_altered` | yes; paths from the leaf diff, labelled unverified | written, but on the check path only when the row was written (RT-04) |
| 5 | valid; some common leaf MAC differs, or a leaf only in the current schema is `present` | `changed` | yes, with those paths | written |
| 6 | valid; only schema differences (a leaf only in the stored record, or a leaf only in the current schema that is absent from the raw option) | `schema` | none | written silently |
| 7 | valid; identical leaf map | `match` | none | not written |

Rule 1's lock (`OptionLock`) treats a held value as stale when it is not `time|token`, or when its time is more than 5 seconds ahead, so a planted row cannot switch the checks off (RT-01). The save path waits for the lock at most about 1.8 seconds (nine pauses of 0.2 s between ten tries) and then goes on without it.

A valid seal proves that the plugin wrote the leaf set, so a set difference under rule 6 can only come from a plugin version that added or removed settings. It is not tampering, which is why rule 6 is silent and rule 4 is not.

## 4. Check triggers and throttling (AC 3, SB12-09, SB12-11)

| Trigger | Where | Gate |
|---|---|---|
| `admin` | `admin_init`, registered only when `is_admin() && ! wp_doing_ajax()` (so not Heartbeat or other admin-ajax calls) | `current_user_can( AdminController::CAPABILITY )` (`manage_options`, the settings screen's capability) first. Then the daily cron event is scheduled again if it is missing (RT-06). Then `throttle_open()`: the transient `wp_bouncer_fp_check` holds the time it was set, and a value that is not an int, lies in the future or is older than an hour counts as open whatever its timeout says (RT-06). On success, `close_throttle()` sets it for `HOUR_IN_SECONDS` **before** the compare. |
| `cron` | `Plugin::daily_maintenance()` (hook `wp_bouncer_daily_maintenance`, per site) | none |
| `save` | inside `SettingsAuditor::on_write()` (§6) | none; it is not filterable |

- The filter `wp_bouncer_settings_drift_check` (`bool $run, string $trigger`, default true) runs for `admin` and `cron` (SB12-17). It never applies to `save`, because skipping the save-path compare would reopen the masking hole (T4).
- Nothing is hooked on the front end, at `plugins_loaded`, on REST, on login or on AJAX. On those requests `drift_monitor()` is never built.
- A non-manager admin request costs one `current_user_can()` call and nothing more.
- Twice-daily cron is declined (§18). The window is at most an hour while a manager is active, a day through cron, and unbounded under `DISABLE_WP_CRON` with no admin visits. The docs state this.

## 5. Check flow (`SettingsDriftMonitor::check( $trigger )`)

```
try:
  if trigger != save and !apply_filters( 'wp_bouncer_settings_drift_check', true, trigger ): return
  key      = FingerprintKey( wp_salt( 'auth' ), get_current_blog_id() )
  raw_rec  = store.load()                              // 1 query (not autoloaded)
  raw_set  = get_option( Settings::OPTION )             // autoloaded: no query
  current  = SettingsFingerprint::record( raw_set, raw_set !== false, key, 0 )
  marker   = raw_rec is unparsable ? store.marker() !== null : true   // marker read only here
  verdict  = DriftDetector::compare( FingerprintRecord::from_stored( raw_rec ), current, key, marker )
  if verdict.kind == match: return                      // no write, no lock
  if !store.claim_lock(): return                        // another request is on it; drift stays detectable
  try:
    if store.load_fresh() != raw_rec: return            // a save or another check changed it: that request handled it
    if verdict.reportable() and stored.logged > now - HOUR: return   // SB12-10 gate (only when the record is valid); nothing written (AC 5)
    if verdict.reportable():
      ok = auditor.record_row( verdict.reason( found_by( trigger ) ), false )
      alerts.on_settings_drift( ... , row_written: ok )                // queued; mailed at shutdown
      if ok: store.save( current with logged = now )                   // re-baseline (SB12-19)
      else:  store.save( stored leaves unchanged, logged = now )       // AC 13: fingerprint kept, retry in an hour; one mail per hour at most
    else:                                               // baseline or schema
      store.save( current )
      if verdict.kind == baseline: store.set_marker( now )
  finally: store.release_lock()
  if verdict.reportable(): fire hooks (§10)             // after the record write and the lock release
catch Throwable e:
  if WP_DEBUG_LOG: error_log( 'WP Bouncer: settings drift check failed: ' . get_class( e ) )   // no message text, no values
  // never wp_die; the fingerprint stays unchanged unless save() already succeeded
```

Why each step is in this order:

- **Lock-free compare first.** A check that finds no drift writes only the throttle transient. It takes no lock and does no write (AC 10).
- **Re-read under the lock.** The save path takes the same lock (§6), so when this request holds it, every other save has either finished (the record changed, so this check backs off) or not yet compared. Either way exactly one request writes the row (AC 4). The walk-through is in §7.
- **Row, then record, then hooks** (SB12-19). A listener on `wp_bouncer_settings_changed` that writes the settings again is then compared against the record that was just written. Without that ordering it would cause a false drift.
- **Rebuilding `current` with `logged = now`.** The seal covers `logged`, so the record is re-sealed.

`found_by( trigger )` returns `the daily check`, `an admin page check` or `a settings save`.

## 6. Save path: the WPB-8 interaction (AC 1, AC 6, SB12-03)

`SettingsAuditor::on_write( $old_raw, $new_raw, bool $deleted = false, bool $old_present = true )` becomes:

```
monitor = plugin.drift_monitor()
monitor.before_audited_write( old_raw, old_present )   // takes the lock; compares OLD against the record; may write a drift row
try:
  ... existing WPB-8 body unchanged: SettingsChange::from(), record_row(), on_risky_settings_change() ...
  // (an effect-free write still reaches after_audited_write; only the WPB-8 row is skipped)
finally:
  monitor.after_audited_write( new_raw, !deleted )    // writes the record for NEW (if different); releases the lock; fires the deferred drift hooks
reload_settings(); do_action( 'wp_bouncer_settings_changed', ... )   // WPB-8's, after the record is fresh
```

- `on_add()` calls `on_write( Settings::defaults(), $value, false, false )`. The WPB-8 diff still uses the defaults as "before", but the drift compare sees "option was missing". A deletion made while the plugin was deactivated is then caught by the `add_option()` in `Installer::activate()` on reactivation.
- `on_delete()` passes `new_present = false`, so the record describes a missing option.
- `before_audited_write()` does three things:
  - It fingerprints `old_raw` and compares it with the stored record (rules 1 to 7).
  - A `baseline` or `schema` result is silent.
  - A reportable result writes the drift row **before** the WPB-8 row (SB12-03 order) and queues the alert. Its hooks are deferred to `after_audited_write()`. The SB12-10 hourly gate does **not** apply on this path: refreshing without a row would mask the drift (T4). The number of rows is still bounded, because a save-path drift row needs an unaudited write between two audited ones, so there can never be more of them than WPB-8 rows.
- **Lock on the save path.** It tries `claim_lock()` up to 10 times, 200 ms apart (2 s at most). If it still has no lock (for example a stale lock under 60 s old after a crash), it goes ahead without one. The save is authoritative: it describes the value that was just written. The lock is re-entrant within the request (a static depth counter), so a nested audited write, such as a listener saving again, does not wait on itself.
- **Plugin-driven rewrites** (`SettingsAuditor::as_upgrade()`, `Installer`) are audited writes, so they re-baseline in the same call with no drift row (AC 7, SB12-07). They still compare their *old* value: an upgrade does not make an earlier drift legitimate.
- **No recursion** (AC 6). The record and the marker are separate options. The auditor listens to `update_option_wp_bouncer_settings`, `add_option_wp_bouncer_settings` and `delete_option_wp_bouncer_settings` only, and `before_delete()` filters on the name.
- **Too early for `wp_salt()`.** If an audited write happens before `pluggable.php` is loaded (another plugin writing while it is being included), the monitor keeps the first old value and the last new value and runs both halves on `init`. This is rare, and it never touches `plugins_loaded`.

Cost of an audited save: one extra non-autoloaded `get_option()`, about 130 HMACs, and one `update_option()` when the record changes. Saves are rare.

## 7. Bounds and concurrency (AC 4, AC 5, SB12-10)

- **Rows.** The check path writes at most one drift row per site per hour (gated on `logged` in the sealed record). The admin check runs at most hourly and the cron daily. A lost transient only causes an extra compare, never an extra row inside the hour. Drift rows are `ACTION_ALERT`, which bypasses `WriteBudget`, so the gate is the only bound.
- **Mail.** Mail uses the existing `settings` bucket (10 an hour) and the queue. Forced mails (§9) are `uncapped`, within `MAX_UNCAPPED_PER_HOUR`.
- **Lock.** The lock is the option `wp_bouncer_fp_lock`, claimed with the `INSERT IGNORE` and compare-and-swap pattern of `AlertNotifier::claim_reminder_slot()`. A lock older than 60 s is taken over by the compare-and-swap. It is released in `finally` and is never autoloaded.
  - `add_option()` is **not** used. Core's `INSERT ... ON DUPLICATE KEY UPDATE` lets two racing first claims both succeed, as the comment on `claim_reminder_slot()` already notes (§18, SB12-10).
- **Interleavings, walked through.** Drift D is present, a check C and a save S run at once.
  - C locks first: C writes the row for D and a record of the settings it read (which include D). S then compares its old value (also including D) with that record, gets a match, writes no drift row, writes the WPB-8 row and refreshes the record.
  - S locks first: S writes the row for D and the new record. C's fresh re-read sees a changed record and backs off.
  - Both orders give one drift row and one WPB-8 row.
- **Persistent object cache.** A direct SQL edit stays invisible to WordPress, and to the firewall, until the cached `alloptions` entry expires. The check sees it when it takes effect. This is documented.

## 8. Log row (AC 2, SB12-15, SB12-16)

| Column | Value |
|---|---|
| `action` | `alert` (`BlockLogInterface::ACTION_ALERT`). Not a threat action: it is outside `BlockLog::THREAT_ACTIONS` and inside `NON_THREAT_ACTIONS`, so the WPB-11 map, the widget and the "blocked" totals ignore it |
| `rule` | `settings` (`AdminController::SETTINGS_LOG_RULE`) |
| `created_at` | detection time (the row says it is not the time of the change) |
| `ip`, `country`, `user_agent`, `method`, `uri` | empty (`record_row( $reason, false )`). These would belong to the checker (an admin or cron), not to the author, and a drift row that showed the admin's IP next to "actor unknown" would point at the wrong person (stricter than SB12-15) |
| `reason` | English, fixed heads (`DriftVerdict::HEADS`), paths only, at most 255 characters, with the paths cut first as in `SettingsDiff::describe()` |

Reason texts:

- `changed`: `Settings changed outside WP Bouncer (found by the daily check, not when made; actor unknown): allowlist, rules.waf.enabled. Now the baseline; review them.`
- `fingerprint_missing`: `Settings fingerprint missing or altered (found by an admin page check; actor unknown). Baseline rebuilt; review all settings.`
- `fingerprint_altered`: the same head, plus `Differs from the record (unverified): <paths>.` when there are paths.
- `keys_changed`: `Security keys changed or settings fingerprint altered (found by ...; actor unknown). Baseline rebuilt; review all settings.`

## 9. Alert (AC 8, SB12-08, SB12-18)

`AlertNotifier::on_settings_drift()` queues one event of type `firewall` with `settings => true`, `logged => true`, `blog => get_current_blog_id()` and `ctx['actor'] => 'unknown'`.

- **Title:** `Firewall settings changed outside WP Bouncer`.
- **Detail** (`DriftVerdict::mail_detail()`): `Found by the daily check, not when it was made. Actor unknown; the request details in this email are of the check, not of the change. Changed: <safe paths | "unknown (the stored fingerprint was missing or altered)" | "unknown (the WordPress security keys changed, or the fingerprint was altered)">. This can be a legitimate restore, import or staging copy. WP Bouncer now treats these settings as normal: review them.` When the row failed, `The Activity Log row could not be written.` is appended. When the mail is forced, `Sent to the site admin as well because the alert settings may have changed.` is appended.
- **Every drift is mailed** (owner decision 2). There is no `risky` classification, because the direction of a change (on to off) cannot be known without old values.
- **Normal case.** The mail is sent only if `wants( 'firewall_changes', current alerts )`. Recipients are `firewall_recipients( array(), current alerts )`, and the mail counts against the `settings` cap.
- **Forced case** (`DriftVerdict::forces_alert()`). A mail is forced when the paths include anything that `silences_alerts()` matches (`alerts.*`, `mode`, `settings`), or when the kind is `fingerprint_missing`, `fingerprint_altered` or `keys_changed`, since in those cases nobody knows what changed.
  - The alert switch is ignored.
  - Recipients are `base_recipients( current alerts )`, plus `get_option( 'admin_email' )`, plus the network admin on multisite.
  - The mail is `uncapped`.
- The row is written whatever the switch says (AC 8).
- **Upgrade Notice** (AC 16). The alert is on by default (`firewall_changes` defaults to true), so readme.txt needs an Upgrade Notice. That is the docs-writer's job.

## 10. Public hooks and extension points

| Hook | Type | When | Args |
|---|---|---|---|
| `wp_bouncer_settings_changed` (existing) | action | after a reportable drift (and as before on every audited change) | `$paths` (safe), `$old = array()` (no old values exist; listeners must tolerate an empty array; to be documented), `$new` (current, normalised), `$actor = 'unknown'` from `AuditActor::resolve( null, array() )` |
| `wp_bouncer_settings_drift` (new) | action | after a reportable drift, after the record write | `string[] $paths`, `string $kind`, `string $trigger` (`admin`, `cron`, `save`), `bool $row_written`. For shipping evidence off the server (SB12-05) |
| `wp_bouncer_settings_drift_check` (new) | filter | before an `admin` or `cron` check | `bool $run`, `string $trigger` |

There is no UI, no acknowledge state (SB12-19) and no "trust the next change" switch (SB12-12). The existing listeners (`DashboardWidget::flush`, `ThreatMapPanel::flush`) ignore the arguments.

## 11. First run, upgrade from 1.2.1, reactivation (AC 7, SB12-07)

- **Fresh install.** `Installer::activate()` adds the settings option. That is an audited add, and the save path sees no record and no marker, so it writes the baseline silently and sets the marker.
- **Upgrade from 1.2.1 or earlier.** No `Installer` step is added and `DB_VERSION` is not bumped. The first `admin` or `cron` check, or the first audited save, takes rule 1 and writes the baseline silently. Anything changed between the update and that first baseline is not seen; this is documented. The baseline does not depend on WPB-11's DB_VERSION 4 upgrade, so it also works if that upgrade failed.
- **Deactivate and reactivate.** Deactivation clears cron but keeps `wp_bouncer_fp` and `wp_bouncer_fp_since`.
  - A change made while deactivated is caught by the next check, or by the reactivation save path if the option was deleted.
  - If the option still exists, `activate()` does not write it and the record is kept.
- **Downgrade, change, upgrade again.** This is reported once as drift. That is correct, because 1.3.0 was not running when the change was made. A record with an unknown future `v` is unparsable and gives rule 2 once after a downgrade.

## 12. Privacy (AC 9, SB12-01, SB12-15)

- The record holds key paths and 128-bit keyed MACs. No value can be recovered without `K`, which comes from `wp-config.php` and is never stored. A bare MAC of a boolean, a country code or one IP cannot be brute-forced from a backup of the options table alone (SB12-02 caveat: this is not true when the salts live in the database).
- Rows and mails carry paths only, through `safe_paths()`, and actor `unknown`. Rows carry no IP or user agent (§8).
- No personal data is added. The exporter, the erasers and the privacy policy text **do not change**. Rows follow the existing retention.

## 13. Multisite (AC 11, SB12-13)

- Everything is per site: the record, the marker, the lock, the throttle transient (per-blog options and transients) and the row (per-blog log, with `record_row()`'s non-switched writer when switched). `get_option()` is used, never `get_site_option()`.
- The seal includes `blog_id`.
- The cron check runs inside each site's own `wp_bouncer_daily_maintenance`, so no request loads every site. A network-wide sweep is declined (§18).
- `wp_salt()` is network-wide, so a salt rotation gives one `keys_changed` row per site. That is expected and documented.
- The network admin screen runs the `admin` check for the main site only.
- Network-level settings are out of scope. The plugin keeps no network settings option, only `wp_bouncer_update_manifest` and `wp_bouncer_old_wp_mailed`, which are not settings.

## 14. Uninstall (AC 10, SB12-14)

`wp_bouncer_uninstall_site()`, which already runs per site through `Installer::for_each_site()` after `SettingsAuditor::unregister()`, adds:

```
delete_option( 'wp_bouncer_fp' );
delete_option( 'wp_bouncer_fp_since' );
delete_option( 'wp_bouncer_fp_lock' );
delete_transient( 'wp_bouncer_fp_check' );
```

The fixed-name regex can also gain `wp_bouncer_fp_check`, for its timeout row on sites without an object cache (§19). Deleting `wp_bouncer_settings` during uninstall writes no drift row, because the auditor is unregistered and no check runs during uninstall.

## 15. Performance (AC 3, SB12-11)

- **Front end, REST, AJAX, login:** no new hook, object, option read or query.
- **Admin, manager:** one transient read per page. Once an hour that becomes one non-autoloaded `get_option()` plus about 65 HMACs (well under 1 ms) and one transient write. The lock and the record write happen only on drift or baseline.
- **Cron:** the same, once a day per site.
- **Save:** §6.

## 16. Risks and tradeoffs

1. **DB write and read of `wp-config.php` together** (T2): no protection. With DB write access only, an attacker can still delete both the record and the marker to force a silent baseline (SB12-06 residual). The docs say so (SB12-05).
2. **False positives** (T10): restores, imports, staging copies (`keys_changed` when the salts differ), salt rotations and downgrades each give one row and one mail. The wording says it may be legitimate.
3. **Save path ignores the hourly gate.** This is chosen over masking. It is bounded by the number of audited writes.
4. **Raw fingerprint, not normalised.** A rewrite that has no effect (for example `true` to `1` by a serializer in another plugin) shows as drift. In exchange, plugin updates that change defaults or clamps never cause false drift.
5. **Lock wait on save.** Up to 2 s, only within 60 s of a crashed check.
6. **Persistent object cache.** Detection is delayed until the edit takes effect (§7).
7. **Weaken then revert** between two checks is never seen (T6). This is point-in-time comparison, not a change feed. Documented.
8. **Schedule.** About 7 new classes on a release already carrying WPB-11 and WPB-13. The pure core is small and fully unit-testable.

## 17. Test plan

Unit tests (`tests/Unit/Audit/`, `tests/Unit/SettingsDiffTest.php`; no WordPress, with a fixed secret):

| Test | ACs |
|---|---|
| `SettingsDiff::leaves()`: list paths are one leaf; unknown keys are ignored; missing path or non-array parent gives `present=false` | 15 |
| `SettingsFingerprint`: same settings in a different key order give an identical record; changing one leaf changes exactly that MAC; non-scalar values (nested arrays, objects decoded to arrays, invalid UTF-8 through the `p:` fallback) are stable; `"1"` and `true` differ | 15, 9 |
| The record contains no substring of any value (allowlist IP, recipient email, block message) | 9 |
| `DriftDetector`, one test per row of §3: same settings → `match`; one key changed → `changed [path]`; key added (present in raw) → `changed`; key removed from raw → `changed`; junk key → `match`; option missing → `changed [settings]`; no record without marker → `baseline`, with marker → `fingerprint_missing`; `kid` differs → `keys_changed`; seal broken, leaf dropped, or extra leaf with old seal → `fingerprint_altered`; schema-only differences → `schema`; record from another `blog_id` → `fingerprint_altered` | 2, 7, 15 |
| `DriftVerdict`: reason at most 255 characters with the head intact and 30 long paths cut; `safe_paths()` applied; `forces_alert()` for `alerts.*`, `mode`, `settings` and the unknown kinds | 2, 9, 8 |

Integration tests (`tests/Integration/Audit/SettingsDriftTest.php`, MySQL/MariaDB and the SQLite e2e):

| Test | ACs |
|---|---|
| Direct `$wpdb` update of the option, then a `cron` check → one `alert`/`settings` row, actor `unknown`, empty IP, one queued `firewall_changes` mail; the record is replaced; a second check → nothing | 2, 4, 8 |
| `update_option()` with the auditor hooks removed → the same result | 2, 15 |
| `delete_option()` with the hooks removed → a row naming `settings` | 2 |
| UI save (admin-post handler) and plugin-loaded `update_option()` → exactly one WPB-8 row and no drift row; the record changes in the same request | 1, 6 |
| SB12-03: SQL edit of leaf A, then a UI save of leaf B → a drift row naming A first, then the WPB-8 row naming B | 6 |
| Writing `wp_bouncer_fp` triggers no audit hook (hook call counter at 0) | 6 |
| A listener on `wp_bouncer_settings_changed` that saves the settings again → no false drift | 6 |
| No record and no marker → silent baseline on the first `admin` check; 1.2.1 fixture data (settings, no fp options) → silent baseline; record deleted with the marker kept → `fingerprint_missing` row; both deleted → silent (documented residual) | 7 |
| `SettingsAuditor::as_upgrade()` write → WPB-8 row only, then a check finds a match | 7 |
| Deactivate, SQL edit, reactivate, check → one row; deactivate, delete the option, reactivate → one row from the save path | 7 |
| `alerts.firewall_changes` off → row written, no mail; `alerts.enabled` set to false by the drift → mail forced to the recipients and `admin_email` | 8 |
| Rewrite the option on each of 5 checks within an hour (throttle transient deleted) → 1 row; the hour passes → 1 more row, naming the accumulated paths | 4, 5 |
| `admin_init` throttle: two admin page loads → one compare (query counter); a non-manager → no option read; an AJAX request → no hook | 3 |
| Concurrency: claim the lock from a second connection, run a check → no row and no write; release, run again → one row. Also fork two PHP processes on one drift → one row (e2e) | 4 |
| Lock held by a fake earlier request → the save path waits and then proceeds; a stale (over 60 s) lock is taken over | 4 |
| Record-write failure (filter `pre_update_option_wp_bouncer_fp` returns the old value) → row written, next check retries; missing log table → `record_row()` false, mail says so, leaves unchanged | 13 |
| `check()` with a throwing `wp_salt` filter → no exception escapes, the debug log line is written, the record is unchanged | 13 |
| No revert: after drift the settings are still the drifted values; the firewall is unaffected | 14 |
| Multisite: drift on site B → a row in B's log only; A's record and log are unchanged | 11 |
| A drift row is absent from `ThreatQuery` tallies, the widget's blocked counts and the map (as for SB13-10) | (SB12-16) |
| Front-end request (e2e, `?p=1`): `pre_option_wp_bouncer_fp`, `pre_option_wp_bouncer_fp_since` and the lock option are never read or written (instrumented by an mu-plugin) | 3, 15 |
| Uninstall single-site and multisite: the three options and the transient are gone on every site (extend `UninstallTest` and `MultisiteUninstallTest`) | 10 |
| SQLite e2e: the drift scenario and the `INSERT IGNORE` lock work | 12 |

Docs (AC 16) belong to the docs-writer: CHANGELOG and readme **Added** entries; the 1.2.1 Known limits are replaced by the remaining limits (DB write access with the salts, changes before the baseline, the detection window, weaken-then-revert); the SB12-05 sentence; the SB12-02 salt caveat in the settings help; an Upgrade Notice; and the new hooks in the developer guide.

## 18. Security recommendations (`documentation/security/wpb-12-settings-drift.md`)

| ID | Decision | How, or why not |
|---|---|---|
| SB12-01 per-leaf keyed HMAC | **Adopted, one change** | Per-leaf, 128-bit truncated HMAC-SHA256 with the path in the input and the key from `wp_salt( 'auth' )`, never stored; no copy, no bare hash (§2). **Change:** values are canonicalised from the raw option read at schema paths (with an `absent` marker), not from normalised settings. Key order and junk keys still don't matter, but future changes to defaults or clamps can no longer cause false drift on every site. |
| SB12-02 salt dependency | **Adopted (docs); Site Health note declined for 1.3.0** | Documented in the settings help and the docs. A Site Health check is extra scope; it could come later. No secret is added to the database. |
| SB12-03 masking on save | **Adopted** | `before_audited_write()` compares the old value first, with drift row and then the WPB-8 row, then refreshes (§6). It costs one extra non-autoloaded read per audited save. The record is not in memory, so the security doc's "no extra query" is not quite reached. |
| SB12-04 sealed record | **Adopted, extended** | `{v, kid, logged, leaves, seal}`; the seal also covers `blog_id` (§2.3, rule 4). |
| SB12-05 residual risk statement | **Adopted** | §16; docs-writer adds the exact sentence; no "tamper-proof" wording; the `wp_bouncer_settings_drift` action allows shipping evidence off the server. |
| SB12-06 marker and decision table | **Adopted, different storage** | Same table (§3, rules 1 to 3). The marker is its own non-autoloaded option `wp_bouncer_fp_since`, read only when the record is missing, not a field in `wp_bouncer_db_version`. Changing that option's format would break `Installer::maybe_upgrade()`'s strict comparison, and no read is added to the normal path. |
| SB12-07 upgrade and fresh install | **Adopted** | Baseline at activation through the save path; lazy baseline on upgrade (the "first admin or cron check" option the doc allows); no `Installer` step; never on `plugins_loaded` (§11). |
| SB12-08 drift silencing its own alert | **Adopted, extended** | Forced, uncapped mail for `alerts.*`, `mode`, `settings`, **and** for the three kinds with unknown keys, to the base recipients, `admin_email` and the network admin (§9). |
| SB12-09 window and throttle | **Adopted; twice-daily cron declined** | Capability `manage_options`; transient set before the compare; no login, REST or AJAX checks (§4). Twice-daily scheduling is left to the owner later, as suggested. |
| SB12-10 bounded rows, atomic claim | **Adopted, different lock primitive** | Hourly gate in the sealed `logged`; nothing is written while the gate is closed (§7). The lock uses `INSERT IGNORE` plus compare-and-swap instead of `add_option()`, whose upsert is not atomic (see `AlertNotifier::claim_reminder_slot()`). The save path does not apply the gate; reason in §6. |
| SB12-11 off the firewall path, fail safe | **Adopted** | §4, §5, §15. `register()` stays read-free; `Throwable` is caught and the class name goes to the debug log; the record option is separate. |
| SB12-12 false positives | **Adopted** | Silent re-baseline only for the plugin's own writes and for schema-only differences under a valid seal; no trust switch (§3, §10). |
| SB12-13 multisite | **Adopted; network sweep declined** | Per-site everything, per-site cron (§13). A sweep would duplicate what each site's cron already does. |
| SB12-14 uninstall | **Adopted** | §14, with integration tests. |
| SB12-15 no personal data | **Adopted, stricter** | Drift rows store no IP, country, user agent, method or URI (§8). |
| SB12-16 not a threat | **Adopted** | `ACTION_ALERT`, rule `settings`; test against the map and widget (§17). |
| SB12-17 check filter | **Adopted** | `wp_bouncer_settings_drift_check( $run, $trigger )`, `admin` and `cron` only; no UI. |
| SB12-18 email on drift | **Adopted** | §9, §10: title and detail as given; existing queue and cap; row always written; `wp_bouncer_settings_changed` with `array()` as old and actor `unknown`. |
| SB12-19 auto re-baseline | **Adopted** | Row first, then record; on row failure the leaves are kept (§5); the "last drift found" Dashboard line (Could) is deferred. |

## 19. Questions for the data-engineer

1. **Record encoding.** A serialized PHP array (`update_option( ..., false )`) or a JSON string? About 5 KB, 64 leaves. Confirm `autoload` comes out `off` on WP 7.0 for both `wp_bouncer_fp` and `wp_bouncer_fp_since`.
2. **Lock primitive.** Extract `claim_reminder_slot()`'s `INSERT IGNORE` and compare-and-swap into a shared `Storage\OptionLock` (claim with TTL, release), or keep a private copy in `FingerprintStore`? Confirm `INSERT IGNORE` translates on the SQLite integration, and that the cache invalidation (`wp_cache_delete` of the option and `notoptions`) is right under Redis or Memcached.
3. **Fresh re-read under the lock** (`load_fresh()`). Is `wp_cache_delete( 'wp_bouncer_fp', 'options' )` followed by `get_option()` enough, or should it be a direct prepared `SELECT` that bypasses the cache, as `claim_reminder_slot()` does?
4. **Throttle.** A transient `wp_bouncer_fp_check` (one or two primary-key reads per manager admin page without an object cache), or an autoloaded option holding the next check time (no query, but a new autoloaded row)? The AC allows "transient or equivalent".
5. **Empty request fields.** Does `BlockLog::record()` accept, and does the schema allow, empty `ip`, `country`, `user_agent`, `method` and `uri` for drift rows? Do the exporter, eraser and Activity Log filters behave with an empty IP?
6. **Uninstall.** Is `delete_transient()` enough for `wp_bouncer_fp_check` on sites without an object cache, or should the name also join the fixed-name regex, for the timeout row left by an interrupted earlier uninstall?
7. **`alloptions` staleness.** Is it acceptable that a direct SQL edit is seen only when the persistent cache expires (§7), or should the check read `wp_bouncer_settings` with a direct query? A direct query would detect edits that are not yet in effect, at the cost of one query.
8. **No schema change.** Please confirm that nothing here needs a table or index, and that `Installer::DB_VERSION` stays `'4'`.

## Data decisions (data-engineer)

Based on reading `Installer`, `uninstall.php`, `AlertNotifier::claim_reminder_slot()`, `SettingsAuditor` and `BlockLog`. Nothing was run or measured for this item. The SQLite and Redis/Memcached points are reasoned from code and need the tests named below.

1. **Options, not a table. Store the record as a JSON string, not a serialized array (small change to §2.3 and `FingerprintStore`).** Three fixed rows per site (`wp_bouncer_fp`, `wp_bouncer_fp_since`, `wp_bouncer_fp_lock`) are the right size: 64 leaves of a 32-hex MAC plus a path of about 30 characters is 4 to 5 KB, `option_value` is `longtext`, and the size never grows, so there are no limits to hit and no growth to plan. A table would add a schema change for no gain.
   - JSON, because this is the one option built to be read after someone tampered with the database. `get_option()` runs `maybe_unserialize()` on every serialized value, so a planted serialized object would be instantiated on each admin check, before the seal is looked at. A JSON string is decoded by `FingerprintRecord::from_stored( string )` with `json_decode( ..., true )` and an array check, and the content is only ASCII hex and key paths. `load()` then returns a string (or false).
   - `load_fresh()` can then compare the stored text with `===`. This replaces the array `!=` in the §5 pseudocode.
2. **Autoload: pass `false` explicitly on every `add_option()` and `update_option()` call, for both `wp_bouncer_fp` and `wp_bouncer_fp_since`. Never omit the argument.** On WP 6.6 and later (so on 7.0) an omitted argument on a new row becomes `'auto'`, and WordPress then autoloads any value under about 150 KB, so a 5 KB record would end up in `alloptions` and be loaded on every request, including the firewall's. `false` is stored as `'off'` (older core: `'no'`). Both are excluded from the autoload set. Make this a test: after a baseline, `SELECT autoload FROM options` is not in `yes/on/auto/auto-on`, and the name is absent from `wp_load_alloptions()`. The lock row is inserted with SQL and the literal `'no'`, which is fine.
3. **Lock: extract a shared `Storage\OptionLock`, and give it an owner token (fixes a gap in the plain copy).** The reminder code stores a timestamp and `release` doesn't exist there. A lock needs it, and a bare `DELETE` on release lets a request whose stale lock was taken over (after 60 s) delete the new owner's lock.
   - Stored value `"<time>:<token>"` with a random token per claim. Claim: `INSERT IGNORE` (1 affected row means won), otherwise a direct `SELECT`, then if older than the TTL a compare-and-swap `UPDATE ... WHERE option_name = %s AND option_value = %s` on the exact old string. Release: `DELETE ... WHERE option_name = %s AND option_value = %s` on our own string.
   - Re-entrancy (the static depth counter in §6) stays in `SettingsDriftMonitor`, not in the lock.
   - Cache: the lock is only ever touched through SQL, so nothing reads it via `get_option()`. Still call `wp_cache_delete( name, 'options' )` and `wp_cache_delete( 'notoptions', 'options' )` after a claim and a release, as `forget_reminder_cache()` does. That is the right pair for Redis and Memcached, because a non-autoloaded option is cached under its own key and a miss is remembered in `notoptions`. `alloptions` is not involved.
   - `claim_reminder_slot()` can move to the shared class in a later cleanup. Do not touch it while the developer is in `src/`.
   - SQLite: the WordPress SQLite integration is expected to translate `INSERT IGNORE` to `INSERT OR IGNORE`, and the existing reminder code already relies on it. I did not verify that the e2e suite exercises it. The tester should add a test that a second claim returns false on SQLite (the §17 "SQLite e2e" row).
4. **`load_fresh()`: use a direct prepared `SELECT option_value FROM %i WHERE option_name = %s` (same shape as `claim_reminder_slot()`), not `wp_cache_delete()` plus `get_option()`.** The delete-then-read pair can still return a stale copy from a replicated cache (Memcached or Redis replicas), and the whole point is to see what a racing request has written. It costs one query, only when drift was found.
   - One matching change in `save()`: call `wp_cache_delete( 'wp_bouncer_fp', 'options' )` first. `update_option()` compares against the cached old value and skips the write when they are equal, so a stale cache entry could turn the re-baseline into a silent no-op.
5. **Throttle: keep the transient `wp_bouncer_fp_check`.** Without an object cache, `get_transient()` is two point reads on the unique `option_name` index per manager admin page, which is far below a millisecond. Set it with `set_transient( name, 1, HOUR_IN_SECONDS )`; core stores it with autoload off and removes an expired pair on the next read. The alternative, an autoloaded "next check" option, adds a row to `alloptions` that every front-end request loads, which is the cost SB12-11 forbids.
6. **Empty request fields: fine, no schema change.** The `bouncer_log` columns are `NOT NULL DEFAULT ''`, and `BlockLog::normalize()` maps any missing field to `''` (the `uri` redaction handles an empty string). Rows with an empty IP already exist, for example from cron. The privacy exporter and eraser work on the traffic table and match a requested identifier, which an empty IP never equals, and the Activity Log `ip` filter ignores an empty value (`! empty()` in `BlockLog::where()`). Not verified: how `LogListTable` and the CSV export render an empty IP and country. The tester should open one drift row in both.
   - **Gap in the current code**: `SettingsAuditor::record_row()` has no `$request_details` argument yet. It always writes the request's IP, country, method, URI and user agent, and it calls `geo()->lookup()`. The developer must add the argument and skip `current_request()` and the geo lookup when it is false (an extra lookup per drift row would also be pointless).
7. **Uninstall: also add `fp_check` to the fixed-name regex (§14 says "can"; make it "does").** `delete_transient()` is enough when the transient is a real database row, but with a persistent object cache it only clears the cache, and a timeout row left by an interrupted earlier run (or written while no cache was active) stays. Add `fp_check` to the `wp_bouncer_(?:export_...|erase_range_\d+)` group, so the alternation becomes `export_[0-9a-f]{32}|erase_range_\d+|fp_check`. The loose `LIKE '_transient_%wp_bouncer_%'` already finds it.
   - Multisite: confirmed. `wp_bouncer_uninstall_site()` runs per site inside `switch_to_blog()` through `Installer::for_each_site()`, and `delete_option()`, `delete_transient()` and `$wpdb->options` follow the switched blog. So the three options and the transient are removed on each site with no extra code. They are all per-site; nothing is network-level and no `delete_site_option()` is needed.
   - `uninstall.php` has no "keep data" setting today, so nothing to respect.
   - Add `wp_bouncer_fp`, `wp_bouncer_fp_since` and `wp_bouncer_fp_lock` next to the `wpb_map_*` deletions.
8. **`alloptions` staleness: accept it, and do not read the settings with a direct query.** The record describes the settings as WordPress sees them. If the check read the database directly, it would re-baseline to a value that the firewall is not using yet. When the cache entry later expires or is rebuilt, or a save runs, `old_raw` (from the cached copy) would no longer match the record, and a false drift row would appear. Reading through `get_option()` everywhere keeps the record, the firewall and the save path on the same view. A persistent object cache delays detection until the edit takes effect, which §7 already documents.
9. **No schema change. `Installer::DB_VERSION` stays `'4'`.** No table, index or `dbDelta` change is needed: the log table already allows the empty fields, and drift rows are `alert` rows, which the `action_created` key (from the WPB-11 data decisions) already serves. No upgrade step is needed, because the baseline is lazy and idempotent (rule 1 of §3). The existing `maybe_upgrade()` and `RedactionMigration` paths are untouched, so the version bump problem noted for WPB-11 does not apply here.

**Changes to the design:** (a) JSON string for the record, with string comparison in `load_fresh()` (item 1); (b) an owner token in the lock value and a compare-and-delete release, in the shared `Storage\OptionLock` (item 3); (c) `save()` clears the option cache entry before `update_option()` (item 4); (d) `fp_check` goes into the uninstall regex (item 7); (e) `record_row()` must really drop request details and the geo lookup (item 6). Everything else in §2, §5, §7, §13 and §14 is confirmed.
