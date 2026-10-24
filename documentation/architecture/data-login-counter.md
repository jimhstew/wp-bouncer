# Data design: atomic login counter and the 1.2.0 redaction migration (S10)

Owner: data-engineer. Covers RT-08, RT-07 (subjects), schema version 3.

## Storage choice

| Data | Store | Why |
|---|---|---|
| Login attempt counter (one per subject, a window of minutes) | Persistent object cache (`ObjectCacheCounter`) when `wp_using_ext_object_cache()`, otherwise the custom table `{prefix}bouncer_counters` (`TableCounter`) | The count must be atomic across parallel requests. `wp_cache_incr` is atomic on Redis and Memcached. Transients and options are read-modify-write. A table gives a row lock (InnoDB) or database lock (SQLite). |
| Lockouts | Transients (unchanged) | Written once per lockout; no race that matters. |
| Rate-limit, 404 and probe counters | Transients (unchanged) | High volume, approximate counts are fine for throttling. |
| Migration cursors | Option `wp_bouncer_migration_3`, autoload off | Tiny; deleted when the migration ends. |

## Schema (DB_VERSION 3)

`{prefix}bouncer_counters`: `counter_key char(32)` primary key (md5 of the logical key), `hits int`, `expires_at bigint` (Unix time), `KEY expires_at`.
The column is `hits`, not `value`, to stay clear of reserved words in the SQLite translator.
Per site on multisite (`$wpdb->prefix`). Created by `dbDelta()` in `Installer::create_tables()`, which runs on activation and on upgrade (`maybe_upgrade()` compares the stored version). Dropped by `uninstall.php`.

## Statements (all prepared; MySQL, MariaDB, SQLite)

1. `INSERT IGNORE INTO %i (counter_key, hits, expires_at) VALUES (%s, 0, %d)`
2. `UPDATE %i SET hits = 0, expires_at = %d WHERE counter_key = %s AND expires_at <= %d` (new window; moving `expires_at` forward means two racing resets cannot both match)
3. `UPDATE %i SET hits = hits + 1 WHERE counter_key = %s` (atomic per row)
4. `SELECT hits FROM %i WHERE counter_key = %s`

No `ON DUPLICATE KEY UPDATE`, no `LIMIT` on writes. Purge: `DELETE ... WHERE expires_at < %d` in the daily cron (the table holds only active subjects).
Cost: four primary-key statements per login attempt that has a username and password. Login is not the hot path (the firewall does not touch this table).

Growth: one row per subject with an attempt in the last window, so bounded by distinct attackers per window (about 100 bytes a row), emptied daily. A flood from many /64s grows it at the request rate until the purge; the log budget (S6) does not apply here, so the purge could be made hourly if a site sees millions of distinct sources a day.

## Migration to version 3 (`Storage\RedactionMigration`)

Redacts rows written by earlier versions (the 1.1.3 work was never released on its own): `uri` in `bouncer_log`, `uri` and `referrer` in `bouncer_traffic` (through `UrlRedactor::redact()`), and usernames of non-existent accounts in lockout reasons (`(last username "x")` becomes `(last: unknown username)`; an existing account keeps its name; the banned-username reason is an admin-chosen word and is left).

- Batches of 500 rows by primary key: `WHERE id > last ORDER BY id LIMIT 500` is an index range, so cost does not grow with position. The reasons job uses the `rule` index plus `LIKE`.
- Only changed rows are updated, one `UPDATE ... WHERE id = %d` each, so a second run changes nothing (idempotent) and rows written while it runs (already redacted) are harmless.
- Resumable: cursors are saved after every batch. Time-boxed: 1.5 s in the upgrade request, then a one-minute cron event (`wp_bouncer_migrate_data`) continues with 20 s slices until done. A short option lock keeps overlapping runs from duplicating work (abandoned after 120 s).
- Measured on MySQL 8.4 (local, InnoDB): about 0.6 s per 100k rows scanned with nothing to change; about 6.5 s per 100k rows that need an `UPDATE`.

Rollback: none needed. The old plugin ignores the table and the redacted values are valid text.

## Uninstall

`uninstall.php` drops `bouncer_counters`, deletes the migration option and lock, and clears `wp_bouncer_migrate_data`. Deactivation clears the migration cron event.
