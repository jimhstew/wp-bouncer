# WPB-11: Threat hotspot map by country on the Activity Log (design)

Status: design, 2026-10-26. Spec: `documentation/backlog.md` → WPB-11 (AC 1–18 plus the 2026-10-26 owner decision: the map follows the date range, country and action filters, **ignores free-text search and the single-IP filter**, and says so next to the map). Security: `documentation/security/wpb-11-threat-map.md` (SB11-01..21, decisions in §10). Release 1.3.0.

Everything is admin-only and read-only. Nothing is added to the firewall path (`plugins_loaded` priority 1) or to front-end requests. There are no AJAX/REST routes, no admin-post handlers and no nonces. The page computes the data server-side and renders it. The data-engineer owns the index question (§11).

## 1. Files

| File | Change |
|---|---|
| `src/Log/DateRange.php` (new, pure) | Parses `log_from` / `log_to` strictly and gives the effective window (§3) |
| `src/ThreatMap/ThreatQuery.php` (new, pure) | Normalised, validated filter set for the map, `runnable()`, `cache_key()` (§4) |
| `src/ThreatMap/CountryTally.php` (new, pure) | Merges and validates raw `country => count` rows, splitting them into known countries and unknown (§5) |
| `src/ThreatMap/HeatScale.php` (new, pure) | Log-scale bucket 0–7 and dot radius (§5) |
| `src/ThreatMap/MapModel.php` (new, pure) | Builds dots (x, y, r, bucket), "not on the map" rows, min/max and totals from a tally and `Centroids` (§5) |
| `src/ThreatMap/CachePolicy.php` (new, pure) | Fresh/stale/build/busy decision and TTL (§6) |
| `src/ThreatMap/KeyIndex.php` (new, pure) | Maintains the 20-key index array and the generation counter (§6) |
| `src/ThreatMap/Centroids.php` (**generated**, pure) | `WIDTH`, `HEIGHT`, `SOURCE`, `POINTS` (ISO alpha-2 => `[x, y]` in viewBox units), `point()`, `codes()`, `UNPLACED` (§8) |
| `src/Log/ThreatMapSource.php` (new interface) | `threats_by_country( array $filters, string $since, string $until ): ?array`. `BlockLog` implements it; `tests/Support/FakeThreatSource.php` is the double |
| `src/Log/BlockLog.php` | `THREAT_ACTIONS` const, `until` in `where()`, `threats_by_country()` (§4) |
| `src/Admin/ThreatMapPanel.php` (new adapter) | Capability check, transients, lock, throttle, flush hooks, `render()` (§6, §7) |
| `src/Admin/views/partials/threat-map.php` (new) | Panel markup (§7) |
| `src/Admin/views/log.php` | Render the panel above the log form; show the date-range notice |
| `src/Admin/AdminController.php` | `log_date_range()`, date keys in `log_filters_from_request()` / `log_filters_to_args()`, enqueue on `tab=log` (§3, §9) |
| `src/Admin/LogListTable.php` | From/To date inputs and a hidden `country` input in `extra_tablenav( 'top' )` (§3) |
| `src/Plugin.php` | `( new ThreatMapPanel( $this ) )->register()` in the existing `is_admin() \|\| wp_doing_cron()` block, next to `DashboardWidget` |
| `wp-bouncer/assets/map/world.svg` (**generated**) | Base map, about 60–85 KB (§8) |
| `wp-bouncer/assets/threat-map.js`, `threat-map.css` (new) | Panel behaviour and styles (§9). The JS is ≤ 6 KB, the CSS ≤ 4 KB |
| `scripts/build-world-map.php`, `scripts/map/SvgAllowlist.php`, `scripts/map/centroid-supplement.json` (new, not shipped) | Generator, allowlist checker and hand-curated centroids for codes missing from Natural Earth admin-0 (§8) |
| `wp-bouncer/uninstall.php` | Delete `wpb_map_keys` and extend the transient regex (§6) |
| `Makefile` | `make map` target; zip check for `.svg` files and size (§8) |
| tests | §12 |

## 2. Layers

- **Domain (pure, unit-tested, no WordPress calls):** `DateRange`, `ThreatQuery`, `CountryTally`, `HeatScale`, `MapModel`, `CachePolicy`, `KeyIndex`, `Centroids`. They use `Geo\Countries` (already pure) and `BlockLog::THREAT_ACTIONS` (a constant, so reading it needs no `$wpdb`).
- **Data access:** `BlockLog::threats_by_country()` behind `Log\ThreatMapSource`.
- **Presentation adapter:** `Admin\ThreatMapPanel` (transients, options, `current_user_can`, `_n()`, `number_format_i18n()`, view). `AdminController` parses requests and enqueues assets.
- **Assets:** a static base map loaded as an image, dots in an inline SVG rendered by PHP, and progressive-enhancement JS. Without JS the panel is open, every dot is drawn, the whole table is listed, and only the tooltip, the toggle and "show all" are missing.

## 3. Date range: new request parameters (SB11-05)

The Activity Log has no date filter today, and AC 7 needs one. WPB-11 adds it, **to the table as well**, so the map and the table can't disagree.

- **Parameters:** `log_from`, `log_to` (the `log_` prefix matches `log_action` and `log_ip`). Format: strict `Y-m-d`, **inclusive days in the site's time zone** (`wp_timezone()`), because the table shows local times.
- **Parsing (`DateRange::parse( string $from, string $to, \DateTimeZone $tz, int $now ): DateRange`):** match `^\d{4}-\d{2}-\d{2}$`, then `checkdate()`, with the year limited to 2000–2100. The date is built with `(new DateTimeImmutable('now', $tz))->setDate(y, m, d)->setTime(0, 0)`. A request string is never passed to `strtotime()` or the `DateTime` constructor. The adapter reads the values with `sanitize_text_field( wp_unslash() )` and passes `''` when they are missing.
- **Rules, in order:**
  1. A value that doesn't parse is ignored (note `invalid`).
  2. `to` is later than today: clamp it to today.
  3. Only `to` given: `from = to − 29 days`. Only `from` given: `to = today`.
  4. `from > to`: both are ignored (note `reversed`).
  5. More than 365 days: `from = to − 364` (note `capped`).
  6. Neither given: no explicit range. The map uses `today − 29 … today` (30 days); the table stays unfiltered by date, as in 1.2.x.
- **Value object (readonly):** `?string $from`, `?string $to` (the accepted values, used to refill the inputs), `string $start`, `string $end` (the effective local `Y-m-d`), `string $since_utc` (local `start` 00:00 converted to UTC `Y-m-d H:i:s`), `string $until_utc` (local `end + 1 day` 00:00 in UTC, exclusive), `bool $explicit`, `string $note` (`''|invalid|reversed|capped`), and `days(): int`. The conversion goes through `DateTimeImmutable` with the zone, so DST days are handled.
- **Table:** `AdminController::log_date_range()` parses once per request (a static memo). If `$range->explicit` is true, `log_filters_from_request()` adds `since`, `until`, `from` and `to`. `BlockLog::where()` gains `until` → `created_at < %s` (`since` already exists). `log_filters_to_args()` maps `from`/`to` back to `log_from`/`log_to`, so pagination, sorting and **CSV export** follow the range.
- **UI (`extra_tablenav('top')`):** two `<input type="date" name="log_from|log_to" max="<today local>">` with visible short labels "From" and "To", before the Filter button. Add `<input type="hidden" name="country">` when a country filter is active, because the table toolbar has no country select and the form would otherwise drop it. A `note` is shown once above the panel as `notice notice-warning inline`, for example "The end date is before the start date, so the date filter was ignored." It is escaped and gives no echo of the raw input.

## 4. Query, threat definition and filters (SB11-01, -02, -15)

- **Threat actions:** `BlockLog::THREAT_ACTIONS = array( self::ACTION_BLOCKED, self::ACTION_LOCKOUT )`. `monitored` (monitor-only), `alert`, `login` and `suppressed` are not threats. `suppressed` is a per-minute summary row with no IP and no country. Any action added later is excluded until someone adds it here on purpose. Help text: "Counts blocked requests and lockouts. Monitor-only matches, alerts and admin logins are not counted."
- **`ThreatQuery::from_filters( array $log_filters, DateRange $range ): ThreatQuery`** keeps only `rule`, `action` and `country`. `search` and `ip` are dropped (owner decision 2026-10-26). Validation:
  - `action`: `''` or one of `THREAT_ACTIONS`, else `runnable() === false`, `reason() === 'action'`. No query runs.
  - `country`: `strtoupper`, then `^[A-Z]{2}$` and `Countries::is_valid()`, else not runnable (`reason 'country'`).
  - `rule`: `^[a-z0-9_-]{1,32}$` (the column length), else not runnable. Ids are **not** limited to `log_rule_labels()`, because third-party rules added through `wp_bouncer_rules` log under their own ids, and the table filters on them.
- **`cache_key( int $generation ): string`** = `'wpb_map_' . substr( hash( 'sha256', json_encode( $payload ) ), 0, 20 )`. The payload is the fixed-order array `[ 'v' => 1, 'g' => $generation, 'rule', 'action', 'country', 'since' => since_utc, 'until' => until_utc ]` with `''` for unset values. The name is 28 characters and request text never appears in it.
- **`BlockLog::threats_by_country( array $filters, string $since, string $until ): ?array`:**
  ```php
  $filters = array_intersect_key( $filters, array_flip( array( 'rule', 'action', 'country' ) ) ) + array( 'since' => $since, 'until' => $until );
  list( $where, $args ) = $this->where( $filters );
  $in  = implode( ', ', array_fill( 0, count( self::THREAT_ACTIONS ), '%s' ) );
  $sql = "SELECT country AS k, COUNT(*) AS n FROM {$this->table} WHERE {$where} AND action IN ({$in}) GROUP BY country ORDER BY n DESC LIMIT 300";
  $rows = $this->db->get_results( $this->db->prepare( $sql, array_merge( $args, self::THREAT_ACTIONS ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL -- table from $wpdb->prefix, $where from where() (fixed fragments, %s placeholders), $in is %s placeholders, LIMIT is a literal; every value is bound.
  if ( '' !== $this->db->last_error ) { return null; }
  ```
  The method returns `array<string,int>` (raw stored value => count) and casts counts with `(int)`. `ORDER BY n DESC` makes the 300 cap keep the largest groups: junk values (spoofed headers) could in theory exceed 300 groups, and anything past the cap is lost from the "unknown" count, which is acceptable. `search` and `ip` are never passed in, so the `LIKE` scan is never part of the map. The SQL is valid on MySQL, MariaDB and SQLite: no `FIELD()`, `COLLATE` or `ONLY_FULL_GROUP_BY` issue.
- **Case:** MySQL and MariaDB collations group `us` with `US`; SQLite does not. `CountryTally` merges the values in PHP.

## 5. Pure aggregation and scale

- **`CountryTally::from_rows( array $raw ): CountryTally`:** for each `value => n`, `strtoupper(trim)`. If the result matches `^[A-Z]{2}$` and `Countries::is_valid()`, it is added to `countries[code]`; otherwise to `unknown` (SB11-07: never dropped, never emitted). `countries()` is sorted by count descending, then by code ascending. It also has `unknown(): int`, `total(): int`, and `to_array()` / `from_array()` for the cache. `from_array()` re-validates, so a tampered transient can't inject values.
- **`HeatScale`:** `STEPS = 8`. `bucket( int $count, int $min, int $max ): int`. If `$max <= $min` it returns 7. Otherwise `t = (ln c − ln min) / (ln max − ln min)` and the bucket is `min( 7, (int) floor( t * 8 ) )`. `radius( int $bucket ): float` = `5.0 + 0.75 * bucket` (viewBox units), so size is a second, non-colour cue.
- **`MapModel::build( CountryTally $t ): array`** returns:
  - `dots`: a list of `{code, count, x, y, r, bucket}` for countries with `Centroids::point()`, in the tally's order (descending count).
  - `unplaced`: `code => count` for valid codes without a point: `Countries::SPECIAL` (T1, EU, AP) and `Centroids::UNPLACED` (AQ).
  - `min` / `max` over the **dots**, plus `unknown`, `total` and `plotted_total`.

  Descending order is both the focus order (AC 4) and the paint order. Big dots are drawn first and small neighbours on top, so a small dot is never hidden under a big one (AC 2). The keyboard still reaches every dot (§9).

## 6. Cache (SB11-03, -04, -05, -06, -21)

- **Transients (per site, never `*_site_transient`):**
  - `wpb_map_<20 hex>`: box `{ v: 1, built: int, fresh_until: int, tally: array }`, stored with a `DAY_IN_SECONDS` expiry, so a stale copy is available while another request rebuilds.
  - `wpb_map_lock`: 30 s, **site-wide**, so only one map aggregate runs at a time.
  - `wpb_map_thr_<user_id>`: 5 s per-user throttle on cache misses.
- **Option `wpb_map_gen`** (autoload `false`): the generation counter. Only `flush()` writes it; `load()` only reads it (WPB11-RT-04). **Option `wpb_map_keys`** (autoload `false`): `{ keys: { name => built } }`. `KeyIndex::normalise( mixed ): array` accepts only names matching `^wpb_map_[0-9a-f]{20}$`. `KeyIndex::remember( array $index, string $name, int $now, int $cap = 20 ): array{index, evicted}` evicts the oldest entries, and the adapter deletes their transients. The generation counter is part of every key, so `flush()` makes even an orphan from a lost-update race unreachable.
- **`CachePolicy::decide( ?array $box, int $now, bool $locked, bool $throttled ): string`:**

  | Box | Lock or throttle | Result |
  |---|---|---|
  | fresh (`now < fresh_until`) | any | `fresh`: serve |
  | stale | lock **or** throttle held | `stale`: serve, with "Updated N minutes ago" |
  | stale | neither | `build`; on a query error serve the stale box |
  | none | throttle held | `busy`: "The map is being updated. Reload the page in a few seconds." The table still works |
  | none | not throttled | `build`, even if another user holds the lock (the widget's rule: a slow page beats an empty one) |

- **Build:** take the lock (30 s; the `wpb_map_lock` option, taken with `INSERT IGNORE`, taken over when stale with a compare-and-swap, and released only by its owner's token; with an external object cache, `wp_cache_add()`; WPB11-RT-02/03), then set this user's throttle (5 s), then call `threats_by_country()`. `null` means a database error: delete the lock, cache nothing, show the `error` state (a generic message, never `last_error`; SB11-18). Otherwise run `CountryTally::from_rows()` and compute `ttl = CachePolicy::ttl( (int) apply_filters( 'wp_bouncer_map_cache_ttl', 300 ), $tally->total() )`. The TTL is clamped to 60–3600, and is **3600 when `total > DashboardWidget::FLOOD_ROWS`**. Then `set_transient( name, box, DAY )`, re-read the generation and, if a flush moved it, delete the new box and skip the index write (WPB11-RT-01); otherwise `update_option( 'wpb_map_keys', …, false )`. Release the lock in a `finally` block.
- **`ThreatMapPanel::flush()`** bumps `wpb_map_gen`, deletes every listed transient, then resets `wpb_map_keys` to `{ keys: {} }`. It does not touch the lock. It is hooked like the widget: `wp_bouncer_log_cleared`, `wp_bouncer_settings_changed`, and `Installer::CRON_HOOK` at priority 20. Any future code that deletes log rows calls `DashboardWidget::flush()` and `ThreatMapPanel::flush()`.
- **Bounds:** at most 20 map boxes, one lock and one throttle per recently active admin. A `search` or `ip` value changes nothing.
- **Uninstall:** `delete_option( 'wpb_map_keys' )` and extend `$wpb_exact` with `map_(?:[0-9a-f]{20}|lock|thr_\d+)` inside the `wpb_(?:…)` group. This runs per site on multisite, through the existing `for_each_site`.
- **Deviation recorded:** AC 9 says "one transient". Because the map follows filters, it is a capped group (≤ 20 boxes, plus the lock and throttle). The product-manager should update AC 9's wording.

## 7. Panel and states (`ThreatMapPanel::render( array $log_filters, DateRange $range ): void`)

The panel returns immediately if `is_network_admin()` is true or `! current_user_can( AdminController::CAPABILITY )` (defence in depth: `render()` already `wp_die`s). It is called from `views/log.php` above `<form class="wpb-log-form">`, after the date notice.

**States, chosen by a pure `MapModel::state()`:**

| State | When | Output |
|---|---|---|
| `filtered_out` | `ThreatQuery` is not runnable | "The map counts blocked requests and lockouts only, so nothing matches the action filter ‘%s’." or "No threats match this filter." No query runs |
| `busy` / `error` | §6 | Message only |
| `no_geo` | the geo database is not loaded (`$plugin->geo_database_loaded()`) **and** no known-country threats in the window | Notice: "Country data needs the geolocation database." with a link to `AdminController::url( 'tools' )`, plus the "Unknown location" line. No map |
| `empty` | `total === 0` | "No threats recorded in this period yet." No map |
| `ok` | otherwise | Map, legend and table. If there is no geo database but countries exist (from a CDN country header), add the line: "No geolocation database is installed, so new entries only get a country if your proxy sends a country header." |

The `no_geo` rule reads AC 8 narrowly: sites that get countries from a CDN header still see their map. This is noted in the summary for the owner.

**Markup** (`views/partials/threat-map.php`; every value is escaped, counts use `number_format_i18n()`, and strings use the `wp-bouncer` domain):

```html
<section class="wpb-map" aria-labelledby="wpb-map-h">
  <div class="wpb-map-head"><h2 id="wpb-map-h">Threats by country</h2>
    <button type="button" class="button-link wpb-map-toggle" aria-expanded="true" aria-controls="wpb-map-body" hidden>Hide map</button></div>
  <div id="wpb-map-body" class="wpb-map-body">
    <p class="wpb-map-window">Last 30 days (27 Sep 2026 – 26 Oct 2026). Ignores the search box and the IP filter.</p>   <!-- date_i18n( get_option('date_format') ); "Last 30 days" only when !explicit; plus "Country: Germany (DE) · Clear" link when a country filter is active -->
    <div class="wpb-map-grid">
      <figure class="wpb-map-figure">
        <div class="wpb-map-canvas">
          <img class="wpb-map-base" src="…/assets/map/world.svg?ver=VERSION" alt="" width="1000" height="H" decoding="async">
          <svg class="wpb-map-dots" viewBox="0 0 1000 H" role="group" aria-labelledby="wpb-map-h" aria-describedby="wpb-map-desc">
            <circle class="wpb-heat-7" cx="…" cy="…" r="10.3" tabindex="0" role="img"
              aria-label="United States (US): 1,234 threats" data-cc="US" data-title="United States (US)" data-count="1,234 threats"/>
            <circle class="wpb-heat-3" … tabindex="-1" …/>   <!-- roving tabindex rendered server-side: first dot 0, the rest -1 -->
          </svg>
          <div class="wpb-map-tip" role="tooltip" hidden></div>
        </div>
        <figcaption id="wpb-map-desc">Each dot is a country that threats came from. Brighter red and larger dots mean more threats. The table lists the same numbers.</figcaption>
        <div class="wpb-map-legend"><span>Logarithmic scale:</span> <span>3</span><span class="wpb-map-swatches" aria-hidden="true"><i class="wpb-heat-0"></i>…<i class="wpb-heat-7"></i></span><span>1,234</span></div>
        <p class="wpb-map-unknown">Unknown location: 12 threats</p>
      </figure>
      <div class="wpb-map-top">
        <table class="widefat striped"><caption>Top countries</caption>
          <thead><tr><th scope="col">Country</th><th scope="col">Code</th><th scope="col">Threats</th></tr></thead>
          <tbody><tr><td><span aria-hidden="true">🇺🇸</span> <a href="…&country=US">United States</a></td><td>US</td><td>1,234</td></tr>
            <tr class="wpb-map-extra">…</tr>   <!-- rows 11+; JS hides them -->
            <tr><td>Tor network … <span class="wpb-map-off">(not on the map)</span></td>…</tr></tbody></table>
        <button type="button" class="button wpb-map-more" aria-expanded="false" hidden>Show all 34 countries</button>
      </div>
    </div>
    <p class="description">Country comes from the visitor's IP address (geolocation database or a trusted proxy header). It can be wrong, and behind an untrusted proxy it can be forged. Use the map as a hint before blocking a country, not as proof.</p>
  </div>
</section>
```

- **Strings:** `aria-label` is `sprintf( _n( '%1$s (%2$s): %3$s threat', '%1$s (%2$s): %3$s threats', $n ), … )`. `data-title` is `sprintf( __( '%1$s (%2$s)' ), name, code )` and `data-count` is `sprintf( _n( '%s threat', '%s threats', $n ), … )`. Plurals are therefore resolved in PHP, and JS only copies strings. Names come from `Countries::name()` (AC 16).
- **Legend:** when `min === max` it shows a single `wpb-heat-7` swatch and one label. The swatches run in the inline direction, so in RTL the lowest count sits at inline-start, on the right (AC 13).
- **Links:** each table row's country link keeps the current filters (`log_filters_to_args()`) and sets `country`, which also filters the table. Dots are **not** links: a tap shows the tooltip (AC 4).
- **Payload:** the only per-country data in the markup is the code, name and counts. There is no JSON data island (§10, SB11-09).

## 8. Asset pipeline (SB11-11, -12, -20)

- **Tool:** PHP CLI. The repo has no `package.json` and Node is only used for `node --test`; PHP 8.3 is always present. Script: `scripts/build-world-map.php` with no dependencies beyond `ext-json` and `ext-dom`. It defines `ABSPATH` as a stub and requires `wp-bouncer/src/Geo/Countries.php` for the code list.
- **Inputs (fetched by a developer, never at build or run time, never shipped):** Natural Earth vector, a pinned GitHub tag of `nvkelso/natural-earth-vector`. `v5.1.2` is the latest known at design time; the developer confirms the newest tag and records it. Files:
  - `geojson/ne_110m_admin_0_countries.geojson` for the outlines.
  - `geojson/ne_50m_admin_0_countries.geojson` for centroids. Its `LABEL_X`/`LABEL_Y` label points sit inside the main landmass, which is better than a geometric centroid for the US, France or Norway, and it covers about 240 units including small states that 110m drops.

  The script has constants `NE_TAG` and `INPUT_SHA256 = [ file => hash ]`, and refuses inputs whose SHA-256 differs. Usage: `php scripts/build-world-map.php --in <dir>` (the download goes in its own empty directory). The `curl` lines are in `documentation/geolocation.md`.
- **ISO codes:** read `ISO_A2_EH`, falling back to `ISO_A2`, then a small `CODE_OVERRIDES` map in the script (Natural Earth uses `-99` for some states). Codes that are not in `Countries` are skipped and reported. `scripts/map/centroid-supplement.json` supplies `[lon, lat]` and a per-entry source for codes in `Countries::LIST` that Natural Earth admin-0 lacks (for example French overseas departments such as GF, GP, MQ, RE and YT). The coordinates come from Natural Earth map units or the CIA World Factbook (public domain).
- **Projection:** Equal Earth (closed-form, equal-area, so no region looks inflated), with central meridian 0. Antarctica is left out of the outlines and `AQ` goes in `Centroids::UNPLACED`. `x` is scaled to 0–1000; `HEIGHT` is computed from the extents (about 415), with 4 units of padding.
- **Simplification:** Douglas–Peucker at 0.35 units per ring. Rings whose bounding box is under 1 × 1 unit are dropped. Coordinates are rounded to 1 decimal with `sprintf('%.1F')` and written as relative `l` commands. There is one `<path d>` per country, in ISO-code order, so the output is byte-for-byte deterministic. The file must be ≤ **85 KB**, and `world.svg` + `Centroids.php` together ≤ **100 KB** (owner ceiling).
- **SVG shape:** `<svg xmlns viewBox width height aria-hidden="true" focusable="false"><g fill="#dcdcde" stroke="#ffffff" stroke-width="0.5" stroke-linejoin="round"><path d="…"/>…</g></svg>`. It has no comments, metadata, `style`, `id`, `class` or `href`.
- **Allowlist (`scripts/map/SvgAllowlist.php`, `check( string $svg ): string[]`):**
  - Parser: `DOMDocument::loadXML( $svg, LIBXML_NONET )`, with no `LIBXML_NOENT` and no DTD loading. A doctype fails the check.
  - Nodes: element nodes and whitespace-only text only. No comments or processing instructions.
  - Elements: `svg`, `g`, `path`.
  - Attributes: `svg{xmlns, viewBox, width, height, aria-hidden, focusable}`, `g{fill, stroke, stroke-width, stroke-linejoin}`, `path{d}`.
  - Values: colours `^#[0-9a-f]{6}$`; `d` `^[MmLlHhVvZz0-9 .,\-]+$`; numbers `^[0-9.]+$`. Any `on*`, `href`, `style` or `data:` fails.

  The generator runs the check before writing. A PHPUnit test runs it on the committed file in `make test` (and so in `make check` and CI).
- **Generated output is committed** (`assets/map/world.svg`, `src/ThreatMap/Centroids.php`), so `make build` needs no network or Natural Earth files. `Centroids.php` is written in WPCS form: tabs, one `'XX' => array( x, y ),` per line, and a docblock naming the source, tag and input hashes. It passes `make lint`. A unit test pins the SHA-256 of both files, so any change is visible in review.
- **Makefile:** `make map IN=<dir>` runs the generator. After zipping, `build` fails if the zip contains any `.svg` other than `wp-bouncer/assets/map/world.svg`, or if that file is over 100 KB (devops).
- **Base map as `<img>`, dots inline (SB11-12 variant):** the base is drawn with `<img alt="">` from the plugin's own URL. Browsers run no scripts and load no subresources in SVG-as-image, the file is cached across page views instead of adding about 80 KB to every log page, and it stays out of the accessibility tree. The dots are a PHP-built inline `<svg>` overlay with the same viewBox, so they can be focused and styled. The allowlist still matters, because opening `world.svg` directly in a tab would run any script in the plugin's origin. If `world.svg` isn't readable (`is_readable`, checked once and stored in a static), the panel shows the table only.
- **Licence and credits:** Natural Earth is public domain (no attribution required). Credit it anyway in `readme.txt` (Credits), and add a "Threat map data" section to `documentation/geolocation.md` with the tag, input SHA-256s, output SHA-256s, the command, the projection and tolerance, the supplement sources, the measured zip size change, the threat-action list, the cache design and the statement that there is no runtime network call (docs-writer, AC 11 and 18). Note the borders: Natural Earth shows de facto boundaries; the map draws outlines only, with no labels.

## 9. Enqueue, JS and CSS

**Enqueue** (`enqueue_assets()`, after the existing hook check, reusing the `$tab` computed for `ColumnResize`):
```php
if ( 'log' === $tab ) {
	wp_enqueue_style( 'wp-bouncer-map', $url . 'assets/threat-map.css', array( 'wp-bouncer-admin' ), Plugin::VERSION );
	wp_enqueue_script( 'wp-bouncer-map', $url . 'assets/threat-map.js', array(), Plugin::VERSION, array( 'in_footer' => true, 'strategy' => 'defer' ) );
	wp_localize_script( 'wp-bouncer-map', 'wpBouncerMap', array( 'i18n' => array( 'hide' => __( 'Hide map', 'wp-bouncer' ), 'show' => __( 'Show map', 'wp-bouncer' ), 'fewer' => __( 'Show top 10 only', 'wp-bouncer' ) ) ) );
}
```
There is no nonce, `geoNonce` is not passed, `admin.js` is untouched, and there is no jQuery.

**`threat-map.js`:** a vanilla ES5-style IIFE like `columns.js`, with a `core` export for Node tests.
```
(function () {
  var core = { state(raw)→'1'|'0'|null, move(i, key, len, dir)→int|null, place(dot, tip, box)→{left, top} };
  if (typeof module === 'object' && module.exports) { module.exports = core; return; }
  … DOM wiring …
})();
```
- **Boot:** find `.wpb-map`; bail if it is missing. Reveal the `[hidden]` toggle and "more" buttons.
- **Panel state (SB11-13):** key `wpb_map:open`. `getItem` is wrapped in try/catch, and `state()` accepts only `"1"` or `"0"`; anything else is removed and the default (open) applies. On `"0"`, set `body.hidden = true`, `aria-expanded="false"` and the label `i18n.show`. Clicking toggles and calls `setItem` in try/catch. There is no `clear()`. Known tradeoff: a user who closed the panel sees it open for a moment before the deferred script closes it.
- **Roving focus:** one delegated `keydown` on the dots `<svg>`. `move()`: ArrowDown and ArrowRight go to the next dot (lower count), ArrowUp and ArrowLeft go back, and Left/Right are multiplied by `dir` (−1 in RTL, as in `columns.js`). Home and End go to the first and last dot, and the result is clamped (no wrap). The newly focused dot gets `tabindex=0` and the rest `-1`; `focus()` follows.
- **Tooltip:**
  - Show on delegated `pointerover` and `focusin` on a `circle[data-cc]`. Untrusted events are ignored.
  - Content: two `<span>`s, made once with `createElement` and filled with `textContent` from `dataset.title` and `dataset.count`.
  - Position: `place()` clamps the tip inside the canvas box. It prefers above the dot and flips below near the top. `left`/`top` are physical pixels on purpose, because the map is not mirrored.
  - Hide on `pointerout` (after a 300 ms timer, cancelled if the pointer enters the tip; WCAG 1.4.13 hoverable), on `focusout`, and on `Escape`. A document `keydown` listener is added only while the tip is visible and removed on hide (WCAG 1.4.13 dismissible).
  - Touch: `pointerdown` with `pointerType === 'touch'` on a dot shows the tip for it; a tap elsewhere in the panel hides it.
- **Show all:** if `tr.wpb-map-extra` rows exist, set them `hidden`. The button toggles them and `aria-expanded`, and switches between its server-rendered text (kept in `data-more`, read from the markup) and `i18n.fewer`. Focus stays on the button.
- **Forbidden:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `cssText`, `fetch`, `XMLHttpRequest`, `sendBeacon`, `localStorage.clear` and `jQuery`. Colour and size come from server-side classes and attributes; JS never computes them from data (SB11-08).

**`threat-map.css`** uses logical properties throughout:
- **Layout:** `.wpb-map-body{container-type:inline-size}`. `.wpb-map-grid{display:grid;grid-template-columns:minmax(0,auto) minmax(16rem,1fr);gap:1rem}`, and `@container (max-width: 900px)` plus `@media (max-width:782px)` switch to one column (AC 12).
- **Canvas:** `.wpb-map-canvas{position:relative;display:inline-block;max-inline-size:100%;background:#f0f6fc}`. `.wpb-map-base{display:block;inline-size:auto;block-size:auto;max-inline-size:min(100%,720px);max-block-size:45vh}` keeps the table's filters in view on first load (AC 1). `.wpb-map-dots{position:absolute;inset:0;inline-size:100%;block-size:100%}`.
- **Dots:** `circle{stroke:#1d2327;stroke-width:1;vector-effect:non-scaling-stroke;cursor:default}`. The dark ring gives at least 3:1 against both the land (`#dcdcde`) and the sea (`#f0f6fc`) for every bucket (AC 14, WCAG 1.4.11). `circle:focus-visible{stroke:#2271b1;stroke-width:3;outline:none}`.
- **Palette:** `.wpb-heat-0 … -7` set `fill` (and `background` on legend `<i>`), from light tint to bright red. Starting values: `#fde2dd #fbc4ba #f8a294 #f47f6e #ef5b48 #e83a26 #e01e10 #e60000`; the tester verifies contrast.
- **Tooltip:** `.wpb-map-tip{position:absolute;max-inline-size:16rem;padding:.25rem .5rem;background:#1d2327;color:#fff;border-radius:2px;pointer-events:auto}`. Add `.wpb-map-toggle[hidden],.wpb-map-more[hidden]{display:none}`, because `.button` would otherwise override `hidden`.
- **Top table:** `.wpb-map-top{max-block-size:45vh;overflow:auto}`. It gets `tabindex="0"` and `aria-label` only when it actually scrolls; JS checks that.
- **Forced colours:** `circle` and legend `i` get `forced-color-adjust:none` with `stroke` and `border` `CanvasText`; focus uses `Highlight`. There are no transitions or animations, so reduced motion needs nothing.
- **Touch targets (AC 12):** dots are under 24 CSS px at narrow widths. The Top countries table is the equivalent control (WCAG 2.5.8 "equivalent" exception) and is always present.

## 10. Security recommendations

| ID | Decision |
|---|---|
| SB11-01 | **Adopted.** `THREAT_ACTIONS = [blocked, lockout]` allowlist and `action IN (…)`. A non-threat action filter gives the `filtered_out` state with no query. `suppressed` is excluded too (summary row with no IP or country). |
| SB11-02 | **Adopted.** One method with a fixed shape that reuses `where()`, `LIMIT 300`. Adds `ORDER BY n DESC` so the cap keeps the largest groups, and returns `null` on a DB error. |
| SB11-03 | **Adopted, two variants.** Rules are checked by format (`^[a-z0-9_-]{1,32}$`), not against `log_rule_labels()`, because third-party rule ids are valid log values and the 20-key cap already bounds the cache. Days are snapped to site-time-zone midnight (converted to UTC), not UTC midnight, so the window matches the local times in the table. Both are deterministic. |
| SB11-04 | **Adopted.** (1) `s` and `log_ip` are ignored, per the owner decision of 2026-10-26, and the panel says so. (2) `wpb_map_keys` with a cap of 20, plus a generation counter. The deviation from AC 9's "one transient" is recorded (§6). (3) Variant: one site-wide lock instead of one per key, and the stale copy lives inside the day-long box instead of a second transient. |
| SB11-05 | **Adopted.** `log_from`/`log_to`: strict `Y-m-d` + `checkdate`, 365-day cap, reversed ranges rejected, end clamped to today, 30-day default. 5 s per-user throttle. 3600 s TTL over `FLOOD_ROWS`. Index → data-engineer (§11). |
| SB11-06 | **Adopted.** Same three flush events, the uninstall regex and option, per-site transients only. |
| SB11-07 | **Adopted.** `^[A-Z]{2}$` + `Countries::is_valid()`; failures count as Unknown. Valid codes with no place on the map (T1, EU, AP, AQ) appear in the table as "(not on the map)". |
| SB11-08 | **Adopted.** `textContent` only. Heat classes `wpb-heat-0..7` are set server-side, so JS never parses counts or computes colours. Dots are found by delegation and `dataset`, never by a selector built from data. |
| SB11-09 | **Adopted, stricter.** No data JSON at all: dots and table are rendered by PHP with `esc_attr`, `esc_html` and `number_format_i18n`, and `wp_localize_script` carries three UI strings. |
| SB11-10 | **Adopted.** Rendered inside the capability-checked view; no AJAX, REST or admin-post route. Handle `wp-bouncer-map` (defer, no deps), enqueued only when `sanitize_key` gives `tab === 'log'`. No `geoNonce`. Nothing in network admin. |
| SB11-11 | **Adopted.** PHP generator, pinned and hashed inputs, deterministic output committed with a pinned hash, DOM allowlist test, 85/100 KB ceilings and a zip `.svg` check. |
| SB11-12 | **Partly declined.** Dots are inline, as recommended. The base map is an `<img>` of the same-origin file: SVG-as-image is script-free and isolated, browser-cached, and keeps about 80 KB out of every page. The fixed path, the allowlist and the table-only fallback are kept. |
| SB11-13 | **Adopted, except `<details>`.** Storage hygiene as specified. `<details>`/`<summary>` is declined, because a heading inside `<summary>` loses its heading semantics in several screen readers. A real `<h2>` plus a toggle button that stays `hidden` until JS loads works the same without JS (the panel is open by default). |
| SB11-14 | **Adopted.** Help line in the panel. The docs-writer checks `documentation/geolocation.md` against the header-trust gating (`Plugin::geo_header_gated()`). |
| SB11-15 | **Adopted.** Portable SQL, `(int)` casts, case merged in PHP. |
| SB11-16 | **Adopted.** Delegated listeners on the dots SVG, `isTrusted` checks, the only timer is the tooltip's, no network APIs. The document `keydown` listener exists only while the tooltip is shown (needed for WCAG 1.4.13). |
| SB11-17 | **Adopted.** An integration test renders the panel over seeded rows and checks for no IPv4/IPv6, URI or UA strings. No privacy-policy change. |
| SB11-18 | **Adopted.** `null` → generic `error` state, nothing cached. |
| SB11-19 | **Adopted.** Mapped in §12. The browser checks are a manual checklist plus Node logic tests, because e2e has no browser (same as WPB-10b). |
| SB11-20 | **Adopted.** Docs-writer work in §8. |
| SB11-21 | **Adopted.** `wp_bouncer_map_cache_ttl` clamped to 60–3600. |

## 11. Questions for the data-engineer

1. **Index.** Run `EXPLAIN` (MySQL 8.0, MariaDB 10.11/11.x, and SQLite through the e2e stack) on the §4 query over 100k and 1M rows (`FLOOD_ROWS`; the write budget allows about 170k rows a day), with 30-, 90- and 365-day windows, with and without `rule` and `country` filters. Compare the existing `created_at` key with `(created_at, action, country)` and `(action, created_at, country)`. Both are covering for this query, and the second also skips `monitored`/`login` rows. Security suggested `(created_at, country)`, but that still needs row lookups for `action`. Check that `period_counts()`, `per_day()` and the table's paging don't get worse.
2. **`DB_VERSION` 3 → 4.** `Installer::create_tables()` starts `RedactionMigration::begin()` on **any** version change. Confirm that a re-run is harmless and affordable on a large log, or limit it to upgrades from versions below 3.
3. **dbDelta `ADD INDEX`.** Check duration and locking on a 5M-row InnoDB table (online DDL), the behaviour of the SQLite translation, and failure and retry through the existing upgrade lock.
4. **Storage.** Confirm the non-autoloaded `wpb_map_keys` option, the transient names (≤ 28 characters) against the uninstall regex, and behaviour with a persistent object cache (no `wp_options` rows; the index still drives flushes).

## 12. Test plan

**Unit, no WordPress** (`tests/Unit/ThreatMap/*`, `tests/Unit/Log/DateRangeTest.php`):
- **`DateRange`:**
  - Defaults: 30 days ending today, in `Pacific/Auckland` and `America/Los_Angeles`, across a DST change.
  - Rejected input: `2026-1-01`, `2026-02-30`, `20261001`, `2026-10-01T00:00`, `next monday`, `0000-01-01`, 300 characters, `%00`.
  - Only `from`, only `to`, reversed, over 365 days (capped), a future `to` (clamped).
  - Exact `since_utc` / `until_utc` values.
- **`ThreatQuery`:** `login`, `alert`, `monitored`, `suppressed` and `zzz` are not runnable; `blocked` and `lockout` are. Bad countries: `<x`, `a"b`, `us1`, `ZZ`, `''`. Bad rules. The key is the same for equivalent filters and different for different ones, is under 60 characters, ignores `search` and `ip`, and changes with the generation.
- **`CountryTally`:** `us` and `US` merge; `''` and junk go to unknown; SPECIAL codes are kept; ordering; `from_array()` re-validates.
- **`HeatScale`:** empty; one country → 7; all equal → 7; a dominant country (1, 2, 10 000) spreads across buckets; bucket is monotonic and within 0–7.
- **`MapModel`:** dot order; unplaced T1 and AQ; min/max over dots only; each state.
- **`CachePolicy`:** every row of the decision table; TTL clamp; flood TTL.
- **`KeyIndex`:** 100 inserts leave 20; the oldest is evicted; junk and foreign names are dropped.
- **`Centroids`:** every `Countries` code except SPECIAL and `UNPLACED` has a point; every point is inside `WIDTH` × `HEIGHT`; keys match `^[A-Z]{2}$`.
- **`WorldMapAssetTest`:** the allowlist passes on the committed file and fails on injected `<script>`, `<foreignObject>`, `onload`, `href`, `style`, a comment, a DOCTYPE with an entity, and a `data:` URL. Size ceilings. Pinned SHA-256 of `world.svg` and `Centroids.php`.
- **`ThreatMapScriptTest`:** the forbidden tokens from §9 are absent from `threat-map.js`; the file is ≤ 6 000 bytes; `admin.js` does not mention `wpb_map`.

**JS** (`tests/js/threat-map.test.js`, `make test-js`): `state()` with `"<img src=x onerror=alert(1)>"`, `"2"`, `""`, `null`, `"1"`, `"0"`. `move()` with every key, in LTR and RTL, at the bounds. `place()` clamping and flipping.

**Integration** (WordPress matrix on MySQL/MariaDB, `tests/Integration/...`):
- `threats_by_country()`:
  - Counts only blocked and lockout, out of rows for all six actions plus `zzz`.
  - `[since, until)` boundaries; `rule`, `action` and `country` filters; `search` and `ip` ignored.
  - The `''` group; `ORDER BY` and the 300 cap; `null` on a forced DB error.
- `where()` `until` on the table. `LogListTable` and CSV export follow `log_from`/`log_to`; invalid and reversed values are ignored and the notice is shown.
- Cache:
  - The first render builds and the second runs no map query (count queries through the `query` filter).
  - Flood TTL with a fake source over `FLOOD_ROWS`; the `wp_bouncer_map_cache_ttl` clamp.
  - Flush on clear-log, settings change and cron.
  - At most 20 `wpb_map_` boxes after 100 filter sets.
  - Throttle → `busy`; lock → stale; an orphan becomes unreachable after `flush()`.
  - Uninstall removes all `wpb_map_*` transients and the option (single site and multisite).
- Enqueue: only on `tab=log`. Not on other tabs, `logx`, `log/../`, other hooks, the front end or network admin. `wpBouncerMap` contains no nonce.
- States: empty, `no_geo` (no geo meta option), header-only countries draw the map, `log_action=login` → `filtered_out`, error.
- Privacy: rendered panel HTML over seeded rows contains no seeded IPv4/IPv6, URI or UA.
- Capability: a user without `manage_options` gets no map.
- Multisite: site 2's map excludes site 1's rows.

**e2e** (`run.sh`, SQLite, against the zip):
- The log tab contains `assets/map/world.svg`, `threat-map.js?ver=`, `class="wpb-map-dots"` and a seeded `data-cc`. The rules tab has no `threat-map.js`.
- `world.svg` returns 200 from the built zip.
- The panel markup has no `http(s)://` URL outside the site origin.
- `log_from`/`log_to` filter on SQLite.
- `make build` passes the `.svg` and size checks.

**Manual browser checklist** (Chrome, Firefox, Safari; recorded in the PR with screenshots for AC 18):
- Hover, focus, Arrow/Home/End and Esc on the tooltip; touch tap.
- The panel toggle persists, and seeded junk in `localStorage` is handled; the page still works when `setItem` throws.
- "Show all"; legend; one-country and equal-count cases.
- 782 px, 320 px (400% reflow), 200% zoom.
- RTL (`he_IL`): the legend mirrors and the map does not.
- Forced colours; NVDA or VoiceOver read the dot labels, table and caption.
- A seeded spoofed country `"<"` shows no dialog; no request leaves the origin (devtools network log).
- The zip size change is measured.

## 13. Risks, compatibility and extension

- **Risks.**
  1. Without the index (§11), a 365-day window on a flooded log can be slow on a miss. The flood TTL, lock, throttle and stale serving limit how often that happens.
  2. Dots overlap in Europe and the Caribbean. Paint order, roving focus and the table mitigate it.
  3. Natural Earth draws de facto borders. Outlines only, no labels.
  4. Country is spoofable behind an untrusted proxy (help text, SB11-14).
  5. `XK` (Kosovo) and other codes missing from `Countries` count as Unknown. A possible follow-up is to add them to `Countries`, which also affects the country-block picker.
  6. Brief open-then-close of a collapsed panel on load.
  7. AC 8 is read narrowly (§7).
- **Backward compatibility.** With no date parameters, the table behaves exactly as in 1.2.x. The new parameters are optional, and existing bookmarks and export links still work. No settings keys change. A schema change happens only if the data-engineer adds the index.
- **Multisite.** Per-site table, transients and option. Nothing appears in network admin. `localStorage` is shared per origin, which is acceptable for a UI preference.
- **Uninstall.** §6. Browser `localStorage` is not touched, the same as WPB-10b.
- **Extension points.** The `wp_bouncer_map_cache_ttl` filter (clamped), the public static `ThreatMapPanel::flush()` for code that deletes log rows, and CSS hooks (`.wpb-map`, `.wpb-heat-0..7`, `.wpb-map-dots`). There is deliberately no filter on `THREAT_ACTIONS`: it defines what a threat is, and a filter could make admin logins count as attacks. `wpBouncerMap` is not an API.

## Data decisions (data-engineer)

Measured on local MariaDB 10.11.14, InnoDB, generated rows spread evenly over 365 days (60% blocked, 20% monitored, 10% login, 10% alert, 20 countries). MySQL 8 was not run here. Its range-plus-covering-index behaviour is the same, so I reasoned from this.

1. **Index: yes, add `KEY action_created (action,created_at,country)`.** The §4 query with the existing `created_at` key does a row lookup for every row in the window (`Using index condition`). At 1M rows, 30 days takes 3.8 s and 365 days 5.8 s. With `(created_at,action,country)`: 0.05 s and 0.39 s. With `(action,created_at,country)`: 0.03 s and 0.21 s (it reads only blocked and lockout rows; 100k rows: 0.008 s versus 0.021 s on `created_at`). Both are covering, and the optimizer picks `action_created` unaided. **Follow this section, not §13's "no schema change"**. The `rule` filter still needs lookups, but only for matching rows, and `rule` may be chosen instead. `country`-only filters are covered. `period_counts()` and `top()` already filter on `action IN/NOT IN`, and `per_day()` and the table paging keep using `created_at` (verified by EXPLAIN: paging `ORDER BY created_at DESC LIMIT 50` is unchanged). They don't get worse. The cost is one more index to maintain per insert (about 170k rows a day at most). `BlockLog::where()` is fine: `created_at` is `datetime` and `since`/`until` are bound `Y-m-d H:i:s` strings, so `>=` and `<` are range conditions. Don't wrap the column in a function.
2. **`DB_VERSION` '3' to '4' in `Installer`, and the `dbDelta` change:** add one line `KEY action_created (action,created_at,country)` after `KEY rule (rule)` in the log table. dbDelta runs a plain `ALTER TABLE ... ADD KEY` for a new key name. **Yes, the bump would restart `RedactionMigration`**: `create_tables()` calls `begin()` on any version change, and `begin()` adds the cursors again because the option was deleted at the end of the first run. The rescan would walk both tables from id 0 (cheap SELECTs, only differing rows updated, so harmless but pointless). Fix: replace the condition with `if ( (int) get_option( self::DB_VERSION_OPTION ) < 3 )` (a missing option is 0, so fresh installs still call it on empty tables). Also update the docblock "Version 3 also redacts rows..." and add "Version 4 adds the action_created key". Add a unit test: upgrading from '3' does not create `wp_bouncer_migration_3`.
3. **ADD INDEX cost:** 1M rows took 1.7 s with `ALGORITHM=INPLACE, LOCK=NONE` (MariaDB). Expect roughly 10 s on 5M rows. InnoDB on MySQL 5.6+ and MariaDB 10.0+ does this online (reads and writes continue, with a brief metadata lock at start and end), and plain `ADD KEY` in dbDelta uses it by default. Retention purge keeps the table small anyway. If the ALTER fails, `tables_exist()` is still true, so `create_tables()` records version 4 without the index and nothing retries. The query stays correct, only slower; I accept that (a `SHOW INDEX` check would need a SQLite branch). The existing upgrade lock only covers a crashed run. No readme upgrade notice is needed beyond one changelog line: "adds an index to the activity log table (a few seconds on large logs)".
4. **SQLite (not run, reasoned from code):** the WordPress SQLite translator is expected to translate dbDelta's `SHOW INDEX` lookup and `ALTER TABLE ... ADD KEY` into `CREATE INDEX`, so a new key is added without data loss. I did not verify this. The query uses only portable SQL. SQLite can use the index (it is covering). Run the e2e suite once on the upgrade path (install with DB_VERSION 3, then 4) to confirm. This is the tester's job.
5. **Storage:** non-autoloaded `wpb_map_keys` option: design is sound (autoload false, as for `wp_bouncer_migration_3`; 28-character transient names plus the `_transient_timeout_` prefix fit `option_name` varchar(191)). Uninstall must delete `_transient_wpb_map_%` and `_transient_timeout_wpb_map_%` (escape `_` in LIKE); I checked the design, not uninstall.php code, which does not exist yet. With a persistent object cache no option rows exist, so the keys list still drives the flushes. Test data tables were dropped.
