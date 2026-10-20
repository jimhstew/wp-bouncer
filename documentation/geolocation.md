# Geolocation

Country blocking needs to know where an IP is. WP Bouncer never calls a remote API per visitor. It uses one of two local sources, chosen under **General → Country lookup**.

## 1. Local database (default)

A table of IP ranges you import under **Tools → Geo database**, either by URL or by file upload. Importing replaces the previous data.

### How an import runs

A full DB-IP file is about 710,000 ranges. Inserting them takes from 20 seconds to a few minutes depending on the database, which is more than many hosts allow a single PHP request. So the import (`Geo\GeoImport`) is split into steps:

1. **Start** (the form submit). The file is downloaded or uploaded, unpacked to a plain CSV in `wp-content/uploads/wp-bouncer/` (with an `.htaccess` that denies web access), and its first lines are checked. If none parse, for example because the URL returned an HTML error page, the import is refused and the current data is untouched. Otherwise the table is emptied and the progress is saved in the `wp_bouncer_geo_import` option.
2. **Steps.** The Tools tab shows a progress bar and calls `admin-ajax.php?action=wp_bouncer_geo_step` repeatedly. Each step imports for about 5 seconds from the saved byte offset (`CsvImporter::import_chunk()`), then saves the new offset. A failed step is retried up to three times. Re-inserting a batch is harmless (`INSERT IGNORE` on the primary key). Without JavaScript, a **Continue import** button runs one step per click.
3. **Finish.** The last step records the row count in `wp_bouncer_geo_meta` and deletes the working file.

If you leave the page, the import pauses and carries on the next time you open the Tools tab. **Stop import** ends it early and keeps the ranges loaded so far, marked "incomplete". While an import runs, addresses whose ranges aren't loaded yet look up as unknown, and country blocking lets them in.

The step length can be changed with a filter, for hosts with very short limits:

```php
add_filter( 'wp_bouncer_geo_step_seconds', function () { return 3.0; } );
```

Uploads are limited by PHP's `upload_max_filesize` and `post_max_size`; the Tools tab shows the current limit. Upload the `.csv.gz` (about 5 MB) rather than the unpacked CSV (about 30 MB), or import by URL.

Supported files (`.csv` or `.csv.gz`):

| Source | Licence | Notes |
|---|---|---|
| [DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite) | CC BY 4.0 | IPv4 + IPv6, about 710k ranges, updated monthly. The Tools form is pre-filled with `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz`. Attribution required: "IP Geolocation by DB-IP" linking to db-ip.com, somewhere on your site. |
| [IP2Location LITE DB1](https://lite.ip2location.com/database/db1-ip-country) | CC BY-SA 4.0 | Free account needed to download. The IPv4 file (integer ranges) is supported. The IPv6 file uses 128-bit integers and isn't. |
| Your own | — | Any CSV whose first three columns are `start_ip,end_ip,country_code`. |

The parser (`Geo\CsvImporter`) skips headers, comments, blank lines, `ZZ` (unassigned) rows and rows it can't parse, and reports how many it skipped.

MaxMind GeoLite2 is **not** supported directly. Its CSV splits networks and locations across two files, and its licence requires an account key. Convert it to `start,end,country` yourself if you prefer it.

**Keep it fresh.** IP allocations change. Re-import monthly. There's no automatic download, on purpose: the plugin makes no outbound requests you haven't asked for.

**Storage.** Each range is stored as two 32-character hex strings (the 16-byte address, with IPv4 mapped into `::ffff:0:0/96`), indexed on the start address. A lookup is one indexed `ORDER BY … DESC LIMIT 1` query. The full DB-IP file takes roughly 40–50 MB including the index.

## 2. Header from your CDN or web server

If something in front of WordPress already geolocates requests, read its result instead:

| Source | Header / variable name to enter |
|---|---|
| Cloudflare (IP Geolocation on) | `CF-IPCountry` |
| nginx `ngx_http_geoip2_module` / Apache `mod_maxminddb` | whatever variable you export, e.g. `GEOIP_COUNTRY_CODE`, `MM_COUNTRY_CODE` |
| AWS CloudFront | `CloudFront-Viewer-Country` |

The name is looked up as an HTTP header first (`HTTP_<NAME>`), then as a raw server variable. If the header is missing, the local database is used as a fallback.

**Only use a header if clients can't reach your origin directly.** Otherwise anyone can send `CF-IPCountry: US`. With Cloudflare, firewall your origin to Cloudflare's IP ranges.

Cloudflare reports Tor exit nodes as `T1`, which can be blocked like a country.
