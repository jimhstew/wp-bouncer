# Rules reference

All rules live in `wp-bouncer/src/Rules/`, except `uploads_php`, which lives in `wp-bouncer/src/Hardening/` because it works through the web server and the upload handler rather than the request firewall. Settings are stored under `wp_bouncer_settings['rules'][<id>]`, and every rule has an `enabled` flag.

Evaluation order: `ip_blocklist`, `sensitive_files`, `not_found`, `login_lockout`, `rate_limit`, `user_agent`, `xmlrpc`, `user_enumeration`, `country`, `waf`. The first rule that refuses a request wins.

Administrators (users with `manage_options`) are never inspected by the WAF, the rate limiter, the sensitive-file rule or the 404 counter. Allowlisted and loopback IPs skip every rule.

Email alerts aren't a rule; they are described at the end.

---

## `ip_blocklist`: IP blocklist
**Default:** on (empty list) · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `ips` | string[] | IPv4/IPv6 addresses or CIDR ranges. Invalid entries are dropped on save. |

Adding IPs: Rules tab, the "Block IP" row action in the Activity Log, or the "Block" button on the Dashboard's Top IPs.

## `user_agent`: User-Agent filter
**Default:** on · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `block_empty` | bool | Refuse requests with no User-Agent. Real browsers always send one. |
| `patterns` | string[] | Plain text matches anywhere, ignoring case. `/regex/flags` is a PCRE pattern, and invalid regexes are dropped on save. |

The default patterns are well-known attack tools only. Generic clients such as `curl`, `python-requests` and `Go-http-client` aren't listed, because uptime monitors and integrations use them. Add them yourself if you want.

## `country`: Country blocking
**Default:** off · **Status:** 403 · Needs a geo source, see [geolocation.md](geolocation.md)

| Setting | Type | Notes |
|---|---|---|
| `mode` | `block` \| `allow` | `allow` refuses every country *not* listed. An `allow` list with no countries counts as off, so the whole world can't be locked out. |
| `countries` | string[] | ISO 3166-1 alpha-2 codes, plus `T1` (Tor, Cloudflare header only), `EU`, `AP`. |
| `block_unknown` | bool | Refuse IPs the database can't place. Leave this off unless you really mean it, because new or reassigned ranges are often missing. |
| `scope` | `site` \| `login` | `login` covers wp-login.php, xmlrpc.php and /wp-admin/ only, so visitors can still read the site. |

## `xmlrpc`: XML-RPC blocking
**Default:** on, `block_all` · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `mode` | `block_all` \| `block_abuse` | `block_abuse` keeps XML-RPC working for apps but refuses `system.multicall`, `pingback.ping` and `pingback.extensions.getPingbacks`. |

While the rule is on, the plugin also removes the `X-Pingback` header and the RSD link. In `block_all` mode it also sets `xmlrpc_enabled` to false and empties the method list. Use `block_abuse` if you rely on the WordPress mobile apps, Jetpack or a desktop blogging client.

## `login_lockout`: Login lockout
**Default:** on · **Status:** 403 with Retry-After

| Setting | Type | Default | Notes |
|---|---|---|---|
| `max_attempts` | int 1–100 | 5 | Failures allowed in the window. |
| `window_minutes` | int 1–1440 | 15 | Fixed window from the first failure. |
| `lockout_minutes` | int 1–43200 | 60 | |
| `banned_usernames` | string[] | admin, administrator, root, test | Trying one locks the IP out immediately. **Remove any name a real account uses.** |
| `generic_errors` | bool | true | "Unknown username" and "wrong password" become the same message. |

The protection works at two levels:
1. `LoginLockoutRule` refuses **POSTs** to wp-login.php and any request to xmlrpc.php from a locked-out IP before WordPress authenticates. The login page itself still displays.
2. The `authenticate` filter (priority 999) refuses locked-out IPs on *every* login path, including REST application passwords and custom login forms.

Lift a lockout early under Tools → Unlock an IP.

## `rate_limit`: Rate limiting
**Default:** off · **Status:** 429 with Retry-After

| Setting | Type | Default |
|---|---|---|
| `max_requests` | int 10–100000 | 240 |
| `window_seconds` | int 1–3600 | 60 |
| `ban_minutes` | int 1–1440 | 10 |

Only requests that reach PHP are counted. Static files served by the web server aren't. **Without a persistent object cache** (Redis or Memcached), every counted request writes a transient to `wp_options`, so only enable this on busy sites that have one. Don't set limits so low that a page load (one HTML request plus AJAX calls) trips them. Sites behind a CDN must configure the client IP source first, otherwise every visitor shares the CDN's IP.

## `waf`: Web application firewall
**Default:** on, all categories · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `sqli` | bool | UNION SELECT, `' OR '1'='1` tautologies, SLEEP/BENCHMARK, `information_schema`, `INTO OUTFILE`, stacked DROP/TRUNCATE. |
| `xss` | bool | `<script`, `javascript:`, `on*=` event handlers inside tags, iframe/object/embed/base/meta tags, `document.cookie`. |
| `traversal` | bool | `../../`, `/etc/passwd`, `../wp-config.php`, `php://` and similar stream wrappers. Also checked in the URL path. |
| `code_injection` | bool | `<?php`, `eval(`/`assert(`/`shell_exec(`/`base64_decode(`, `${jndi:`, `; wget http://…`. |
| `excluded_params` | string[] | Top-level parameter names that are never inspected. |

Scope: parameter names and values in the query string and POST body (nested arrays included, values capped at 8 KB). Each value is checked as-is and after one extra round of URL decoding, which catches double encoding. Cookies and headers aren't inspected.

**False positives:** the signatures are tuned to leave normal prose alone. Phrases like "select a union rep", "I <3 the online =" and "edit wp-config.php" are all in the test suite as must-pass. A site whose visitors legitimately submit code, such as a programming Q&A form, should add that form's field name to `excluded_params`. Start new installs in monitor mode and check the log.

Signatures are in `WafRule::SIGNATURES`. Each one has a short name that appears in the log reason.

## `user_enumeration`: User enumeration
**Default:** on · **Status:** 403

| Setting | Type | Notes |
|---|---|---|
| `block_author_scan` | bool | `?author=<number>` for logged-out visitors (outside wp-admin). Author slugs (`?author_name=jane`, `/author/jane/`) still work. |
| `block_rest_users` | bool | `/wp-json/wp/v2/users…` and `?rest_route=/wp/v2/users…` for logged-out visitors. |

The users sitemap (`/wp-sitemap-users-1.xml`) is removed while the rule is on.

## `sensitive_files`: Sensitive-file probes
**Default:** on · **Status:** 403 · `src/Rules/SensitiveFileRule.php`

| Setting | Type | Notes |
|---|---|---|
| `ban_minutes` | int 0–43200 | How long the IP is then refused on every page. Default 60. `0` refuses only the probe itself. |
| `extra_paths` | string[] | More path fragments to treat as probes, matched anywhere in the lowercased path, e.g. `/old-admin/`. |

Matched against the decoded, lowercased path (never the query string). The groups, each named in the log reason, are in `SensitiveFileRule::PATTERNS`: environment files (`/.env`, `/.env.production`), version-control data (`/.git/`, `/.svn/`…), server config files (`.htpasswd`, `.htaccess`, `.user.ini`, `.DS_Store`…), hidden config folders (`/.aws/`, `/.ssh/`…), wp-config copies (`wp-config.php.bak`, `wp-config.old`…), PHP file backups (`*.php.bak`, `*.php~`, `*.php.swp`…), database dumps (`*.sql`, `*.sql.gz`, `*.sqlite`), site backup archives at the top level (`/backup.zip`, `/wordpress.tar.gz`…), log files (`debug.log`, `error_log`), phpinfo pages, database admin tools (`adminer*.php`, `/phpmyadmin/`), known web shells (`wso.php`, `c99.php`…), PHP in uploads, the PHPUnit `eval-stdin.php` exploit, project manifests at the top level (`composer.json`, `package.json`, `docker-compose.yml`) and `/server-status`.

Never treated as probes: `/.well-known/…`, `/wp-config.php`, `/wp-config-sample.php`, and the uploads self-test script.

Why one request is enough: a file that exists is served by the web server before WordPress runs, so a request that reaches WordPress is for a file that isn't there. No real visitor asks for `/.git/config`. The ban key is `sf_ban:<ip>` in the counter store; **Tools → Unlock an IP** clears it.

## `not_found`: 404 flood
**Default:** on · **Status:** 403 · `src/Rules/NotFoundFloodRule.php`

| Setting | Type | Notes |
|---|---|---|
| `max_404` | int 3–10000 | "Not found" pages allowed per window. Default 20. |
| `window_seconds` | int 10–3600 | Default 60. |
| `ban_minutes` | int 1–43200 | Default 60. |
| `ignore_crawlers` | bool | Don't count User-Agents of major search engines (Google, Bing, DuckDuckGo, Baidu, Yandex, Apple, Yahoo, Petal, Seznam, Qwant). User-Agents can be faked, so this trades a little protection for not banning crawlers that revisit removed pages. Default on. |

Two halves. `Plugin::track_not_found()` runs on `template_redirect` at priority 999, after other plugins have had their chance to turn the 404 into a redirect or a page; if `is_404()`, it calls `NotFoundFloodRule::record()`. Going over the limit places a ban (logged with action `lockout`), and `inspect()` refuses the IP from its next request.

Not counted: missing static files (images, CSS, JS, source maps, fonts, audio/video, PDF), so a page with a broken image never bans its reader; logged-in administrators; allowlisted IPs. `.txt`, `.json`, `.xml` and `.php` do count, because scanners ask for plugin `readme.txt` files and config files. REST API "no route" errors aren't page 404s and don't count. Keys: `nf_count:<ip>`, `nf_ban:<ip>`.

## `uploads_php`: No PHP in uploads
**Default:** on · `src/Hardening/UploadsGuard.php` (WordPress side) and `src/Hardening/UploadsPolicy.php` (pure, unit-tested)

| Setting | Type | Notes |
|---|---|---|
| `htaccess` | bool | Keep a `# BEGIN WP Bouncer` … `# END WP Bouncer` block in `wp-content/uploads/.htaccess`. |
| `check_uploads` | bool | Refuse uploads that are scripts in disguise. |

**The `.htaccess` block** is a `<FilesMatch>` on script extensions (`php`, `php0`–`php9`, `phtml`, `pht`, `phar`, `phps`, `pgif`, `shtml`, `cgi`, `pl`, `py`, `asp`, `aspx`, `jsp`) with `Require all denied`, plus `Order`/`Deny` for Apache 2.2. It deliberately doesn't use `php_flag engine off`, which gives a 500 error on servers running PHP-FPM. It is written with WordPress's `insert_with_markers()`, so anything else in the file stays. A fingerprint of the wanted state is kept in option `wp_bouncer_uploads_htaccess`; on each `init` the plugin compares it and only touches the file when something changed (after a failed write it retries once an hour, and the Bouncer screens show a warning). The block is removed when either setting turns it off, while `WP_BOUNCER_DISABLE` is on, on deactivation, and on uninstall. If nothing else was in the file, the file is deleted.

**Safety check.** `Require` and `Deny` are only allowed in `.htaccess` when the host's `AllowOverride` permits them; on a host that doesn't, every file in uploads, images included, would get a 500 error while the block is there. So after writing the block the plugin schedules a one-off cron job (`wp_bouncer_uploads_check`) that puts a small text file in uploads and fetches it. If the server answers with a 5xx error, the block is removed, the state is marked `broken` so it isn't written again, an `alert` entry is logged, and the Bouncer screens show an error. **Test now** runs the same check first. **Write it now** on the Rules tab tries again once the host is fixed. A check that can't reach the site at all changes nothing.

nginx ignores `.htaccess`. The Rules tab shows the equivalent rule:

```nginx
location ~* ^/wp-content/uploads/.*\.(php[0-9]?|phtml|pht|phar|phps|pgif|shtml|cgi|pl|py|asp|aspx|jsp)$ {
    deny all;
}
```

**Test now** (`UploadsGuard::probe()`) writes `wp-content/uploads/wp-bouncer-test-<random>.php`, requests it over HTTP from the site itself, deletes it, and stores the result in option `wp_bouncer_uploads_probe`. Protected means a 401/403, or the script's source coming back as text. Not protected means the script ran. If the safety check found the block breaking uploads, the result is "not protected, block removed". Anything else (404, 500, a timeout, a redirect) is reported as "could not tell".

**Upload checks** hook `wp_handle_upload_prefilter` and `wp_handle_sideload_prefilter`, which cover the media library, the REST API (`/wp/v2/media`), `media_handle_sideload()` and WP-CLI `wp media import`. A file is refused if any part of its name after the first dot is a script extension (`photo.php.jpg`, since some servers run any file with `.php` in its name), if it is a server config file (`.htaccess`, `.user.ini`, `php.ini`, `web.config`, `.htpasswd`), or if its first 50 MB contain `<?php` in any case. Refusals are logged with rule `uploads_php`. Plugins that write files themselves, without WordPress's upload functions, aren't covered; the `.htaccess` block is what protects against those.

---

## Email alerts
**Default:** on · General tab · `src/Alerts/AlertNotifier.php` (hooks) and `src/Alerts/AlertFormatter.php` (pure, unit-tested) · Settings in `wp_bouncer_settings['alerts']`

| Setting | Type | Notes |
|---|---|---|
| `enabled` | bool | Master switch. |
| `recipients` | string[] | Up to 10 valid addresses. Empty means the site's admin email. |
| `new_admin` | bool | An account is created as, promoted to or given the administrator role (any role with `manage_options`), or made a multisite super admin. Hooks: `user_register`, `set_user_role`, `add_user_role`, `granted_super_admin`. |
| `plugin_changes` | bool | A plugin is installed (`upgrader_process_complete`, action `install`), activated, deactivated or deleted (`activated_plugin`, `deactivated_plugin`, `deleted_plugin`). WP Bouncer itself being deactivated says so in the subject. |
| `plugin_updates` | bool | A plugin is updated. Off by default, since updates are routine and auto-updates already email the admin. |

Events are queued during the request and sent as one `wp_mail()` on `shutdown`, so "install and activate" is one email. Creating an administrator fires several hooks; they are merged into one line per user. Each email gives what happened, when, who was logged in (or "no logged-in user" for WP-CLI, cron or code), and the IP, country and User-Agent. Names are stripped of control characters, so a crafted username can't add mail headers. At most 20 emails go out per hour (transient `wpb_alert_count`); every event is also written to the Activity Log with rule `alerts` and action `alert`, which the Dashboard's statistics leave out. Alerts keep working while `WP_BOUNCER_DISABLE` is on, because they never refuse anyone.

**Send a test email** (General tab) sends a sample and reports WordPress's mail error if sending fails.

---

## Traffic log
**Default:** off · Traffic tab · `src/Traffic/` · Settings in `wp_bouncer_settings['traffic']`

| Setting | Type | Notes |
|---|---|---|
| `enabled` | bool | Record requests. |
| `retention_days` | int 1–7 | Rows older than this are deleted by the hourly cron job `wp_bouncer_traffic_purge`. Default 7. The purge never keeps anything longer than 7 days, whatever is stored. |
| `skip_background` | bool | Don't record `/wp-cron.php` or admin-ajax Heartbeat requests. Default on. |
| `skip_admins` | bool | Don't record logged-in administrators. Default off. |

`TrafficRecorder` writes one row on `shutdown` at priority 100, after everything else, so `http_response_code()` is final. Blocked requests are included: the block page ends with `exit`, and PHP still runs shutdown hooks. WP-CLI is never recorded. A failure to write (for example, the table is missing) is silent and never breaks the page.

Columns of `{prefix}bouncer_traffic`: `created_at` (UTC), `ip`, `method`, `uri` (up to 2048 characters), `referrer` (2048), `user_agent` (512), `client`, `status` (0 if unknown), `user_id` (0 for visitors). Indexed on time, IP, client and status.

**Client type** (`ClientClassifier::classify()`, pure) is read from the User-Agent, first match wins: attack tool (sqlmap, WPScan, Nikto…), search engine (Googlebot, Bingbot…), uptime monitor, feed reader, bot or crawler (anything saying bot, crawl or spider; SEO and AI crawlers; link previews), WordPress (its own loopback and pingback requests), script or tool (curl, wget, Python, Go, Java…), then mobile browser or browser for `Mozilla/…`, "no User-Agent" for an empty one, and "other". The User-Agent is whatever the client claims, so the type is a reading aid, not proof.

**Secrets in URLs** (`TrafficEntry::redact_url()`, pure): the values of `key`, `pwd`, `pass`, `password`, `token`, `access_token`, `refresh_token`, `id_token`, `auth`, `code`, `secret`, `client_secret`, `api_key`, `signature`, `nonce`, `_wpnonce`, `session`, `sid`, `otp`, `jwt`, and any parameter whose name contains `pass`, `token` or `secret`, become `[removed]`, in both the URL and the referrer. That covers WordPress's password-reset links (`wp-login.php?action=rp&key=…`).

What isn't recorded: files the web server serves itself (images, CSS, JS, and any file that exists), since those never reach WordPress.
