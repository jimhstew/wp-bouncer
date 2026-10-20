# Rules reference

All rules live in `wp-bouncer/src/Rules/`. Settings are stored under `wp_bouncer_settings['rules'][<id>]`, and every rule has an `enabled` flag.

Administrators (users with `manage_options`) are never inspected by the WAF or the rate limiter. Allowlisted and loopback IPs skip every rule.

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
