# WP Bouncer

A self-contained firewall for WordPress. Like a bouncer at a club door, it checks every visitor before WordPress does any real work and turns away the ones that don't belong:

- known-bad IP addresses and ranges
- visitors from countries you choose
- attack tools and blank user-agents
- password guessers (failed-login lockouts)
- XML-RPC abuse
- request floods (rate limiting)
- SQL injection, cross-site scripting and similar attacks in URLs, forms and JSON bodies (a small web application firewall)
- username harvesting
- scanners probing for secrets and backups (`.env`, `.git`, `wp-config.php.bak`, database dumps, web shells)
- scanners hitting page after page of "not found" URLs
- scripts uploaded to `wp-content/uploads`, the commonest way sites get backdoored

It can also keep a **traffic log** of every request that reaches WordPress (who, what kind of client, which URL, the response code and where they came from) for up to a week.

It also emails you when an administrator account appears, when an administrator signs in from a country or network not seen for that account recently, a plugin is installed, activated, deactivated or deleted, or the firewall's own settings change, so you hear about a break-in the same day. Every administrator login is recorded in the Activity Log.

The Dashboard tab and Site Health also report whether your PHP and database versions still get security fixes, and flag PHP and WordPress settings that weaken security.

There is no cloud service, account or subscription. Everything runs on your server, and nothing about your visitors is sent anywhere. Licence: GPL-2.0-or-later.

---

## What's in this repository

| Folder / file | What it is | Goes on your server? |
|---|---|---|
| `wp-bouncer/` | The plugin itself | **Yes**, as the zip built from it |
| `builds/` | The zip to upload, created by `make` | The zip inside it, yes |
| `tests/` | Automated tests. They contain sample attack strings on purpose, which is why some hosts' malware scanners flag them. | **No, never** |
| `documentation/` | Developer documentation and the changelog | No |
| `Makefile`, `composer.json`, `php*.dist` | Build and test tooling | No |

---

## Install

### 1. Get the zip

If someone has already given you `wp-bouncer-<version>.zip`, skip to step 2.

To build it yourself, you need `make` and `zip` (both come with macOS and most Linux systems). In this folder, run:

```bash
make
```

This creates `builds/wp-bouncer-<version>.zip`, with a `.sha256` checksum next to it. The zip contains only the `wp-bouncer/` folder: no tests and no documentation.

### 2. Upload it to WordPress

1. In wp-admin go to **Plugins → Add New Plugin → Upload Plugin**.
2. Choose the zip, click **Install Now**, then **Activate**.

From version 1.1.0 on, the plugin updates itself like any other plugin (see [Updates](#updates)). To upgrade an older copy, upload the newer zip the same way. WordPress asks whether to replace the installed version; choose **Replace current with uploaded**. Your settings and log are kept.

Without the upload screen, unzip it on your computer and copy the `wp-bouncer` folder into `wp-content/plugins/` on the server (by FTP, SFTP or your host's file manager). Then activate it under **Plugins**.

Requirements: WordPress 7.0 or newer, PHP 8.3 or newer, and MySQL or MariaDB (or SQLite, with the SQLite Database Integration plugin). The plugin doesn't declare a minimum database version. CI tests MySQL 8.4 and MariaDB 10.11 and 11.4, and the Dashboard tab reports whether your database version is still supported.

On a multisite network, network-activate WP Bouncer. Per-site activation can strip the uploads protection, and only network admins can change the network-wide uploads setting, URL geo imports and regex User-Agent patterns.

---

## First-time setup (5 minutes)

A new **Bouncer** item appears in the wp-admin menu. Most protection is on from the moment you activate. Before relying on it, do the following:

1. **Bouncer → General → "Your IP as currently detected".** Check that this is your real public IP (search "what is my IP" to compare).
   - If it shows something else, such as your host's proxy, Cloudflare, or 127.0.0.1, your site is behind a proxy or CDN. Set **Client IP source** to match (Cloudflare: `CF-Connecting-IP`) and list the proxy's addresses under **Trusted proxies**.
   - A forwarding header is believed only when the request comes from an address listed under **Trusted proxies**. If you choose a header but list no proxies, WP Bouncer ignores the header, uses the connection address, and shows an **IP detection** notice on every admin screen. The notice's buttons either accept the connection address (**I have no proxy: use the connection address**) or trust a private or same-server proxy (**Trust `<address>` as my proxy**). For a public proxy or CDN, don't trust its single address; list the CDN's full published IP ranges under **Trusted proxies** instead. The notice can't be dismissed. While it shows, bans and lockouts are suspended (failed logins are still logged) and rate limiting is effectively off. The WAF, User-Agent, blocklist and sensitive-file checks still apply.
   - Header values that are private, loopback, link-local, carrier-grade NAT, unique-local or unspecified are refused. If an intranet reverse proxy passes real private client addresses, add `define( 'WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS', true );` to wp-config.php. Loopback is never accepted from a header.
   - Ranges wider than /8 (IPv4) or /16 (IPv6) are ignored in **Trusted proxies** and the **Allowlist**, and are dropped when you save, with a message naming them.
   - This matters. If it's wrong, every visitor looks like the same IP, and blocking one would block everybody.
2. **Add yourself to the Allowlist** (General tab, **Add my IP** button). IPs on the allowlist skip every rule, so you can't lock yourself out. If your address is shared with other visitors (a proxy, CDN or the fallback above), WP Bouncer refuses the save and points you to IP detection instead of allowlisting the shared address.
3. **Optional: try Monitor mode first.** In General, set **Mode** to **Monitor**. Matching requests are logged but not blocked. After a few days, look at the **Activity Log**. If nothing legitimate shows up there, switch back to **Enforce**.
4. **Country blocking (optional).** This is off until you set it up:
   1. **Tools → Geo database → Import.** The form is pre-filled with this month's free DB-IP file. Keep the page open while the progress bar runs, usually one to three minutes.
   2. **Countries tab:** tick the countries to block, or choose "allow only these countries". Choose whether to apply it site-wide or only to the login pages. Then switch the rule on.
   3. The DB-IP licence asks for a credit somewhere on your site, such as "IP Geolocation by DB-IP" linking to https://db-ip.com.
5. **Check the alert emails reach you.** **General → Email alerts → Send a test email.** Alerts go to the site's admin email unless you list other addresses. If the test doesn't arrive, check spam; many hosts need an SMTP plugin before WordPress can send mail.
6. **Check uploads are protected.** **Rules → No PHP in uploads → Test now.** "Protected" means your server refused to run a test script placed in the uploads folder. On nginx, which ignores `.htaccess`, add the rule shown there to your server config and test again.

---

## Using it

| Tab | What you do there |
|---|---|
| **Dashboard** | Blocks in the last 24 hours, 7 days and 30 days, a 14-day chart, the top rules, IPs and countries, and an on/off switch for every rule. Administrators also get a **WP Bouncer** box on the WordPress Dashboard, one per site, with the 24-hour and 7-day counts. |
| **General** | Enforce or monitor mode, IP detection and trusted proxies, the allowlist, how long to keep the log, the message blocked visitors see, and email alerts. |
| **Rules** | Each blocking rule, with its own on/off switch and settings, in four groups: Block lists, Login and accounts, Scanners and floods, and Attack payloads and hardening. A rule that needs attention is flagged, and rate limiting shows a "Before switching on" note. Rules that other plugins add appear under Other. |
| **Countries** | Pick countries from the list of 249, grouped by continent and searchable. |
| **Activity Log** | Everything that was blocked or would have been (in monitor mode): when, which IP and country, which rule and why. Email alerts and administrator logins (action **Admin login**) are listed too. Filter, search, export to CSV, or **Block IP** from any row. For an IPv6 row, **Block /64** blocks its whole network, which is how the firewall counts that client. |
| **Traffic** | Optional. Every request that reached WordPress for the last 1 to 7 days: time, IP, client type (browser, mobile, search engine, bot, uptime monitor, script, attack tool…), method and URL, response code, referrer, User-Agent and logged-in user. Filter by client, response class or IP, search, export to CSV, **Block IP** from any row. |
| **Tools** | Import or refresh the geo database, unlock an IP that is locked out or banned, and the emergency instructions below. |

Out of the box every rule is on except **country blocking** and **rate limiting**, which need setting up first. The **traffic log** is off until you switch it on (Traffic tab), because it adds one database write per request.

**Privacy.** WordPress's Export and Erase Personal Data tools include the traffic log (by user account), the block log and the administrator-login history and rows. Erasing an administrator deletes their login history and login rows; the block-log rows are kept. Erasing a user keeps the block-log rows but clears the URL and reason of the rows that name that account. The privacy policy guide gets a suggested paragraph. Exports and erasure are by account, not by IP address.

**Environment checks** appear on the Dashboard tab and in Site Health: PHP and database versions against their security support end dates, and PHP and WordPress settings that weaken security (for example `allow_url_include`, `display_errors`, `DISALLOW_FILE_EDIT`, a web-readable `debug.log`). Each check says why it matters and how to fix it. WP Bouncer never changes those settings itself.

About the traffic log: it records requests that reach WordPress, including ones WP Bouncer blocked (with their 403), redirects and 404s. Images, CSS and JS that your web server serves directly never reach WordPress, so they aren't in it; your host's access log has those. WP-Cron and the admin Heartbeat are skipped by default. Passwords, password-reset keys, tokens and nonces are removed from URLs and referrers before saving. Rows older than the retention you choose (1 to 7 days) are deleted every hour. IP addresses are personal data in many places, so mention the log in your privacy policy.

Three rules ban an IP for a while after it misbehaves, so it can't try anything else meanwhile: **sensitive-file probes** (two requests for files like `/.env` within 10 minutes; the first is refused), **404 flood** (more than 20 "not found" pages in a minute; missing images and search engine crawlers don't count) and **rate limiting**. Logged-in administrators are never banned by these. For IPv6, bans and lockouts apply to the whole /64 network. Automatic bans and lockouts last at most 24 hours. Requests caused by another site's page need more probes or 404s before anything is banned, and then only those cross-site requests are refused.

**No PHP in uploads** adds a marked `# BEGIN WP Bouncer` block to `wp-content/uploads/.htaccess`; anything else in that file is left alone. Straight after writing it, the plugin checks that files in uploads still load. Some hosts don't allow this kind of rule in `.htaccess` and answer every upload, images included, with an error; there the block is taken out again and the Bouncer screens say so. It also refuses uploads that are scripts in disguise, such as `photo.php.jpg` or an "image" containing PHP code.

**JSON request bodies** are checked like form fields, for visitors who aren't logged in and for users who can't edit posts. Users who can edit posts are not checked, because their saves send HTML and code as JSON; that means a valid REST nonce with a login cookie, or valid application-password credentials on a REST or XML-RPC request. A body that is too large (1 MB for visitors who aren't logged in, 8 MB for logged-in users, both capped by the server's post size limit), nested more than 512 levels, or has more than 5,000 fields is refused with a 403, because it can't be checked. Turn the check off with **Also inspect JSON request bodies** on the Rules tab. Developers can raise the limits with the `wp_bouncer_waf_json_max_bytes` and `wp_bouncer_waf_json_max_fields` filters.

Blocked visitors get a short "403 Forbidden" page with your block message, or "429 Too Many Requests" from rate limiting. A locked-out login shows "Too many failed login attempts, try again in N minutes".

Refresh the geo database about once a month (**Tools → Import**), because IP address allocations change.

---

## Updates

From version 1.1.0, new releases arrive like any other plugin update:

- **See that there's an update.** When a new version is published on GitHub, the Plugins screen and **Dashboard → Updates** show "There is a new version of WP Bouncer available". This can take up to 12 hours; **Dashboard → Updates → Check again** checks straight away. **View version … details** shows what changed.
- **Update when you choose.** Click **Update now** on the Plugins screen, or tick it on **Dashboard → Updates**. Settings, the log and the geo database are kept.
- **Or update automatically.** Click **Enable auto-updates** next to WP Bouncer on the Plugins screen. WordPress then installs new versions by itself, a few hours after they're published, and emails the site admin.

Updates come only from this repository's GitHub releases. Before installing, the plugin checks that the download's SHA-256 matches the one published with the release. If it doesn't match, the update is refused and the installed version keeps running.

The check fetches a small file (`update.json`) from GitHub a few times a day. It sends nothing about your site or visitors. To switch it off, add `define( 'WP_BOUNCER_DISABLE_UPDATES', true );` to `wp-config.php` and update by uploading zips yourself.

**Tools → Updates** shows the installed version, whether a newer one exists, and a **Check for updates now** button.

Forks and test setups that point updates at another server with the `wp_bouncer_update_manifest_url` or `wp_bouncer_update_package_prefix` filters must also define `WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS` as `true` in `wp-config.php`. Without it the filters are ignored, and updates come only from this repository's releases.

---

## Upgrading to 1.2.0

The full notes are in [documentation/CHANGELOG.md](documentation/CHANGELOG.md). The points that need action:

- **Requirements.** PHP 8.3 and WordPress 7.0 are now the minimum. A site below them isn't offered 1.2.0, and stays on its current version. Upgrade PHP and WordPress first.
- **Database upgrade (schema 3).** The first request after the update creates the login-counter table `{prefix}bouncer_counters` and adds a `user_id` index to the traffic log. On a large traffic log, update on a quiet day, and take a backup first.
- **Older log rows are redacted.** The first slice runs during the update request; the rest runs from cron, a minute later, in short slices. Secret values in URLs are replaced with `[removed]`, and usernames of accounts that don't exist are removed from lockout reasons. Rows aren't deleted, and the removed text can't be recovered.
- **Bans last at most 24 hours.** Bans placed before the update keep their length, but temporary IPv6 bans reset, because their keys now cover the whole /64 network.
- **Logins from another site are refused.** Headless front ends and apps on another domain must be allowed with the `wp_bouncer_login_allowed_origins` filter (see "A headless front end or app can't log in" under If something goes wrong).
- **WAF JSON inspection is new and on.** For a day or two, check the Activity Log for "WAF JSON" entries from legitimate senders.
- **Behind a proxy or CDN**, list its addresses under **General → Trusted proxies**. Until you do, bans and lockouts are suspended, and an admin notice explains the fix.
- **Email alerts for firewall changes** are on by default. Lowering the log retention sends one too.

## If something goes wrong

### You (or your visitors) are being blocked and you can still get into wp-admin

1. Open **Activity Log** and find the entry. It names the rule that blocked the request and why.
2. Then fix the cause:
   - **Switch that rule off** on the Dashboard, or adjust its settings on the Rules tab.
   - **Add the IP to the allowlist** (General).
   - For a login lockout, or a rate-limit, probe or 404-flood ban: **Tools → Unlock an IP**.
   - Nothing makes sense? Set **Mode → Monitor** while you investigate. Nothing is blocked in monitor mode.

### You can't get in at all: the emergency switch

This turns off **all** blocking, including login lockouts, while leaving the plugin's settings screens working so you can fix things.

1. Open `wp-config.php` in the root folder of your WordPress site. Use your host's file manager, FTP/SFTP, or SSH.
2. Add this line **above** the line that says `/* That's all, stop editing! */`:

   ```php
   define( 'WP_BOUNCER_DISABLE', true );
   ```

3. Save, then log in to wp-admin. A red notice confirms the plugin is switched off. WP Bouncer's block in `wp-content/uploads/.htaccess` is removed on the next page load and comes back when you remove the line. Email alerts keep working.
4. Fix the setting that caught you (see the section above). Usually you add your IP to the allowlist, correct **Client IP source**, or switch off the rule.
5. **Remove the line from `wp-config.php`.** Until you do, your site has no protection from WP Bouncer.

### Turning the plugin off completely

Use any one of these:

- **wp-admin:** **Plugins → WP Bouncer → Deactivate**.
- **No wp-admin access:** rename the folder `wp-content/plugins/wp-bouncer` to `wp-bouncer.off` with your file manager or FTP. WordPress deactivates a plugin whose folder has gone. Rename it back and reactivate it when you're ready.
- **SSH with WP-CLI:** run `wp plugin deactivate wp-bouncer`. WP-CLI is never blocked by the plugin.

Deactivating keeps your settings and log, and removes WP Bouncer's block from `wp-content/uploads/.htaccess`. Deactivating it from wp-admin or WP-CLI also sends an alert email, so an intruder can't switch it off quietly. **Deleting** the plugin from the Plugins screen removes everything: its tables, settings, lockouts, the uploads block and scheduled tasks.

### Something that used to work in the uploads folder stopped

A few plugins wrongly run PHP files from `wp-content/uploads`. If one breaks after you install WP Bouncer, the Activity Log won't show it (the web server refuses those requests, not WordPress). Untick **Rules → No PHP in uploads → Tell the web server not to run scripts in the uploads folder** and save; the block is removed straight away. Consider replacing that plugin.

### Alert emails don't arrive

Use **General → Email alerts → Send a test email**. If it fails or never arrives, WordPress on your host can't send mail; install an SMTP plugin. Alerts are also listed in the Activity Log (filter by action **Alert**), and at most 20 emails are sent per hour.

### The site got slower after switching on the traffic log

Each recorded request is one database write. On a busy site, tick **Skip logged-in administrators**, shorten the retention, or switch the log off on the Traffic tab; **Clear traffic log** empties it straight away.

### The whole site returns 403 for everyone

This is almost always IP detection. Every visitor appears to come from the same address, usually your proxy or CDN, and that address got blocked or rate-limited.
1. Use the emergency switch above.
2. Fix **General → Client IP source** and **Trusted proxies**, following the **IP detection** notice on the admin screens. WP Bouncer never bans a trusted proxy's address automatically, so a ban on it came from the blocklist or a rate limit before the fix.
3. Remove the proxy's address from the IP blocklist, or unlock it on the **Tools** tab.

### A webhook or API client gets a 403 when it sends JSON

Look in the Activity Log for a reason that starts with **WAF JSON** (for example "WAF JSON has too many fields"). That means the body was too large, too deeply nested or had too many fields to check, so it was refused. A reason such as `WAF sqli (union select) in JSON field "title"` means a signature matched. For a webhook that sends large JSON without logging in, add a mu-plugin that raises the limit for visitors who aren't logged in:

```php
add_filter( 'wp_bouncer_waf_json_max_bytes', function ( int $max, bool $logged_in ): int {
	return $logged_in ? $max : 4194304; // 4 MB for visitors who aren't logged in.
}, 10, 2 );
```

The filter has no route information, so the higher limit applies to every anonymous visitor. Keep it no higher than the webhook needs. The other option is to untick **Also inspect JSON request bodies** on the Rules tab, which turns the JSON check off for everyone.

### An update went wrong

If the site breaks after an update, use the emergency switch or rename the plugin folder (above) to get back in. Then install the previous version: download its zip from the repository's **Releases** page and upload it under **Plugins → Add New Plugin → Upload Plugin**, choosing **Replace current with uploaded**. Turn off auto-updates for WP Bouncer until a fixed version is out.

### A headless front end or app can't log in

Logins that the browser says another site started are refused, and so are REST requests that send application-password credentials from another site. The Activity Log shows "Login post from another site refused" or "Application-password request from another site refused". If the other site is yours, add its origin, such as `https://app.example.com`, with the `wp_bouncer_login_allowed_origins` filter in a plugin or mu-plugin:

```php
add_filter( 'wp_bouncer_login_allowed_origins', function ( array $origins ): array {
	$origins[] = 'https://app.example.com';
	return $origins;
} );
```

This needs the login lockout rule switched on. Monitor mode doesn't refuse these logins.

### Geo import fails or stops

The import runs in short steps, so it works on hosts with strict time limits. If it stops with an error, click **Retry**. If you leave the page, the import carries on the next time you open **Tools**. Uploads must fit the server's upload limit, which the Tools tab shows. Upload the `.csv.gz` file (about 5 MB) rather than the unpacked `.csv`, or use the URL option.

---

## Known limitations

These are the limits the team has accepted or documented for 1.2.0, in plain terms. None is a known exploit. Each is a place where WP Bouncer doesn't stop everything.

- **Updates aren't signed yet.** The update check compares each download with the SHA-256 published in the same GitHub release. That catches a corrupted or swapped download, but not someone who can publish a release in this repository. Release signing is deferred.
- **The WAF checks parameters, not everything.** It inspects query strings, form fields and JSON bodies, but not JSON bodies from users who can edit posts (see above). It doesn't inspect cookies, most request headers or raw XML and text bodies. A large signed JSON webhook sent without a login cookie may hit the size limits and need the filters raised. It doesn't look past the first layer of URL encoding, or into the middle of values over 64 KB. Keep WordPress and your plugins up to date; that is the main defence.
- **Some XML-RPC requests are refused that needn't be.** In "block abuse" mode, any XML-RPC body with a DOCTYPE or ENTITY declaration is refused, even inside CDATA.
- **Shared addresses share limits.** Visitors behind one address (a mobile carrier, an office, a CGNAT network) share counters and bans, so one abuser can affect the others. IPv6 clients are counted per /64 network for logins, rate limits, sensitive-file and 404 counts and bans, so everyone on one /64 shares those limits. Attempts from one /48 are capped at 8 times the per-/64 login limit, so a busy /48 can still leave its neighbours with few login attempts.
- **A proxy that forwards no header hides its visitors.** If a proxy on the same server passes no forwarding header, its visitors look like local requests, and local requests are not checked. List the proxy under Trusted proxies and have it send the header.
- **Forged headers can avoid some bans.** A scanner that fakes `Sec-Fetch-Site: cross-site` avoids probe and 404 bans, but each of its requests is still refused. Forged cross-site headers gain nothing at login. Old browsers that send no Fetch Metadata headers can still be used to get a visitor banned through third-party content.
- **Other security plugins may count refused logins.** WordPress still reports them as failed logins.
- **The lost-password form can reveal accounts.** WordPress adds its own "invalid combination" message after the generic error, so the form can still show whether an account exists.
- **On multisite, sub-site admins can still upload geo CSV files** (within the size cap). Only URL imports, the uploads setting and regex User-Agent patterns are restricted to network admins.

## For developers

```bash
make            # build builds/wp-bouncer-<version>.zip
make manifest   # also write builds/update.json (needs PHP)
make test       # unit tests (needs PHP and `composer install`)
make integration  # WordPress integration tests on MySQL/MariaDB (set WPB_TESTS_DB_* first)
make e2e        # end-to-end tests in a throwaway WordPress
make check      # unit tests + build + end-to-end tests against the built zip
make clean      # delete builds/
```

To publish a release, bump the version, add a changelog entry, then push a tag named `v<version>` (for example `git tag v1.2.0 && git push origin v1.2.0`). GitHub Actions tests it, builds it and publishes the release that installed sites update from. See the developer guide for the details.

Start with [documentation/developer-guide.md](documentation/developer-guide.md). It covers the code layout, how to build and test, and links to the architecture, rules, geolocation and testing guides. Changes are listed in [documentation/CHANGELOG.md](documentation/CHANGELOG.md).

## Licence

GPL-2.0-or-later; see [wp-bouncer/LICENSE](wp-bouncer/LICENSE). If you use the DB-IP Lite geo database, its CC BY 4.0 licence requires attribution to DB-IP.
