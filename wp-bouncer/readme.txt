=== WP Bouncer ===
Contributors: wpbouncer
Tags: firewall, security, brute force, country blocking, waf
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.2.1
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A self-contained firewall that turns away unwanted visitors at the door. No cloud service, no account, no subscription.

== Description ==

WP Bouncer checks every request before WordPress does any real work and refuses the ones that don't belong. Every rule can be switched on or off on its own:

* **IP blocklist**: IPv4/IPv6 addresses and CIDR ranges.
* **User-Agent filter**: known attack tools, empty User-Agents, your own patterns.
* **Country blocking**: block chosen countries or allow only chosen countries, site-wide or only on login. Pick from all 249 countries, grouped by continent.
* **XML-RPC blocking**: all of it, or just multicall password spraying and pingback abuse.
* **Login lockout**: lock out IPs after repeated failures, lock out instantly on usernames like "admin", hide whether a username exists.
* **Rate limiting**: temporarily ban IPs that hammer the site.
* **Web application firewall**: SQL injection, XSS, path traversal and code injection signatures, in URLs, form fields and JSON request bodies. Users who can edit posts are not checked for JSON.
* **User enumeration**: stops ?author=N scans, the REST user list and the users sitemap for anonymous visitors.
* **Sensitive-file probes**: bans IPs that look for .env, .git, wp-config backups, database dumps, logs, phpinfo pages and web shells.
* **404 flood**: bans IPs that hit many "not found" pages, as vulnerability scanners do. Missing images and search engine crawlers don't count.
* **No PHP in uploads**: tells the web server not to run scripts from wp-content/uploads, and refuses uploads that are scripts in disguise. A "Test now" button checks what your server really does.

**Traffic log** (optional): every request that reaches WordPress, with IP, client type, URL, response code, referrer and User-Agent, kept for 1 to 7 days. Filter, search, export to CSV, block an IP from any row. Secrets such as password-reset keys are removed from URLs before saving.

**Email alerts** tell you when an administrator account is created or promoted, or a plugin is installed, activated, deactivated or deleted, the usual signs that someone else has got in. Changes to the firewall's own settings are emailed too.

**Administrator logins**: every successful login by an administrator is recorded in the Activity Log, with the user, IP address, country, time and login method. You are emailed when an administrator logs in from a country or network (IPv4 /24, IPv6 /64) not seen for that account in the last 90 days. Both can be switched off on the General tab.

**Site health**: the Dashboard tab and Site Health show whether your PHP and database versions still get security fixes, and flag PHP and WordPress settings that weaken security.

**Privacy**: the WordPress Export and Erase Personal Data tools cover the traffic log, the block log and administrator logins.

You also get an Activity Log of everything refused and every administrator login (searchable, filterable, CSV export, one-click "Block IP"), a dashboard with 24-hour, 7-day and 30-day stats, a WP Bouncer box on the WordPress Dashboard for administrators, a monitor (log-only) mode for trying rules safely, an allowlist, and proxy/CDN-aware IP detection.

Country lookups are done locally against a free database you import (DB-IP Lite or IP2Location LITE), or read from your CDN's country header. No visitor data leaves your server.

**Threat map**: the Activity Log shows where blocked requests and lockouts came from, on a world map and in a Top countries table, for the date range you pick. The map ignores the search box and the IP filter.

**Settings drift**: WP Bouncer notices when its own settings were changed while the plugin wasn't loaded (for example with `wp --skip-plugins` or in the database). It writes an Activity Log row and emails you, but it never reverts the change.

== Installation ==

1. Upload the `wp-bouncer` folder to `/wp-content/plugins/` and activate it.
2. Go to **Bouncer → General** and check that "Your IP as currently detected" is correct. If you're behind a proxy or CDN, set the IP source and list the proxy's addresses under trusted proxies (the **IP detection** notice on each admin screen helps with this).
3. Optionally switch to Monitor mode for a few days and review the Activity Log.
4. For country blocking, import a geo database under **Bouncer → Tools**, then pick countries on the **Countries** tab.
5. On a multisite network, network-activate WP Bouncer. Per-site activation can strip the uploads protection.

== Frequently Asked Questions ==

= I locked myself out =

Add `define( 'WP_BOUNCER_DISABLE', true );` to wp-config.php, log in, fix the settings, and remove the line. Or rename the plugin folder over FTP/SSH.

= Does it phone home? =

It sends nothing about your site or visitors. It makes two kinds of outbound request: the geo database download, only when you click Import with a URL, and an update check, a few times a day, that fetches a small update.json from the plugin's GitHub releases. The update check sends no site URL. Add `define( 'WP_BOUNCER_DISABLE_UPDATES', true );` to wp-config.php to switch it off; you can then update by uploading new zips yourself.

= Will the uploads protection break my site? =

It only adds a marked block to wp-content/uploads/.htaccess that refuses to run script files there; images and other uploads are unaffected, and anything else in that file is left alone. Right after writing it, the plugin checks that a file in uploads still loads; on a host that doesn't allow the rule and answers with errors, the block is taken out again and the Bouncer screens tell you. Untick it under Rules → No PHP in uploads to remove the block. It is also removed when WP Bouncer is deactivated or WP_BOUNCER_DISABLE is on. On nginx, which ignores .htaccess, the Rules tab shows the rule to add to your server config.

= Why does WP Bouncer show an IP detection notice? =

Your Client IP source is set to read a forwarding header (such as X-Forwarded-For or CF-Connecting-IP), but no trusted proxies are listed. Without a list, the header can't be trusted, so WP Bouncer uses the connection address instead and suspends bans and lockouts until you fix it. The notice offers buttons for the common cases:

* **I have no proxy: use the connection address** if nothing sits in front of your site.
* **Trust the address shown as my proxy** if the connection comes from a private or same-server proxy.
* For a public address (a CDN), list the CDN's full published IP ranges under General → Trusted proxies. Don't trust a single public address.

= I'm not getting alert emails =

Use **Send a test email** under Bouncer → General → Email alerts. If it doesn't arrive, your site can't send mail; many hosts need an SMTP plugin. Every alert is also written to the Activity Log.

= Can I log in from another site, such as a headless front end or an app? =

Not by default. A login that the browser says another site started is refused before the password is checked, and so is a REST request that sends application-password credentials from another site. Add the other site's origin (for example `https://app.example.com`) with the `wp_bouncer_login_allowed_origins` filter, from a plugin or mu-plugin. This needs the login lockout rule switched on.

= Why are my bans shorter now? =

Automatic bans and lockouts last at most 24 hours. Bans placed before the update keep their original length.

= Why was a JSON request blocked? =

Requests with JSON bodies are checked for attack patterns, like form fields, unless the sender can edit posts. A body is refused when it is too large (1 MB for visitors who aren't logged in, 8 MB for logged-in users, both capped by the server's post size limit), nested more than 512 levels, or has more than 5,000 fields. Look for "WAF JSON" in the Activity Log. For a webhook or integration that sends large JSON without logging in, raise the limits with the `wp_bouncer_waf_json_max_bytes` and `wp_bouncer_waf_json_max_fields` filters in a mu-plugin, or untick "Also inspect JSON request bodies" on the Rules tab.

= Does WP Bouncer hold personal data? =

It logs IP addresses, requested URLs, referrers and User-Agents: the Activity Log for blocked requests, and the Traffic log if you switch it on. Secret values in URLs are removed before saving. For each administrator, it also records successful logins (user name, IP address, approximate country, browser, time and login method) in the Activity Log, and keeps the IP ranges and countries each administrator logged in from for 90 days, to spot a new location. It stores ranges and countries, not full IP addresses, in that history. The WordPress Export and Erase Personal Data tools cover the traffic log by user account and the administrator-login history and rows. For the block log, erasing a user keeps the rows, but clears the URL and reason of rows that name that account. The privacy policy guide gets a suggested paragraph. Administrator logins can be switched off with "Record administrator logins" on the General tab.

= Does it replace Wordfence? =

It replaces the firewall, brute-force, country-blocking and rate-limiting parts. It has no malware scanner, no two-factor authentication and no cloud threat feed.

= Why is the threat map empty, or showing "Unknown location"? =

The map counts blocked requests and lockouts only, and needs a country for each entry. Import the geo database under Tools, or use a country header from your CDN. Entries with no known country are listed as unknown location and aren't drawn. Without a geo database and without a country header, the map isn't drawn at all.

= Does WP Bouncer notice settings changed outside WordPress? =

Only partly. After each change made with WP Bouncer loaded, it keeps a keyed fingerprint of its settings. A daily check, and a check on admin page loads by users who can manage WP Bouncer (at most once an hour), compares the settings with it. A difference, such as a change made with `wp --skip-plugins` or in the database, writes one Activity Log row and sends the firewall-change email. The row says when it was found, not when it was made, and shows only the setting names. The email is sent even with alerts off when the alert, mode or admin-email settings changed, or when the fingerprint can't be trusted. The settings found then become the new baseline.

Limits, in plain words:

* It only detects. It never reverts a change.
* Anyone who can read wp-config.php or run code on the server can defeat it.
* It needs real security keys (salts) in wp-config.php. If they are missing or still the placeholder, WordPress keeps them in the database, and the check adds nothing.
* Someone who can write the database but not wp-config.php can't forge a matching record. They can delete the record and the baseline, though, and the next check starts over silently.
* Restoring an older settings-and-fingerprint pair is not detected.
* Once the fingerprint is broken, the attacker chooses who gets the email, because the addresses are in the database. To keep an independent copy, send the `wp_bouncer_settings_drift` action to your own log or SIEM.
* Removing WP Bouncer from active_plugins is not detected.
* Detection can take up to a day: the daily cron, or the next admin page load (at most hourly).
* A legitimate restore, import, staging copy or salt rotation is reported as drift, once.

== Credits ==

The threat map's base map and country positions come from Natural Earth 5.1.2 (https://github.com/nvkelso/natural-earth-vector), which is in the public domain. A few island positions come from the CIA World Factbook, also public domain.

== Changelog ==

= 1.2.1 =
* Security fix: settings changes made with WP-CLI or from code are now logged and alerted, as changes on the admin screen already were. Settings-change alerts are limited to 10 an hour, except changes that could silence alerts. Turning off any alert now sends an alert.
* New: drag the edge of a column heading to resize columns on the Activity Log and Traffic tab. Widths are kept in this browser.
* Rules tab categories are shown in columns on wide screens, and long Request and User-Agent values no longer overlap the next column.

= 1.2.0 =
* Minimum versions are now PHP 8.3 and WordPress 7.0.
* Upgrading creates a login-counter table and updates the traffic log's indexes. On a large traffic log this can take a while.
* Older log rows are redacted: secret values in URLs, and usernames of accounts that don't exist in lockout reasons. This runs in the background after the update.
* Bans and lockouts last at most 24 hours. Bans placed before the update keep their length.
* Logins from another site are refused. Headless apps and other sites must be added with the wp_bouncer_login_allowed_origins filter.
* A sensitive-file probe bans only on a second probe within 10 minutes. Probes and 404s caused by another site's page have their own, higher limits.
* Forwarding headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP and similar) are ignored unless the sender is a listed trusted proxy. With no trusted proxies listed, the connection address is used, an admin notice explains the fix, and bans and lockouts are suspended until you configure it.
* Private, loopback, link-local, carrier-grade NAT, unique-local and unspecified addresses are refused from a header. The opt-in constant WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS allows private client addresses from a trusted proxy on intranet sites.
* Loopback requests are exempt only when they carry no forwarding header. Loopback and trusted-proxy addresses are never banned.
* Over-broad trusted proxy and allowlist entries (wider than /8 for IPv4 or /16 for IPv6) are ignored and dropped on save.
* IPv6 addresses are counted per /64 network for logins, rate limits, sensitive-file and 404 limits, and bans (WP_BOUNCER_IPV6_PREFIX sets the width). Temporary IPv6 bans placed before the update reset.
* Security fix: update packages must come from the exact expected GitHub release URL. The update-source filters need WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS set to true in wp-config.php.
* New settings alert: firewall changes, the Activity Log being cleared, and a daily reminder while WP_BOUNCER_DISABLE is set. On by default.
* Settings changes are recorded in the Activity Log, naming the changed settings but not their values.
* New Site Health and Dashboard checks for PHP and database support dates and for PHP and WordPress settings with security effects.
* Privacy tools: traffic-log exporter and eraser, block-log eraser, and suggested privacy-policy text.
* Multisite: uninstall and network deactivation clean every site. Sub-site admins can't change the uploads setting, run URL geo imports, or add regex User-Agent patterns.
* Country header and server variables are read separately: a request header is believed only from a trusted proxy.
* Geo URL import accepts only https downloads from the vendor hosts.
* Saving settings that would block you is refused when your address is shared by a proxy or CDN.
* The WAF blocks a request when a built-in signature can't be checked, and inspects longer values in windows.
* New: the WAF checks JSON request bodies (on by default, also after an update). Visitors who aren't logged in, and users who can't edit posts, are checked. Bodies that are too large, too deeply nested or have too many fields are refused, and filters can raise the limits. Watch the log after updating.
* New: a WP Bouncer box on the WordPress Dashboard for administrators, with 24-hour and 7-day block counts, trends, and the top rules, IP addresses and countries.
* New: the Rules tab is grouped into categories, with flags for rules that need attention or need setting up first.
* New: Block /64 in the Activity Log blocks the whole IPv6 network of a row.

= 1.1.1 =
* New: Sensitive-file probes rule. Bans IPs that ask for .env, .git, wp-config backups, database dumps, logs, phpinfo pages, database tools and web shells.
* New: 404 flood rule. Bans IPs that get more than 20 "not found" pages in a minute.
* New: No PHP in uploads. Writes a block to wp-content/uploads/.htaccess (on update too) so scripts there can't run, refuses uploads that are scripts in disguise, and has a "Test now" button.
* New: email alerts for new or promoted administrators and for plugins being installed, activated, deactivated or deleted. Optional alerts for plugin updates. "Send a test email" button.
* New: Traffic tab, an optional log of every request that reaches WordPress (IP, client type, URL, response code, referrer, User-Agent, user), kept 1 to 7 days and purged hourly. Off by default.
* The three new rules and alerts are on by default, including on sites updating from 1.1.0. Each can be switched off on the Dashboard or Rules tab.

= 1.1.0 =
* New: updates from GitHub releases appear on the Plugins screen like any other plugin, with Update now, View details and auto-updates. Each download is checked against a published SHA-256 before it is installed.
* New: Updates card on the Tools tab.

= 1.0.1 =
* Fix: importing a full geo database (upload or URL) failed with a server error on hosts that stop PHP after 30 seconds. The import now runs in short steps with a progress bar, and can be stopped.
* Files that aren't IP-to-country CSVs are now refused before the current data is replaced.
* Clear messages for uploads over the server's size limit.
* Fix: the WP_BOUNCER_DISABLE emergency switch now also lifts login lockouts. A notice shows while it is on.
* The plugin package no longer contains test files.

= 1.0.0 =
* First release.

== Upgrade Notice ==

= 1.2.1 =
Security fix: settings changes from WP-CLI or code are now logged and alerted. Adds resizable log columns.

= 1.2.0 =
Needs PHP 8.3 and WordPress 7.0, and runs a database upgrade. Bans and lockouts last at most 24 hours. Logins from other sites are refused unless allowed with a filter. Behind a proxy or CDN, list its addresses under Trusted proxies. Watch the log for WAF JSON blocks.
