=== WP Bouncer ===
Contributors: wpbouncer
Tags: firewall, security, brute force, country blocking, waf
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.2
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
* **Web application firewall**: SQL injection, XSS, path traversal and code injection signatures.
* **User enumeration**: stops ?author=N scans, the REST user list and the users sitemap for anonymous visitors.
* **Sensitive-file probes**: bans IPs that look for .env, .git, wp-config backups, database dumps, logs, phpinfo pages and web shells.
* **404 flood**: bans IPs that hit many "not found" pages, as vulnerability scanners do. Missing images and search engine crawlers don't count.
* **No PHP in uploads**: tells the web server not to run scripts from wp-content/uploads, and refuses uploads that are scripts in disguise. A "Test now" button checks what your server really does.

**Traffic log** (optional): every request that reaches WordPress, with IP, client type, URL, response code, referrer and User-Agent, kept for 1 to 7 days. Filter, search, export to CSV, block an IP from any row. Secrets such as password-reset keys are removed from URLs before saving.

**Email alerts** tell you when an administrator account is created or promoted, or a plugin is installed, activated, deactivated or deleted, the usual signs that someone else has got in.

You also get an Activity Log of everything refused (searchable, filterable, CSV export, one-click "Block IP"), a dashboard with 24-hour, 7-day and 30-day stats, a monitor (log-only) mode for trying rules safely, an allowlist, and proxy/CDN-aware IP detection.

Country lookups are done locally against a free database you import (DB-IP Lite or IP2Location LITE), or read from your CDN's country header. No visitor data leaves your server.

== Installation ==

1. Upload the `wp-bouncer` folder to `/wp-content/plugins/` and activate it.
2. Go to **Bouncer → General** and check that "Your IP as currently detected" is correct. If you're behind a proxy or CDN, set the IP source and list the proxy's addresses under trusted proxies (the **IP detection** notice on each admin screen helps with this).
3. Optionally switch to Monitor mode for a few days and review the Activity Log.
4. For country blocking, import a geo database under **Bouncer → Tools**, then pick countries on the **Countries** tab.

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

= Does it replace Wordfence? =

It replaces the firewall, brute-force, country-blocking and rate-limiting parts. It has no malware scanner, no two-factor authentication and no cloud threat feed.

== Changelog ==

= 1.1.2 =
* Security fix: a forwarding header (X-Forwarded-For, X-Real-IP, CF-Connecting-IP and similar) is ignored unless its sender is a listed trusted proxy. Without any trusted proxies, the connection address is used and an admin notice explains how to fix the setup. While this fallback is active, bans and lockouts are suspended; failed logins are still logged.
* Security fix: private, loopback, link-local, carrier-grade NAT, unique-local and unspecified addresses are refused when they come from a header. New opt-in constant WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS for intranet sites behind a proxy.
* Security fix: requests from loopback are exempt only when they carry no forwarding header. Loopback and trusted-proxy addresses are never banned.
* Security fix: update packages must come from the exact expected GitHub release URL.
* Over-broad trusted proxy and allowlist entries (wider than /8 for IPv4 or /16 for IPv6) are ignored and dropped on save, with a message naming them.
* Changed: the update-source filters are only honoured when WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS is true in wp-config.php. Forks and testers must add it.
* Changed: saving settings that would block you is refused, with a pointer to IP setup, when your address is shared by a proxy or CDN.
* Changed: release pipeline hardened (pinned actions and downloads, checksum verification, reproducible zip) and CI blocks on coding standards and PHPStan level 6.

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

= 1.1.2 =
Security fixes to IP detection. If your site is behind a proxy or CDN, check the IP detection notice on the admin screens and list your proxy or CDN addresses under General → Trusted proxies. Until you do, forwarded headers are ignored and bans and lockouts are suspended.
