=== WP Bouncer ===
Contributors: wpbouncer
Tags: firewall, security, brute force, country blocking, waf
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.0
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

You also get an Activity Log of everything refused (searchable, filterable, CSV export, one-click "Block IP"), a dashboard with 24-hour, 7-day and 30-day stats, a monitor (log-only) mode for trying rules safely, an allowlist, and proxy/CDN-aware IP detection.

Country lookups are done locally against a free database you import (DB-IP Lite or IP2Location LITE), or read from your CDN's country header. No visitor data leaves your server.

== Installation ==

1. Upload the `wp-bouncer` folder to `/wp-content/plugins/` and activate it.
2. Go to **Bouncer → General** and check that "Your IP as currently detected" is correct. If you're behind a proxy or CDN, set the IP source and trusted proxies.
3. Optionally switch to Monitor mode for a few days and review the Activity Log.
4. For country blocking, import a geo database under **Bouncer → Tools**, then pick countries on the **Countries** tab.

== Frequently Asked Questions ==

= I locked myself out =

Add `define( 'WP_BOUNCER_DISABLE', true );` to wp-config.php, log in, fix the settings, and remove the line. Or rename the plugin folder over FTP/SSH.

= Does it phone home? =

It sends nothing about your site or visitors. It makes two kinds of outbound request: the geo database download, only when you click Import with a URL, and an update check, a few times a day, that fetches a small update.json from the plugin's GitHub releases. The update check sends no site URL. Add `define( 'WP_BOUNCER_DISABLE_UPDATES', true );` to wp-config.php to switch it off; you can then update by uploading new zips yourself.

= Does it replace Wordfence? =

It replaces the firewall, brute-force, country-blocking and rate-limiting parts. It has no malware scanner, no two-factor authentication and no cloud threat feed.

== Changelog ==

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
