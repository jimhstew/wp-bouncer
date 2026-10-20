# WP Bouncer

A self-contained firewall for WordPress. Like a bouncer at a club door, it checks every visitor before WordPress does any real work and turns away the ones that don't belong:

- known-bad IP addresses and ranges
- visitors from countries you choose
- attack tools and blank user-agents
- password guessers (failed-login lockouts)
- XML-RPC abuse
- request floods (rate limiting)
- SQL injection, cross-site scripting and similar attacks (a small web application firewall)
- username harvesting

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

This creates `builds/wp-bouncer-1.0.1.zip`, with a `.sha256` checksum next to it. The zip contains only the `wp-bouncer/` folder: no tests and no documentation.

### 2. Upload it to WordPress

1. In wp-admin go to **Plugins → Add New Plugin → Upload Plugin**.
2. Choose the zip, click **Install Now**, then **Activate**.

From version 1.1.0 on, the plugin updates itself like any other plugin (see [Updates](#updates)). To upgrade an older copy, upload the newer zip the same way. WordPress asks whether to replace the installed version; choose **Replace current with uploaded**. Your settings and log are kept.

Without the upload screen, unzip it on your computer and copy the `wp-bouncer` folder into `wp-content/plugins/` on the server (by FTP, SFTP or your host's file manager). Then activate it under **Plugins**.

Requirements: WordPress 5.8 or newer, PHP 7.4 or newer, and MySQL/MariaDB (or SQLite).

---

## First-time setup (5 minutes)

A new **Bouncer** item appears in the wp-admin menu. Most protection is on from the moment you activate. Before relying on it, do the following:

1. **Bouncer → General → "Your IP as currently detected".** Check that this is your real public IP (search "what is my IP" to compare).
   - If it shows something else, such as your host's proxy, Cloudflare, or 127.0.0.1, your site is behind a proxy or CDN. Set **Client IP source** to match (Cloudflare: `CF-Connecting-IP`) and list the proxy's addresses under **Trusted proxies**.
   - This matters. If it's wrong, every visitor looks like the same IP, and blocking one would block everybody.
2. **Add yourself to the Allowlist** (General tab, **Add my IP** button). IPs on the allowlist skip every rule, so you can't lock yourself out.
3. **Optional: try Monitor mode first.** In General, set **Mode** to **Monitor**. Matching requests are logged but not blocked. After a few days, look at the **Activity Log**. If nothing legitimate shows up there, switch back to **Enforce**.
4. **Country blocking (optional).** This is off until you set it up:
   1. **Tools → Geo database → Import.** The form is pre-filled with this month's free DB-IP file. Keep the page open while the progress bar runs, usually one to three minutes.
   2. **Countries tab:** tick the countries to block, or choose "allow only these countries". Choose whether to apply it site-wide or only to the login pages. Then switch the rule on.
   3. The DB-IP licence asks for a credit somewhere on your site, such as "IP Geolocation by DB-IP" linking to https://db-ip.com.

---

## Using it

| Tab | What you do there |
|---|---|
| **Dashboard** | Blocks in the last 24 hours, 7 days and 30 days, a 14-day chart, the top rules, IPs and countries, and an on/off switch for every rule. |
| **General** | Enforce or monitor mode, IP detection and trusted proxies, the allowlist, how long to keep the log, and the message blocked visitors see. |
| **Rules** | Each blocking rule, with its own on/off switch and settings: IP blocklist, user-agent filter, XML-RPC, login lockout, rate limiting, web application firewall, user enumeration. |
| **Countries** | Pick countries from the list of 249, grouped by continent and searchable. |
| **Activity Log** | Everything that was blocked or would have been (in monitor mode): when, which IP and country, which rule and why. Filter, search, export to CSV, or **Block IP** from any row. |
| **Tools** | Import or refresh the geo database, unlock an IP that is locked out or rate-limited, and the emergency instructions below. |

Out of the box every rule is on except **country blocking** and **rate limiting**, which need setting up first.

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

---

## If something goes wrong

### You (or your visitors) are being blocked and you can still get into wp-admin

1. Open **Activity Log** and find the entry. It names the rule that blocked the request and why.
2. Then fix the cause:
   - **Switch that rule off** on the Dashboard, or adjust its settings on the Rules tab.
   - **Add the IP to the allowlist** (General).
   - For a login lockout or rate-limit ban: **Tools → Unlock an IP**.
   - Nothing makes sense? Set **Mode → Monitor** while you investigate. Nothing is blocked in monitor mode.

### You can't get in at all: the emergency switch

This turns off **all** blocking, including login lockouts, while leaving the plugin's settings screens working so you can fix things.

1. Open `wp-config.php` in the root folder of your WordPress site. Use your host's file manager, FTP/SFTP, or SSH.
2. Add this line **above** the line that says `/* That's all, stop editing! */`:

   ```php
   define( 'WP_BOUNCER_DISABLE', true );
   ```

3. Save, then log in to wp-admin. A red notice confirms the plugin is switched off.
4. Fix the setting that caught you (see the section above). Usually you add your IP to the allowlist, correct **Client IP source**, or switch off the rule.
5. **Remove the line from `wp-config.php`.** Until you do, your site has no protection from WP Bouncer.

### Turning the plugin off completely

Use any one of these:

- **wp-admin:** **Plugins → WP Bouncer → Deactivate**.
- **No wp-admin access:** rename the folder `wp-content/plugins/wp-bouncer` to `wp-bouncer.off` with your file manager or FTP. WordPress deactivates a plugin whose folder has gone. Rename it back and reactivate it when you're ready.
- **SSH with WP-CLI:** run `wp plugin deactivate wp-bouncer`. WP-CLI is never blocked by the plugin.

Deactivating keeps your settings and log. **Deleting** the plugin from the Plugins screen removes everything: its tables, settings, lockouts and scheduled tasks.

### The whole site returns 403 for everyone

This is almost always IP detection. Every visitor appears to come from the same address, usually your proxy or CDN, and that address got blocked or rate-limited.
1. Use the emergency switch above.
2. Fix **General → Client IP source** and **Trusted proxies**.
3. Remove the proxy's address from the IP blocklist, or unlock it on the **Tools** tab.

### An update went wrong

If the site breaks after an update, use the emergency switch or rename the plugin folder (above) to get back in. Then install the previous version: download its zip from the repository's **Releases** page and upload it under **Plugins → Add New Plugin → Upload Plugin**, choosing **Replace current with uploaded**. Turn off auto-updates for WP Bouncer until a fixed version is out.

### Geo import fails or stops

The import runs in short steps, so it works on hosts with strict time limits. If it stops with an error, click **Retry**. If you leave the page, the import carries on the next time you open **Tools**. Uploads must fit the server's upload limit, which the Tools tab shows. Upload the `.csv.gz` file (about 5 MB) rather than the unpacked `.csv`, or use the URL option.

---

## For developers

```bash
make            # build builds/wp-bouncer-<version>.zip
make manifest   # also write builds/update.json (needs PHP)
make test       # unit tests (needs PHP and `composer install`)
make e2e        # end-to-end tests in a throwaway WordPress
make check      # unit tests + build + end-to-end tests against the built zip
make clean      # delete builds/
```

To publish a release, bump the version, add a changelog entry, then push a tag such as `git tag v1.1.1 && git push origin v1.1.1`. GitHub Actions tests it, builds it and publishes the release that installed sites update from. See the developer guide for the details.

Start with [documentation/developer-guide.md](documentation/developer-guide.md). It covers the code layout, how to build and test, and links to the architecture, rules, geolocation and testing guides. Changes are listed in [documentation/CHANGELOG.md](documentation/CHANGELOG.md).

## Licence

GPL-2.0-or-later; see [wp-bouncer/LICENSE](wp-bouncer/LICENSE). If you use the DB-IP Lite geo database, its CC BY 4.0 licence requires attribution to DB-IP.
