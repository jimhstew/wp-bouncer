# Security policy

WP Bouncer is a firewall, so security problems in it matter more than in most plugins. Thank you for taking the time to report one responsibly.

## Supported versions

Security fixes are released as a new version of the plugin. Installed sites get them through the normal WordPress update screen.

| Version | Supported |
|---|---|
| Latest release (currently 1.2.x) | ✅ |
| Older minor versions | ❌: please update. Critical fixes may be backported to the previous minor version for 3 months after a new minor release. |
| Before 1.1.0 | ❌: these versions can't update themselves. Install the latest zip by hand. |

## Reporting a vulnerability

**Please don't report security problems in public issues, discussions or pull requests.**

- Use GitHub's private vulnerability reporting: open <https://github.com/jimhstew/wp-bouncer/security/advisories/new> (or the repository's **Security** tab → **Report a vulnerability**). Only the maintainers can see the report.

Please include:

- The affected version (from the Plugins screen, or `Version:` in `wp-bouncer.php`) and the WordPress and PHP versions.
- The relevant settings (for example the IP source and trusted proxies, monitor or enforce mode, which rules are on). Tell us whether the site is behind a CDN or reverse proxy, and whether it runs Apache or nginx.
- What an attacker can do, and what they need first (none / logged-in user / administrator / network position).
- Steps to reproduce, ideally a minimal HTTP request or script, and what you expected to happen.
- Whether you've told anyone else, and whether you'd like to be credited.

Please test only against sites you own or are allowed to test. Never test against other people's sites.

## What happens next

These are targets for a project with a single maintainer.

| Step | Target |
|---|---|
| Acknowledge your report | within 5 working days |
| First assessment (valid? severity?) | within 10 working days |
| Fix released: Critical / High | as soon as possible, aiming for 14 days |
| Fix released: Medium | within 60 days, or in the next release |
| Fix released: Low | in a future release |

We'll keep you updated, discuss the severity with you, and tell you before the fix is published.

## Disclosure policy

- We follow coordinated disclosure. Please give us a chance to fix the problem before you publish details. We aim to publish a GitHub Security Advisory together with the fixed release. We'll ask GitHub to assign a CVE where the issue warrants one.
- Release notes say a security issue was fixed and how serious it was. Full technical details go in the advisory, normally once sites have had a reasonable time to update (usually 14–30 days).
- If we don't respond within 30 days, or haven't fixed a confirmed issue within 90 days, you may publish. Please tell us first.
- We credit reporters in the advisory and the changelog unless you'd rather we didn't.
- We won't take legal action against good-faith research that follows this policy, stays within scope, avoids harming users and data, and gives us reasonable time to fix the issue.

## Scope

In scope: the plugin code in this repository (`wp-bouncer/`) and the way it's built and delivered (the release workflow, `update.json` and the update check). For example:

- Bypassing a protection that's switched on, in a configuration the documentation describes as safe
- Making the plugin refuse, lock out or ban someone else (another visitor, the site owner)
- Code execution, SQL injection, stored or reflected XSS, CSRF, privilege escalation, or reading data you shouldn't be able to
- Getting a site to install a tampered update
- Filling the database or disk in a way that the plugin's own limits should prevent
- Personal data stored or exposed against what the documentation says

Out of scope:

- Problems that need administrator rights or full control of the site (for example an admin entering a script in a field that only admins can see, or turning protections off). On multisite, issues where a sub-site administrator affects the network or the server *are* in scope.
- Self-XSS, or attacks that need the victim to paste something into their own browser console
- Configurations the plugin warns against (for example reading the IP from a proxy header with no trusted proxies listed). We still want to hear if the warning is missing or unclear.
- WAF evasion through request parts the documentation says aren't inspected (cookies, headers, JSON bodies), unless the bypass also defeats something that *is* inspected
- Volumetric denial of service, or brute-force attempts that the rate limit is designed to slow down rather than stop
- Vulnerabilities in WordPress core, PHP, the web server, the host or other plugins (report those to their maintainers). We do want to know if WP Bouncer makes one of them worse.
- Missing hardening headers on pages WP Bouncer doesn't produce
- Reports from automated scanners that don't show a real impact

## Verifying releases

Each release lists the SHA-256 of its zip, and installed sites check the downloaded zip against it before installing. This catches a corrupted or truncated download. It doesn't prove who published the release, because the hash is published in the same place as the zip. Signed releases are planned ([ADR 002](documentation/adr/002-update-signing.md)).
