# WP Bouncer: WordPress Plugin Dev Team

Stack: PHP, WordPress, MySQL/MariaDB. The main Claude session acts as team
lead and delegates to subagents in `.claude/agents/`. Subagents cannot spawn
other subagents and do not share memory, so hand off work through files.

## Repository layout
- `wp-bouncer/`: the plugin. Only this folder ships in the zip.
  - `wp-bouncer.php` (header, version), `readme.txt`, `uninstall.php`
  - `src/`: namespaced classes (`WPBouncer\`), loaded by `src/Autoloader.php`.
    Composer is for development tools only; the plugin ships no vendor code.
  - `src/Plugin.php` is the composition root. Rules extend
    `Rules/AbstractRule`. Pure-PHP classes (no WordPress calls) sit next to
    thin WordPress-facing adapters so the core is unit-testable.
- `tests/`: `Unit/` (PHPUnit, mirrors `src/`), `Support/` (hand-written
  test doubles), `e2e/run.sh` (real WordPress on SQLite), `fixtures/`.
- `documentation/`: architecture, rules, developer guide, testing,
  geolocation, adding-a-rule, `CHANGELOG.md`.
- `scripts/`: release manifest builder. `builds/`: zips (git-ignored).
- `README.md` at the root; `wp-bouncer/readme.txt` in WordPress.org format.

## Project conventions
- Minimum versions: PHP 8.3, WordPress 7.0 (plugin header, readme.txt,
  phpcs.xml.dist, composer.json). No newer syntax or APIs. `%i` identifier
  placeholders in `$wpdb->prepare()` are allowed (WP 6.2+).
- Follow WordPress Coding Standards (`make lint`). Prefix globals, hooks,
  options, transients, cron hooks and handles with `wp_bouncer` / `wpb_`.
  Custom tables are `{$wpdb->prefix}bouncer_*`, versioned by
  `Installer::DB_VERSION`.
- SQL must work on both MySQL and MariaDB (and on SQLite, which the e2e
  suite uses). Always use `$wpdb->prepare()`.
- Keep the firewall fast: it runs on every request at `plugins_loaded`
  priority 1.
- Bump the version in `wp-bouncer.php` (header and `Plugin::VERSION`),
  `readme.txt` (Stable tag) and `documentation/CHANGELOG.md` together.
- Only run code against local/test sites and databases. Never touch
  production sites or hosting accounts.
- DANGER: never run a plugin update or `wp plugin uninstall` on a test site
  where `plugins/wp-bouncer` is a symlink to this repo's `wp-bouncer/`
  folder. WordPress deletes the installed folder, which deletes the source.

## Commands
| Command | What it does |
|---|---|
| `make test` | Unit tests (PHPUnit, no WordPress, < 1 s) |
| `make analyse` | PHPStan level 6 with WordPress stubs |
| `make lint` | phpcs with the WordPress ruleset |
| `make integration` | WordPress integration tests on MySQL/MariaDB (`WPB_TESTS_DB_*` env vars) |
| `make e2e` | End-to-end suite against the source folder |
| `make check` | Unit tests, build the zip, e2e against the zip |
| `make build` / `make manifest` | Zip (+ sha256), and update.json + release notes |

## Handoff files
- `documentation/backlog.md`: product-manager
- `documentation/architecture/`: architect and data-engineer designs
  (`documentation/architecture.md` is the overall design)
- `documentation/security/`: security-blue guidance, security-red findings
- `documentation/adr/`: decisions
- `tests/`: tester
- `README.md`, `wp-bouncer/readme.txt`, `documentation/*.md`
  (including `CHANGELOG.md`): docs-writer

## Team
| Agent | Role |
|---|---|
| product-manager | Requirements, user stories, prioritization |
| architect | Layered design |
| security-blue | Defensive advice to the architect |
| data-engineer | Schema, migrations, storage and caching |
| developer | Implementation |
| tester | Unit, e2e, static analysis |
| code-reviewer | Pre-merge review |
| security-red | Attacker-mindset audit (read-only) |
| debugger | Root-cause analysis and minimal fixes |
| devops | Dev environment, CI/CD, packaging |
| docs-writer | README, readme.txt, documentation/, changelog |

## Workflows

**New feature**
1. product-manager: story + acceptance criteria in `documentation/backlog.md`
2. security-blue: threat model and recommendations in `documentation/security/`
3. architect: design in `documentation/architecture/`, adopting or declining
   each security recommendation
4. data-engineer: schema/migration design if the feature stores data
5. developer: implement
6. tester: write and run tests (unit + e2e; MySQL/MariaDB when possible)
7. code-reviewer and security-red: run in parallel on the diff
8. developer/debugger: fix blocking findings, then tester re-runs
9. docs-writer: update docs and changelog
10. devops: confirm CI and packaging still pass (`make check`)

**Bug fix**
1. product-manager: triage severity
2. debugger: reproduce, fix, add regression test
3. code-reviewer (and security-red if security-related)
4. docs-writer: changelog entry

**Release**
1. product-manager: confirm scope and version
2. tester: `make test`, `make analyse`, `make check`
3. security-red: final audit of changes since last release
4. docs-writer: readme.txt, changelog, version consistency
5. devops: build the zip and validate it. Releases go out through GitHub:
   pushing a `v<version>` tag runs `.github/workflows/release.yml`, which
   publishes the zip and update.json that installed sites update from. The
   human decides when to commit, push and tag.

Loop steps 6 to 8 until reviewer, tester, and security-red have no blocking
findings. Run independent agents in parallel.
