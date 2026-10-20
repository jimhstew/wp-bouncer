#!/usr/bin/env bash
#
# End-to-end smoke test: installs a throwaway WordPress (SQLite, no MySQL needed),
# activates WP Bouncer, fires real HTTP requests at it and checks the responses.
#
# Usage:   tests/e2e/run.sh
# Options (environment variables):
#   PHP=/path/to/php      PHP binary (default: php on PATH). Needs pdo_sqlite.
#   WPB_E2E_DIR=/tmp/x    Work directory (default: a new temp dir, deleted afterwards).
#   WPB_E2E_PORT=8899     Port for PHP's built-in web server.
#   WPB_E2E_KEEP=1        Keep the work directory and server log for debugging.
#   WPB_E2E_ZIP=file.zip  Install the plugin from a built zip (make build) instead of
#                         linking the wp-bouncer/ source folder. Proves the package works.
#
# Requests come from 127.0.0.1, which the plugin always lets through, so the test
# switches the IP source to X-Real-IP and sends a different fake IP for each scenario.

set -uo pipefail

PHP=${PHP:-php}
PORT=${WPB_E2E_PORT:-8899}
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLUGIN_DIR="$REPO_DIR/wp-bouncer"
FIXTURES="$REPO_DIR/tests/fixtures"
WORK=${WPB_E2E_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/wpb-e2e.XXXXXX")}
U="http://127.0.0.1:${PORT}"
W="$WORK/wordpress"
WP="$PHP -d memory_limit=512M $WORK/wp-cli.phar --path=$W --quiet"

pass=0
fail=0
SERVER_PID=""
FILES_PID=""

cleanup() {
	for pid in $SERVER_PID $FILES_PID; do
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done
	if [ -z "${WPB_E2E_KEEP:-}" ] && [ -z "${WPB_E2E_DIR:-}" ]; then
		rm -rf "$WORK"
	else
		echo "Work directory kept: $WORK"
	fi
}
trap cleanup EXIT

check() { # check "description" expected actual
	if [ "$2" = "$3" ]; then
		pass=$((pass + 1)); printf '  \033[32mok\033[0m   %s\n' "$1"
	else
		fail=$((fail + 1)); printf '  \033[31mFAIL\033[0m %s (expected %s, got %s)\n' "$1" "$2" "$3"
	fi
}

status() { # status IP UA URL [curl args...]
	local ip=$1 ua=$2 url=$3; shift 3
	curl -s -o /dev/null -w '%{http_code}' -H "X-Real-IP: $ip" -A "$ua" "$@" "$url"
}

login() { # login IP USER PASS -> writes page to $WORK/login.html, prints status
	curl -s -o "$WORK/login.html" -w '%{http_code}' -H "X-Real-IP: $1" -A "Mozilla/5.0" \
		-b "wordpress_test_cookie=WP%20Cookie%20check" \
		-d "log=$2&pwd=$3&wp-submit=Log+In&testcookie=1" "$U/wp-login.php"
}

set_settings() { # set_settings 'PHP code that edits $s'
	$WP eval "\$s = get_option('wp_bouncer_settings'); $1; update_option('wp_bouncer_settings', \$s);"
}

echo "==> Setting up WordPress in $WORK"
mkdir -p "$WORK"
cd "$WORK" || exit 1
[ -f wp-cli.phar ] || curl -sfLO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar || { echo "download wp-cli failed"; exit 1; }
if [ ! -d "$W" ]; then
	curl -sfL https://wordpress.org/latest.tar.gz | tar xz || { echo "download WordPress failed"; exit 1; }
	curl -sfLo sqlite.zip https://downloads.wordpress.org/plugin/sqlite-database-integration.latest-stable.zip
	unzip -q sqlite.zip -d "$W/wp-content/plugins/"
	sed "s#{SQLITE_IMPLEMENTATION_FOLDER_PATH}#$W/wp-content/plugins/sqlite-database-integration#; s#{SQLITE_PLUGIN}#sqlite-database-integration/load.php#" \
		"$W/wp-content/plugins/sqlite-database-integration/db.copy" > "$W/wp-content/db.php"
	cat > "$W/wp-config.php" <<'EOF'
<?php
define( 'DB_NAME', 'wp' ); define( 'DB_USER', '' ); define( 'DB_PASSWORD', '' ); define( 'DB_HOST', '' );
define( 'DB_ENGINE', 'sqlite' );
$table_prefix = 'wp_';
define( 'WP_DEBUG', true ); define( 'WP_DEBUG_LOG', __DIR__ . '/debug.log' ); define( 'WP_DEBUG_DISPLAY', false );
define( 'DISABLE_WP_CRON', true );
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
EOF
fi
INSTALLED="$W/wp-content/plugins/wp-bouncer"
if [ -L "$INSTALLED" ]; then
	rm -f "$INSTALLED"            # a link to the source folder: remove the link only
elif [ -d "$INSTALLED" ]; then
	rm -rf "$INSTALLED"           # a copy unpacked from a zip on an earlier run
fi
if [ -n "${WPB_E2E_ZIP:-}" ]; then
	unzip -q "$WPB_E2E_ZIP" -d "$W/wp-content/plugins/" || { echo "unzip $WPB_E2E_ZIP failed"; exit 1; }
	echo "    (plugin installed from $WPB_E2E_ZIP)"
else
	ln -s "$PLUGIN_DIR" "$INSTALLED"
fi
$WP core is-installed 2>/dev/null || $WP core install --url="$U" --title=E2E --admin_user=admin_e2e --admin_password=e2e-pass-123 --admin_email=e2e@example.test --skip-email
# Pin the URLs: WP-CLI can otherwise record the directory name in siteurl.
$WP option update siteurl "$U"
$WP option update home "$U"
$WP plugin activate wp-bouncer
$WP eval '$d = WPBouncer\Settings::defaults(); $d["ip_source"] = "x_real_ip"; update_option("wp_bouncer_settings", $d); global $wpdb; $wpdb->query("DELETE FROM {$wpdb->prefix}bouncer_log"); $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE \"%transient%wpb\_%\"");'
rm -f "$W/debug.log"

# Typical shared-hosting limits, so anything that relies on one long request fails here too.
# display_errors is off as on a production host; PHP's own start-up warnings
# (such as "POST too large") would otherwise land in the page and break redirects.
"$PHP" -d max_execution_time=30 -d upload_max_filesize=2M -d post_max_size=8M -d display_errors=0 \
	-S "127.0.0.1:$PORT" -t "$W" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done

# A second server that stands in for download.db-ip.com in the import-by-URL test.
FILES="$WORK/geo-files"
mkdir -p "$FILES"
FILES_PORT=$((PORT + 1))
"$PHP" -S "127.0.0.1:$FILES_PORT" -t "$FILES" > "$WORK/files-server.log" 2>&1 &
FILES_PID=$!

MOZ="Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"

echo "==> Normal traffic"
check "home page"                    200 "$(status 203.0.113.10 "$MOZ" "$U/")"
check "search"                       200 "$(status 203.0.113.10 "$MOZ" "$U/?s=hello+world")"
check "REST posts endpoint"          200 "$(status 203.0.113.10 "$MOZ" "$U/?rest_route=/wp/v2/posts")"

echo "==> Bad visitors"
check "scanner User-Agent"           403 "$(status 203.0.113.21 "sqlmap/1.7" "$U/")"
check "empty User-Agent"             403 "$(status 203.0.113.22 "" "$U/")"
check "xmlrpc.php"                   403 "$(status 203.0.113.23 "$MOZ" "$U/xmlrpc.php")"
check "?author=1 scan"               403 "$(status 203.0.113.24 "$MOZ" "$U/?author=1")"
check "REST user listing"            403 "$(status 203.0.113.25 "$MOZ" "$U/?rest_route=/wp/v2/users")"
check "WAF: XSS"                     403 "$(status 203.0.113.26 "$MOZ" "$U/?s=%3Cscript%3Ealert(1)%3C/script%3E")"
check "WAF: SQL injection"           403 "$(status 203.0.113.27 "$MOZ" "$U/?id=1%27%20UNION%20SELECT%20user_pass%20FROM%20wp_users--")"
check "WAF: path traversal"          403 "$(status 203.0.113.28 "$MOZ" "$U/?file=../../../../etc/passwd")"
check "users sitemap removed"        404 "$(status 203.0.113.10 "$MOZ" "$U/?sitemap=users")"

echo "==> Brute-force protection"
for i in 1 2 3 4; do login 198.51.100.5 admin_e2e "wrong$i" > /dev/null; done
check "generic login error"          1 "$(grep -c 'username or password you entered is incorrect' "$WORK/login.html")"
check "5th failure still answered"   200 "$(login 198.51.100.5 admin_e2e wrong5)"
check "locked out after 5 failures"  403 "$(login 198.51.100.5 admin_e2e e2e-pass-123)"
login 198.51.100.6 admin x > /dev/null
check "banned username locks out"    403 "$(login 198.51.100.6 admin_e2e e2e-pass-123)"
check "other IPs can still log in"   302 "$(login 198.51.100.7 admin_e2e e2e-pass-123)"

echo "==> Emergency switch (WP_BOUNCER_DISABLE)"
# A must-use plugin loads before plugins, the same as a define in wp-config.php.
mkdir -p "$W/wp-content/mu-plugins"
echo "<?php define( 'WP_BOUNCER_DISABLE', true );" > "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
check "locked-out IP can log in"     302 "$(login 198.51.100.6 admin_e2e e2e-pass-123)"
check "scanner gets in"              200 "$(status 203.0.113.41 "sqlmap/1.7" "$U/")"
check "xmlrpc.php reachable"         1   "$( [ "$(status 203.0.113.42 "$MOZ" "$U/xmlrpc.php")" != 403 ] && echo 1 || echo 0 )"
rm -f "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
check "switch removed: locked again" 403 "$(login 198.51.100.6 admin_e2e e2e-pass-123)"
check "switch removed: scanner out"  403 "$(status 203.0.113.43 "sqlmap/1.7" "$U/")"
$WP eval '(new WPBouncer\Login\LoginGuard(WPBouncer\Settings::load()->rule("login_lockout"), new WPBouncer\Storage\TransientStore(), WPBouncer\Plugin::instance()->log()))->clear("198.51.100.5");'
check "unlocked IP can log in"       302 "$(login 198.51.100.5 admin_e2e e2e-pass-123)"

echo "==> Country blocking"
$WP eval '$g = WPBouncer\Plugin::instance()->geo_database(); $g->import_file("'"$FIXTURES"'/geo-sample.csv"); update_option(WPBouncer\Plugin::GEO_META_OPTION, ["rows" => $g->count(), "source" => "fixture", "imported" => time()]);'
set_settings '$s["rules"]["country"] = ["enabled" => true, "mode" => "block", "countries" => ["CN"], "block_unknown" => false, "scope" => "site"]'
check "blocked country (CN)"         403 "$(status 1.0.2.5 "$MOZ" "$U/")"
check "other country (AU)"           200 "$(status 1.0.0.5 "$MOZ" "$U/")"
check "unknown country"              200 "$(status 8.8.8.8 "$MOZ" "$U/")"
set_settings '$s["rules"]["country"]["scope"] = "login"'
check "login-only scope: page ok"    200 "$(status 1.0.2.6 "$MOZ" "$U/")"
check "login-only scope: login"      403 "$(status 1.0.2.6 "$MOZ" "$U/wp-login.php")"
set_settings '$s["rules"]["country"]["enabled"] = false'

echo "==> Rate limiting"
set_settings '$s["rules"]["rate_limit"] = ["enabled" => true, "max_requests" => 10, "window_seconds" => 60, "ban_minutes" => 1]'
codes=""; for _ in $(seq 1 11); do codes="$codes$(status 203.0.113.88 "$MOZ" "$U/") "; done
check "10 requests allowed, 11th throttled" "200 200 200 200 200 200 200 200 200 200 429 " "$codes"
set_settings '$s["rules"]["rate_limit"]["enabled"] = false'

echo "==> Monitor mode"
set_settings '$s["mode"] = "monitor"'
check "monitor mode lets scanner in" 200 "$(status 203.0.113.77 "sqlmap/1.7" "$U/")"
check "...but logs it"               monitored "$($WP eval 'global $wpdb; echo $wpdb->get_var("SELECT action FROM {$wpdb->prefix}bouncer_log WHERE ip = \"203.0.113.77\"");')"
set_settings '$s["mode"] = "enforce"'

echo "==> Per-rule switches"
set_settings '$s["rules"]["user_agent"]["enabled"] = false'
check "User-Agent rule off"          200 "$(status 203.0.113.31 "sqlmap/1.7" "$U/")"
set_settings '$s["rules"]["user_agent"]["enabled"] = true'

echo "==> Admin screens"
J="$WORK/cookies.txt"; rm -f "$J"
curl -s -o /dev/null -c "$J" -b "wordpress_test_cookie=WP%20Cookie%20check" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" \
	-d "log=admin_e2e&pwd=e2e-pass-123&wp-submit=Log+In&testcookie=1" "$U/wp-login.php"
for tab in dashboard general rules countries log tools; do
	out="$WORK/tab-$tab.html"
	code=$(curl -s -o "$out" -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$U/wp-admin/admin.php?page=wp-bouncer&tab=$tab")
	check "admin tab '$tab' loads"     200 "$code"
	check "admin tab '$tab' no PHP errors" 0 "$(grep -c 'Fatal error\|Warning:\|Notice:\|Deprecated:' "$out")"
done
check "log lists blocked entries" 1 "$( [ "$(grep -o 'wpb-badge-blocked' "$WORK/tab-log.html" | wc -l)" -gt 5 ] && echo 1 || echo 0 )"

echo "==> Geo import through the Tools screen"
# One 500-row batch per step, so even a small file needs several steps.
mkdir -p "$W/wp-content/mu-plugins"
cat > "$W/wp-content/mu-plugins/wpb-e2e.php" <<'PHPEOF'
<?php
add_filter( 'wp_bouncer_geo_step_seconds', '__return_zero' );
// Let download_url() fetch from the local stand-in for download.db-ip.com.
add_filter( 'http_request_host_is_external', '__return_true' );
PHPEOF
echo "add_filter( 'http_allowed_safe_ports', function ( \$p ) { \$p[] = $FILES_PORT; return \$p; } );" >> "$W/wp-content/mu-plugins/wpb-e2e.php"
# 3000 ranges 5.0.0.0/24 .. 5.11.183.0/24, all NL, gzipped like the DB-IP file.
"$PHP" -r '$o = ""; for ($i = 0; $i < 3000; $i++) { $b = intdiv($i, 256); $c = $i % 256; $o .= "5.$b.$c.0,5.$b.$c.255,NL\n"; } file_put_contents($argv[1], gzencode($o));' "$FILES/geo.csv.gz"
printf '<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>\n' > "$WORK/not-geo.csv"
head -c 3000000 /dev/urandom | gzip -1 > "$WORK/too-big.csv.gz"   # over upload_max_filesize (2M)
head -c 9000000 /dev/urandom > "$WORK/way-too-big.csv"              # over post_max_size (8M)

admin() { # admin URL [curl args...] -> body to $WORK/admin.html, prints status
	local url=$1; shift
	curl -s -o "$WORK/admin.html" -D "$WORK/admin.headers" -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$@" "$url"
}
nonce_for() { # nonce_for ACTION -> the _wpnonce of the Tools-tab form with that action
	admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=tools" > /dev/null
	"$PHP" -r 'preg_match("/name=\"_wpnonce\" value=\"([0-9a-f]+)\"(?:(?!_wpnonce).)*?name=\"action\" value=\"" . $argv[2] . "\"/s", file_get_contents($argv[1]), $m); echo $m[1] ?? "";' "$WORK/admin.html" "$1"
}
ajax_nonce() { grep -o '"geoNonce":"[0-9a-f]*"' "$WORK/admin.html" | cut -d'"' -f4; }
redirect_has() { # redirect_has TEXT -> 1 if the last response's Location contains TEXT
	grep -i '^location:' "$WORK/admin.headers" | grep -c "$1"
}
geo_rows() { $WP eval 'echo WPBouncer\Plugin::instance()->geo_database()->count();'; }
import_running() { $WP eval 'echo null === WPBouncer\Plugin::instance()->geo_import()->status() ? 0 : 1;'; }
run_steps() { # run_steps -> number of AJAX steps until done, or "error: ..."
	local nonce n=0 out
	admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=tools" > /dev/null
	nonce=$(ajax_nonce)
	while [ $n -lt 200 ]; do
		n=$((n + 1))
		out=$(curl -s -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -d "action=wp_bouncer_geo_step&_ajax_nonce=$nonce" "$U/wp-admin/admin-ajax.php")
		case "$out" in
			*'"done":true'*) echo "$n"; return ;;
			*'"success":true'*) ;;
			*) echo "error: $out"; return ;;
		esac
	done
	echo "error: never finished"
}
upload() { # upload FILE -> status of the Tools import form posted with FILE
	admin "$TOOLS_POST" -F "_wpnonce=$(nonce_for wp_bouncer_geo_import)" -F action=wp_bouncer_geo_import -F "geo_file=@$1"
}
from_url() { # from_url URL -> status of the Tools import form posted with URL
	admin "$TOOLS_POST" -d "_wpnonce=$(nonce_for wp_bouncer_geo_import)&action=wp_bouncer_geo_import&geo_url=$1"
}
at_least() { [ "$2" -ge "$1" ] 2>/dev/null && echo ok || echo "$2"; }
TOOLS_POST="$U/wp-admin/admin-post.php?action=wp_bouncer_geo_import"

before=$(geo_rows)
check "non-geo file is refused"      302 "$(upload "$WORK/not-geo.csv")"
check "  ...with an explanation"     1   "$(redirect_has "look%20like")"
check "  ...and old data kept"       "$before" "$(geo_rows)"
upload "$WORK/too-big.csv.gz" > /dev/null
check "over upload limit explained"  1   "$(redirect_has "larger%20than")"
upload "$WORK/way-too-big.csv" > /dev/null
check "over post limit explained"    1   "$(redirect_has "larger%20than")"
check "  ...and old data kept"       "$before" "$(geo_rows)"

check "upload starts an import"      302 "$(upload "$FILES/geo.csv.gz")"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=tools" > /dev/null
check "Tools shows progress"         1   "$(grep -c 'id="wpb-geo-progress"' "$WORK/admin.html")"
check "import needs several steps"   ok  "$(at_least 6 "$(run_steps)")"
check "all 3000 ranges loaded"       3000 "$(geo_rows)"
check "import no longer running"     0   "$(import_running)"
check "meta records the file"        "3000 geo.csv.gz" "$($WP eval '$m = get_option(WPBouncer\Plugin::GEO_META_OPTION); echo $m["rows"], " ", $m["source"];')"
check "working file removed"         0   "$(find "$W/wp-content/uploads/wp-bouncer" -name '*.csv' | wc -l | tr -d ' ')"
check "work folder has .htaccess"    1   "$(grep -c 'Require all denied' "$W/wp-content/uploads/wp-bouncer/.htaccess")"
check "lookup uses new data"         NL  "$($WP eval 'echo WPBouncer\Plugin::instance()->geo_database()->lookup("5.4.7.9");')"

check "import by URL starts"         302 "$(from_url "http://127.0.0.1:$FILES_PORT/geo.csv.gz")"
check "  ...and finishes"            ok  "$(at_least 6 "$(run_steps)")"
check "  ...with all ranges"         3000 "$(geo_rows)"
from_url "http://127.0.0.1:$FILES_PORT/missing.csv.gz" > /dev/null
check "bad URL explained"            1   "$(redirect_has "Download%20failed")"
check "  ...and old data kept"       3000 "$(geo_rows)"

upload "$FILES/geo.csv.gz" > /dev/null
check "no-JS step button works"      302 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_geo_step)&action=wp_bouncer_geo_step")"
check "stop button works"            302 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_geo_cancel)&action=wp_bouncer_geo_cancel")"
check "  ...keeps partial data"      500 "$(geo_rows)"
check "  ...marked incomplete"       1   "$($WP eval 'echo (int) ( false !== strpos( get_option( WPBouncer\Plugin::GEO_META_OPTION )["source"], "incomplete" ) );')"
check "  ...import not running"      0   "$(import_running)"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=tools" > /dev/null
check "step with nothing running"    1   "$(curl -s -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -d "action=wp_bouncer_geo_step&_ajax_nonce=$(ajax_nonce)" "$U/wp-admin/admin-ajax.php" | grep -c '"success":false')"
check "AJAX step needs a nonce"      403 "$(curl -s -o /dev/null -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -d "action=wp_bouncer_geo_step&_ajax_nonce=bad" "$U/wp-admin/admin-ajax.php")"
rm -f "$W/wp-content/mu-plugins/wpb-e2e.php"

echo "==> Updates (a local server stands in for GitHub releases)"
# An update deletes the installed plugin folder and unpacks the new one. When the
# plugin is a link to the source folder, that would delete the source, so switch
# to a copy first and refuse to go on if it is still a link.
if [ -L "$INSTALLED" ]; then
	rm -f "$INSTALLED"
	cp -R "$PLUGIN_DIR" "$INSTALLED"
fi
if [ -L "$INSTALLED" ] || [ "$(cd "$INSTALLED" && pwd -P)" = "$(cd "$PLUGIN_DIR" && pwd -P)" ]; then
	echo "Refusing to test updates: $INSTALLED is the source folder"; exit 1
fi
CURRENT=$($WP plugin get wp-bouncer --field=version)
$WP plugin auto-updates disable wp-bouncer > /dev/null 2>&1   # left on by an earlier run in a reused WPB_E2E_DIR

cat > "$W/wp-content/mu-plugins/wpb-e2e-update.php" <<PHPEOF
<?php
add_filter( 'wp_bouncer_update_manifest_url', function () { return 'http://127.0.0.1:$FILES_PORT/update.json'; } );
add_filter( 'wp_bouncer_update_package_prefix', function () { return 'http://127.0.0.1:$FILES_PORT/'; } );
add_filter( 'http_request_host_is_external', '__return_true' );
add_filter( 'http_allowed_safe_ports', function ( \$p ) { \$p[] = $FILES_PORT; return \$p; } );
PHPEOF

publish() { # publish VERSION -> a plugin zip with that version and its update.json on the stand-in server
	local v=$1 rel="$WORK/release/wp-bouncer"
	rm -rf "$WORK/release" && mkdir -p "$WORK/release"
	cp -R "$PLUGIN_DIR" "$rel"
	sed -i.bak -e "s/^ \* Version: .*/ * Version:           $v/" -e "s/'WP_BOUNCER_VERSION', '[^']*'/'WP_BOUNCER_VERSION', '$v'/" "$rel/wp-bouncer.php"
	sed -i.bak -e "s/VERSION = '[^']*'/VERSION = '$v'/" "$rel/src/Plugin.php"
	find "$rel" -name '*.bak' -delete
	printf '## [%s] - 2026-01-01\n\n### Added\n- Release %s for the e2e update test.\n' "$v" "$v" > "$WORK/release/CHANGELOG.md"
	rm -f "$FILES/wp-bouncer-$v.zip"
	(cd "$WORK/release" && zip -qrX "$FILES/wp-bouncer-$v.zip" wp-bouncer)
	"$PHP" "$REPO_DIR/scripts/build-manifest.php" --zip "$FILES/wp-bouncer-$v.zip" --plugin-dir "$rel" \
		--changelog "$WORK/release/CHANGELOG.md" --package-url "http://127.0.0.1:$FILES_PORT/wp-bouncer-$v.zip" \
		--out "$FILES/update.json" --notes-out "$WORK/release/notes.md" > /dev/null
}
refresh_updates() { $WP eval 'delete_site_transient( "update_plugins" ); delete_site_transient( WPBouncer\Update\Updater::CACHE ); wp_update_plugins();'; }
offered() { # offered -> the version WordPress offers for wp-bouncer, "none", or "unsupported"
	$WP eval '$t = get_site_transient( "update_plugins" ); $f = "wp-bouncer/wp-bouncer.php"; echo isset( $t->response[ $f ] ) ? $t->response[ $f ]->new_version : ( isset( $t->no_update[ $f ] ) ? "none" : "unsupported" );'
}
installed_version() { $WP plugin get wp-bouncer --field=version; }
update_now() { # update_now -> the JSON from the Plugins screen's "Update now" (admin-ajax update-plugin)
	admin "$U/wp-admin/plugins.php" > /dev/null
	local nonce
	nonce=$(grep -o '"ajax_nonce":"[0-9a-f]*"' "$WORK/admin.html" | head -1 | cut -d'"' -f4)
	curl -s -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" \
		-d "action=update-plugin&plugin=wp-bouncer%2Fwp-bouncer.php&slug=wp-bouncer&_ajax_nonce=$nonce" "$U/wp-admin/admin-ajax.php"
}

publish "$CURRENT"
refresh_updates
check "same version: no update"      none "$(offered)"
admin "$U/wp-admin/plugins.php" > /dev/null
check "auto-update toggle offered"   1    "$(grep -c 'action=enable-auto-update&amp;plugin=wp-bouncer%2Fwp-bouncer.php' "$WORK/admin.html")"

publish 9.0.0
refresh_updates
check "new release is offered"       9.0.0 "$(offered)"
admin "$U/wp-admin/plugins.php" > /dev/null
check "Plugins screen shows it"      1    "$(grep -c 'There is a new version of WP Bouncer available' "$WORK/admin.html")"
admin "$U/wp-admin/update-core.php" > /dev/null
check "Dashboard > Updates lists it" 1    "$(grep -c 'You have version [0-9.]* installed. Update to 9.0.0' "$WORK/admin.html")"
admin "$U/wp-admin/plugin-install.php?tab=plugin-information&plugin=wp-bouncer&section=changelog" > /dev/null
check "View details shows changelog" 1    "$(grep -c 'Release 9.0.0 for the e2e update test' "$WORK/admin.html")"

sed -i.bak 's/"sha256": "[0-9a-f]*"/"sha256": "0000000000000000000000000000000000000000000000000000000000000000"/' "$FILES/update.json" && rm -f "$FILES/update.json.bak"
$WP eval 'delete_site_transient( WPBouncer\Update\Updater::CACHE );'
check "tampered zip is refused"      1    "$(update_now | grep -c 'failed its integrity check')"
check "  ...old version still there" "$CURRENT" "$(installed_version)"
check "  ...and still running"       403  "$(status 203.0.113.51 "sqlmap/1.7" "$U/")"

publish 9.0.0
$WP eval 'delete_site_transient( WPBouncer\Update\Updater::CACHE );'
check "Update now succeeds"          1    "$(update_now | grep -c '"success":true')"
check "  ...new version installed"   9.0.0 "$(installed_version)"
check "  ...still active"            active "$($WP plugin get wp-bouncer --field=status)"
check "  ...settings kept"           x_real_ip "$($WP eval 'echo get_option( "wp_bouncer_settings" )["ip_source"];')"
check "  ...still blocking"          403  "$(status 203.0.113.52 "sqlmap/1.7" "$U/")"
check "  ...no update offered now"   none "$(offered)"

$WP plugin auto-updates enable wp-bouncer > /dev/null
admin "$U/wp-admin/plugins.php" > /dev/null
check "auto-update switched on"      1    "$(grep -c 'action=disable-auto-update&amp;plugin=wp-bouncer%2Fwp-bouncer.php' "$WORK/admin.html")"
publish 9.1.0
refresh_updates
# Real auto-updates run from WP-Cron, which is what DOING_CRON tells WordPress.
# (Outside cron, WordPress deactivates a plugin while updating it and leaves
# reactivating it to the update screen.)
$WP eval 'define( "DOING_CRON", true ); wp_maybe_auto_update();'
check "auto-update installs 9.1.0"   9.1.0 "$(installed_version)"
check "  ...still active"            active "$($WP plugin get wp-bouncer --field=status)"
check "  ...still blocking"          403  "$(status 203.0.113.53 "sqlmap/1.7" "$U/")"

echo "<?php define( 'WP_BOUNCER_DISABLE_UPDATES', true );" > "$W/wp-content/mu-plugins/wpb-e2e-noupdates.php"
publish 9.2.0
refresh_updates
check "WP_BOUNCER_DISABLE_UPDATES"   unsupported "$(offered)"
rm -f "$W/wp-content/mu-plugins/wpb-e2e-noupdates.php" "$W/wp-content/mu-plugins/wpb-e2e-update.php"

echo "==> PHP debug log"
# WordPress also writes informational lines here (e.g. "Automatic updates starting..."); only PHP problems count.
PHP_PROBLEMS='PHP (Fatal error|Parse error|Warning|Notice|Deprecated)'
touch "$W/debug.log"
check "no PHP warnings or notices" 0 "$(grep -cE "$PHP_PROBLEMS" "$W/debug.log")"
grep -E -A3 "$PHP_PROBLEMS" "$W/debug.log" | head -20

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
