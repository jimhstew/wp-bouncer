#!/usr/bin/env bash
#
# End-to-end smoke test: installs a throwaway WordPress (SQLite by default, or a
# real MySQL/MariaDB database), activates WP Bouncer, fires real HTTP requests at it and checks the responses.
#
# Usage:   tests/e2e/run.sh
# Options (environment variables):
#   PHP=/path/to/php      PHP binary (default: php on PATH). Needs pdo_sqlite (sqlite mode)
#                         or mysqli (mysql mode).
#   WPB_E2E_DIR=/tmp/x    Work directory (default: a new temp dir, deleted afterwards).
#   WPB_E2E_PORT=8899     Port for PHP's built-in web server.
#   WPB_E2E_KEEP=1        Keep the work directory and server log for debugging.
#   WPB_E2E_ZIP=file.zip  Install the plugin from a built zip (make build) instead of
#                         linking the wp-bouncer/ source folder. Proves the package works.
#   WPB_E2E_DB=sqlite|mysql   Database (default sqlite). "mysql" covers MariaDB too. In mysql
#                         mode the database is dropped and recreated at the start of every run,
#                         through PHP's mysqli (no mysql client needed). Use a dedicated name!
#   WPB_E2E_DB_HOST=127.0.0.1 MySQL host, may include a port (127.0.0.1:3307).
#   WPB_E2E_DB_USER=root      MySQL user (needs CREATE/DROP on the database).
#   WPB_E2E_DB_PASSWORD=      MySQL password (default empty).
#   WPB_E2E_DB_NAME=wpb_e2e   MySQL database name (DROPPED and recreated).
#   WPB_E2E_WP_VERSION=latest latest | nightly | a version such as 6.4 or 5.8.3.
#                         WordPress is unpacked into $WPB_E2E_DIR/wordpress-<db>-<version>, so a
#                         reused work directory never mixes databases or versions.
#
# Requests come from 127.0.0.1. A request from loopback with no forwarding header is the
# server itself and skips every rule, so the test switches the IP source to X-Real-IP,
# lists 127.0.0.1 as the trusted proxy (the header is ignored without one) and sends a
# different fake IP for each scenario.

set -uo pipefail

PHP=${PHP:-php}
PORT=${WPB_E2E_PORT:-8899}
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLUGIN_DIR="$REPO_DIR/wp-bouncer"
FIXTURES="$REPO_DIR/tests/fixtures"
WORK=${WPB_E2E_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/wpb-e2e.XXXXXX")}
U="http://127.0.0.1:${PORT}"
DB=${WPB_E2E_DB:-sqlite}
WPV=${WPB_E2E_WP_VERSION:-latest}
DB_HOST=${WPB_E2E_DB_HOST:-127.0.0.1}
DB_USER=${WPB_E2E_DB_USER:-root}
DB_PASSWORD=${WPB_E2E_DB_PASSWORD:-}
DB_NAME=${WPB_E2E_DB_NAME:-wpb_e2e}
case "$DB" in sqlite|mysql) ;; *) echo "WPB_E2E_DB must be sqlite or mysql"; exit 1 ;; esac
case "$WPV" in
	latest)  WP_URL="https://wordpress.org/latest.tar.gz" ;;
	nightly) WP_URL="https://wordpress.org/nightly-builds/wordpress-latest.zip" ;;
	[0-9]*.[0-9]*) WP_URL="https://wordpress.org/wordpress-${WPV}.tar.gz" ;;
	*) echo "WPB_E2E_WP_VERSION must be latest, nightly or a version like 6.4"; exit 1 ;;
esac
case "$DB_NAME" in ""|*[!A-Za-z0-9_]*) echo "WPB_E2E_DB_NAME may only contain letters, digits and _"; exit 1 ;; esac
W="$WORK/wordpress-$DB-$WPV"
WP="$PHP -d memory_limit=512M $WORK/wp-cli.phar --path=$W --quiet"

pass=0
fail=0
SERVER_PID=""

cleanup() {
	for pid in $SERVER_PID; do
		pkill -P "$pid" 2>/dev/null   # PHP_CLI_SERVER_WORKERS children outlive the parent otherwise
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
# Downloaded tools are pinned and verified (RT-02, SB-25). To bump wp-cli, change the version and
# the SHA-512 together: the digest is published at <phar URL>.sha512 on the GitHub release.
WPCLI_VERSION="2.12.0"
WPCLI_SHA512="be928f6b8ca1e8dfb9d2f4b75a13aa4aee0896f8a9a0a1c45cd5d2c98605e6172e6d014dda2e27f88c98befc16c040cbb2bd1bfa121510ea5cdf5f6a30fe8832"
# SQLite Database Integration plugin: exact version, SHA-256 of the downloads.wordpress.org zip.
SQLITE_PLUGIN_VERSION="3.1.1"
SQLITE_PLUGIN_SHA256="5681502868907644ecc472739a75c72453b662c44bcc5dd7c1b1410f988bad44"

hash_of() { # hash_of ALGO FILE -> hex digest
	if command -v "sha${1}sum" > /dev/null; then "sha${1}sum" "$2" | cut -d' ' -f1; else shasum -a "$1" "$2" | cut -d' ' -f1; fi
}
verify() { # verify ALGO FILE EXPECTED LABEL
	[ "$(hash_of "$1" "$2")" = "$3" ] || { echo "checksum mismatch for $4 (expected sha$1 $3)"; rm -f "$2"; exit 1; }
}
# WordPress.org publishes a .sha1 next to each release tarball (not for nightly builds).
fetch_wordpress() { # fetch_wordpress URL OUTFILE
	curl -sfLo "$2" "$1" || return 1
	case "$1" in
		*nightly-builds*) ;;
		*) local want; want=$(curl -sfL "$1.sha1" | tr -d '[:space:]') || return 1
		   [ -n "$want" ] || return 1
		   verify 1 "$2" "$want" "WordPress ($WPV)" ;;
	esac
}

if [ ! -f wp-cli.phar ]; then
	curl -sfLo wp-cli.phar.part "https://github.com/wp-cli/wp-cli/releases/download/v${WPCLI_VERSION}/wp-cli-${WPCLI_VERSION}.phar" || { echo "download wp-cli failed"; exit 1; }
	verify 512 wp-cli.phar.part "$WPCLI_SHA512" "wp-cli ${WPCLI_VERSION}"
	mv wp-cli.phar.part wp-cli.phar
fi
# A phar left over from an older run must match the pin too.
verify 512 wp-cli.phar "$WPCLI_SHA512" "wp-cli ${WPCLI_VERSION}"
if [ "$WPV" = nightly ]; then rm -rf "$W"; fi   # a moving target: always fetch it again
if [ ! -d "$W" ]; then
	DL="$WORK/download.$$"
	rm -rf "$DL"; mkdir -p "$DL"
	if [ "$WPV" = nightly ]; then
		{ fetch_wordpress "$WP_URL" "$DL/wp.zip" && unzip -q "$DL/wp.zip" -d "$DL"; } || { echo "download WordPress ($WPV) failed"; exit 1; }
	else
		{ fetch_wordpress "$WP_URL" "$DL/wp.tar.gz" && tar xzf "$DL/wp.tar.gz" -C "$DL"; } || { echo "download WordPress ($WPV) failed"; exit 1; }
	fi
	mv "$DL/wordpress" "$W" || { echo "unpacking WordPress ($WPV) failed"; exit 1; }
	rm -rf "$DL"
fi
if [ "$DB" = sqlite ]; then
	if [ ! -d "$W/wp-content/plugins/sqlite-database-integration" ]; then
		curl -sfLo sqlite.zip "https://downloads.wordpress.org/plugin/sqlite-database-integration.${SQLITE_PLUGIN_VERSION}.zip" || { echo "download SQLite plugin failed"; exit 1; }
		verify 256 sqlite.zip "$SQLITE_PLUGIN_SHA256" "sqlite-database-integration ${SQLITE_PLUGIN_VERSION}"
		unzip -q sqlite.zip -d "$W/wp-content/plugins/"
		sed "s#{SQLITE_IMPLEMENTATION_FOLDER_PATH}#$W/wp-content/plugins/sqlite-database-integration#; s#{SQLITE_PLUGIN}#sqlite-database-integration/load.php#" \
			"$W/wp-content/plugins/sqlite-database-integration/db.copy" > "$W/wp-content/db.php"
	fi
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
else
	# Real MySQL/MariaDB: start from an empty database every run (mysqli, no client binary).
	# Credentials travel in the environment, not on the command line.
	WPB_H="$DB_HOST" WPB_U="$DB_USER" WPB_P="$DB_PASSWORD" WPB_N="$DB_NAME" "$PHP" -r '
		mysqli_report( MYSQLI_REPORT_OFF );
		$h = getenv( "WPB_H" ); $port = 3306;
		if ( preg_match( "/^(.*):([0-9]+)$/", $h, $m ) ) { $h = $m[1]; $port = (int) $m[2]; }
		$c = mysqli_init();
		if ( ! @$c->real_connect( $h, getenv( "WPB_U" ), getenv( "WPB_P" ), null, $port ) ) { fwrite( STDERR, "MySQL connect failed: " . mysqli_connect_error() . "\n" ); exit( 1 ); }
		$n = getenv( "WPB_N" );
		if ( ! $c->query( "DROP DATABASE IF EXISTS `$n`" ) || ! $c->query( "CREATE DATABASE `$n` CHARACTER SET utf8mb4" ) ) { fwrite( STDERR, "MySQL error: " . $c->error . "\n" ); exit( 1 ); }
	' || { echo "could not reset database $DB_NAME on $DB_HOST"; exit 1; }
	rm -f "$W/wp-content/db.php"
	php_str() { printf "'%s'" "$(printf '%s' "$1" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g")"; }   # PHP single-quoted literal
	{
		echo '<?php'
		echo "define( 'DB_NAME', $(php_str "$DB_NAME") ); define( 'DB_USER', $(php_str "$DB_USER") ); define( 'DB_PASSWORD', $(php_str "$DB_PASSWORD") ); define( 'DB_HOST', $(php_str "$DB_HOST") );"
		echo "define( 'DB_CHARSET', 'utf8mb4' ); define( 'DB_COLLATE', '' );"
		cat <<'EOF'
$table_prefix = 'wp_';
define( 'WP_DEBUG', true ); define( 'WP_DEBUG_LOG', __DIR__ . '/debug.log' ); define( 'WP_DEBUG_DISPLAY', false );
define( 'DISABLE_WP_CRON', true );
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
EOF
	} > "$W/wp-config.php"
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
# Pretty permalinks, as almost every live site has: with plain ones, WordPress
# answers most unknown paths with the home page or a redirect, not a 404.
$WP rewrite structure '/%postname%/'
$WP plugin activate wp-bouncer
$WP eval '$d = WPBouncer\Settings::defaults(); $d["ip_source"] = "x_real_ip"; $d["trusted_proxies"] = ["127.0.0.1"]; update_option("wp_bouncer_settings", $d); global $wpdb; $wpdb->query("DELETE FROM {$wpdb->prefix}bouncer_log"); $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE \"%transient%wpb\_%\"");'
rm -f "$W/debug.log"

# Capture outgoing mail instead of sending it: one JSON line per email.
MAILLOG="$W/wp-content/e2e-mail.log"
mkdir -p "$W/wp-content/mu-plugins"
cat > "$W/wp-content/mu-plugins/wpb-e2e-mail.php" <<'PHPEOF'
<?php
add_filter(
	'pre_wp_mail',
	function ( $null, $atts ) {
		file_put_contents( WP_CONTENT_DIR . '/e2e-mail.log', json_encode( $atts, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n", FILE_APPEND );
		return true;
	},
	10,
	2
);
PHPEOF
rm -f "$MAILLOG"

# Router for PHP's built-in server. Like Apache with WordPress's rewrite rules:
# a file that exists is served (or run, for .php) by the server; anything else
# goes to WordPress. Without it the server answers missing paths with a dot
# (/.env, /x.jpg) itself, so they would never reach the plugin.
# It also stands in for Apache reading wp-content/uploads/.htaccess: while
# WP Bouncer's block is in that file, scripts in uploads get a 403. If the file
# wp-content/e2e-htaccess-500 exists, it acts like a host that doesn't allow
# access rules in .htaccess instead: everything in uploads gets a 500.
cat > "$WORK/router.php" <<'PHPEOF'
<?php
$root = $_SERVER['DOCUMENT_ROOT'];
$path = '/' . ltrim( (string) parse_url( urldecode( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ), '/' );
if ( 0 === strpos( $path, '/wp-content/uploads/' ) && file_exists( $root . '/wp-content/e2e-htaccess-500' )
	&& false !== strpos( (string) @file_get_contents( $root . '/wp-content/uploads/.htaccess' ), '# BEGIN WP Bouncer' ) ) {
	http_response_code( 500 );
	echo 'Internal Server Error';
	return true;
}
if ( preg_match( '#^/wp-content/uploads/.*\.(php[0-9]?|phtml|pht|phar)$#i', $path )
	&& false !== strpos( (string) @file_get_contents( $root . '/wp-content/uploads/.htaccess' ), '# BEGIN WP Bouncer' ) ) {
	http_response_code( 403 );
	echo 'Forbidden';
	return true;
}
if ( file_exists( $root . $path ) ) {
	if ( is_dir( $root . $path ) && '/' !== substr( $path, -1 ) ) {
		header( "Location: $path/" );
		return true;
	}
	return false;
}
chdir( $root );
$_SERVER['SCRIPT_NAME']     = '/index.php';
$_SERVER['PHP_SELF']        = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = $root . '/index.php';
require 'index.php';
PHPEOF

# Typical shared-hosting limits, so anything that relies on one long request fails here too.
# display_errors is off as on a production host; PHP's own start-up warnings
# (such as "POST too large") would otherwise land in the page and break redirects.
# Several workers, so the site can make a request to itself (the uploads test does).
# opcache.enable=0: the update tests swap the linked plugin folder for a copy. OPcache (on by
# default in the built-in server when the extension is loaded) would keep serving the compiled
# plugin under the old, linked path, so __FILE__ would point at the source folder and the
# updater could not recognise its own plugin file ("The plugin is at the latest version").
PHP_CLI_SERVER_WORKERS=4 "$PHP" -d max_execution_time=30 -d upload_max_filesize=2M -d post_max_size=8M -d display_errors=0 \
	-d opcache.enable=0 -S "127.0.0.1:$PORT" -t "$W" "$WORK/router.php" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
sleep 0.2
kill -0 "$SERVER_PID" 2>/dev/null || { echo "web server did not start (port $PORT in use?):"; cat "$WORK/server.log"; exit 1; }

# Files for the import-by-URL and update tests (stands in for download.db-ip.com and GitHub
# releases). They are served by the site's own server, from a folder in the web root: WordPress
# before 5.9 has no http_allowed_safe_ports filter, and its safe-request check (wp_safe_remote_get)
# only accepts ports 80, 443, 8080 and the site's own, so a second server on another port is
# unreachable there.
FILES="$W/e2e-files"
mkdir -p "$FILES"
FILES_URL="$U/e2e-files"

MOZ="Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"
GOOGLEBOT="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

count_in() { # count_in TEXT FILE -> matching lines in FILE (0 if it doesn't exist)
	if [ -f "$2" ]; then grep -cF -- "$1" "$2"; else echo 0; fi
}
mail_count() { count_in '"subject"' "$MAILLOG"; }
log_value() { # log_value COLUMN "WHERE ..." -> first matching value from the bouncer log
	$WP eval 'global $wpdb; echo $wpdb->get_var("SELECT '"$1"' FROM {$wpdb->prefix}bouncer_log WHERE '"$2"' ORDER BY id DESC LIMIT 1");'
}

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
check "users sitemap removed"        404 "$(status 203.0.113.10 "$MOZ" "$U/wp-sitemap-users-1.xml")"

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

echo "==> Sensitive-file probes"
check "/.env refused"                403 "$(status 203.0.113.61 "$MOZ" "$U/.env")"
check "  ...prober banned site-wide" 403 "$(status 203.0.113.61 "$MOZ" "$U/")"
check "  ...other visitors fine"     200 "$(status 203.0.113.62 "$MOZ" "$U/")"
check "  ...logged"                  sensitive_files "$(log_value rule "ip = '203.0.113.61'")"
check "/.git/config refused"         403 "$(status 203.0.113.63 "$MOZ" "$U/.git/config")"
check "wp-config.php.bak refused"    403 "$(status 203.0.113.64 "$MOZ" "$U/wp-config.php.bak")"
check "backup.zip refused"           403 "$(status 203.0.113.65 "$MOZ" "$U/backup.zip")"
check "PHPUnit eval-stdin refused"   403 "$(status 203.0.113.66 "$MOZ" "$U/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")"
check "/.well-known/ is not a probe" 404 "$(status 203.0.113.67 "$MOZ" "$U/.well-known/security.txt")"
check "  ...and not banned"          200 "$(status 203.0.113.67 "$MOZ" "$U/")"
set_settings '$s["rules"]["sensitive_files"]["ban_minutes"] = 0'
check "ban 0: probe refused"         403 "$(status 203.0.113.68 "$MOZ" "$U/.env")"
check "  ...but no ban"              200 "$(status 203.0.113.68 "$MOZ" "$U/")"
set_settings '$s["rules"]["sensitive_files"]["enabled"] = false'
check "rule off: /.env is a 404"     404 "$(status 203.0.113.69 "$MOZ" "$U/.env")"
set_settings '$s["rules"]["sensitive_files"] = ["enabled" => true, "ban_minutes" => 60, "extra_paths" => []]'

echo "==> 404 flood"
set_settings '$s["rules"]["not_found"]["max_404"] = 5'
codes=""; for i in 1 2 3 4 5 6; do codes="$codes$(status 203.0.113.71 "$MOZ" "$U/wp-content/plugins/scan-$i/readme.txt") "; done
check "six 404s answered as 404s"    "404 404 404 404 404 404 " "$codes"
check "  ...then banned"             403 "$(status 203.0.113.71 "$MOZ" "$U/")"
check "  ...ban logged as a lockout" 1 "$(log_value "COUNT(*)" "rule = 'not_found' AND ip = '203.0.113.71' AND action = 'lockout'")"
for i in $(seq 1 12); do status 203.0.113.72 "$MOZ" "$U/wp-content/uploads/missing-$i.jpg" > /dev/null; done
check "missing images don't count"   200 "$(status 203.0.113.72 "$MOZ" "$U/")"
for i in $(seq 1 12); do status 203.0.113.73 "$GOOGLEBOT" "$U/old-page-$i/" > /dev/null; done
check "crawlers don't count"         200 "$(status 203.0.113.73 "$GOOGLEBOT" "$U/")"
codes=""; for i in 1 2 3; do codes="$codes$(status 203.0.113.74 "$MOZ" "$U/typo-$i/") "; done
check "a few 404s are fine"          "404 404 404 200" "$codes$(status 203.0.113.74 "$MOZ" "$U/")"
set_settings '$s["rules"]["not_found"]["max_404"] = 20'

echo "==> Admin screens"
J="$WORK/cookies.txt"; rm -f "$J"
curl -s -o /dev/null -c "$J" -b "wordpress_test_cookie=WP%20Cookie%20check" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" \
	-d "log=admin_e2e&pwd=e2e-pass-123&wp-submit=Log+In&testcookie=1" "$U/wp-login.php"
for tab in dashboard general rules countries log traffic tools; do
	out="$WORK/tab-$tab.html"
	code=$(curl -s -o "$out" -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$U/wp-admin/admin.php?page=wp-bouncer&tab=$tab")
	check "admin tab '$tab' loads"     200 "$code"
	check "admin tab '$tab' no PHP errors" 0 "$(grep -c 'Fatal error\|Warning:\|Notice:\|Deprecated:' "$out")"
done
check "log lists blocked entries" 1 "$( [ "$(grep -o 'wpb-badge-blocked' "$WORK/tab-log.html" | wc -l)" -gt 5 ] && echo 1 || echo 0 )"
check "admin is never banned for probes" 404 "$(status 198.51.100.50 "$MOZ" "$U/.env" -b "$J")"
check "  ...still gets in"           200 "$(status 198.51.100.50 "$MOZ" "$U/wp-admin/" -b "$J")"

echo "==> Geo import through the Tools screen"
# One 500-row batch per step, so even a small file needs several steps.
mkdir -p "$W/wp-content/mu-plugins"
cat > "$W/wp-content/mu-plugins/wpb-e2e.php" <<'PHPEOF'
<?php
add_filter( 'wp_bouncer_geo_step_seconds', '__return_zero' );
// Let download_url() fetch from the local stand-in for download.db-ip.com.
add_filter( 'http_request_host_is_external', '__return_true' );
PHPEOF
# 3000 ranges 5.0.0.0/24 .. 5.11.183.0/24, all NL, gzipped like the DB-IP file.
"$PHP" -r '$o = ""; for ($i = 0; $i < 3000; $i++) { $b = intdiv($i, 256); $c = $i % 256; $o .= "5.$b.$c.0,5.$b.$c.255,NL\n"; } file_put_contents($argv[1], gzencode($o));' "$FILES/geo.csv.gz"
printf '<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>\n' > "$WORK/not-geo.csv"
head -c 3000000 /dev/urandom | gzip -1 > "$WORK/too-big.csv.gz"   # over upload_max_filesize (2M)
head -c 9000000 /dev/urandom > "$WORK/way-too-big.csv"              # over post_max_size (8M)

admin() { # admin URL [curl args...] -> body to $WORK/admin.html, prints status
	local url=$1; shift
	curl -s -o "$WORK/admin.html" -D "$WORK/admin.headers" -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$@" "$url"
}
nonce_for() { # nonce_for ACTION [TAB] -> the _wpnonce of the form with that action (on the Tools tab by default)
	admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=${2:-tools}" > /dev/null
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

check "import by URL starts"         302 "$(from_url "$FILES_URL/geo.csv.gz")"
check "  ...and finishes"            ok  "$(at_least 6 "$(run_steps)")"
check "  ...with all ranges"         3000 "$(geo_rows)"
from_url "$FILES_URL/missing.csv.gz" > /dev/null
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

echo "==> No PHP in uploads"
UP="$W/wp-content/uploads"
HT="$UP/.htaccess"
rm -f "$HT" "$W/wp-content/e2e-htaccess-500"  # left by an earlier run in a reused WPB_E2E_DIR
$WP option delete wp_bouncer_uploads_htaccess > /dev/null 2>&1
status 203.0.113.10 "$MOZ" "$U/" > /dev/null   # any request writes the block if needed
check "block written to uploads/.htaccess" 1 "$(count_in '# BEGIN WP Bouncer' "$HT")"
probe() { # probe -> result of the Rules tab's "Test now" button
	admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_uploads_probe rules)&action=wp_bouncer_uploads_probe" > /dev/null
	$WP eval 'echo get_option( WPBouncer\Hardening\UploadsGuard::PROBE_OPTION )["result"];'
}
check "Test now: protected"          protected "$(probe)"
check "  ...test files deleted"      0 "$(find "$UP" -maxdepth 1 -name 'wp-bouncer-*' | wc -l | tr -d ' ')"
$WP cron event run wp_bouncer_uploads_check > /dev/null
check "after-write check keeps it"   1 "$(count_in '# BEGIN WP Bouncer' "$HT")"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=rules" > /dev/null
check "Rules tab: block in place"    1 "$(count_in 'in place.' "$WORK/admin.html")"
check "Rules tab: shows the result"  1 "$(count_in 'Protected: the server refused' "$WORK/admin.html")"
printf '# Site owner rule\nOptions -Indexes\n' >> "$HT"
set_settings '$s["rules"]["uploads_php"]["htaccess"] = false'
status 203.0.113.10 "$MOZ" "$U/" > /dev/null
check "setting off: block removed"   0 "$(count_in 'WP Bouncer' "$HT")"
check "  ...owner's lines kept"      1 "$(count_in 'Options -Indexes' "$HT")"
check "Test now: not protected"      unprotected "$(probe)"
set_settings '$s["rules"]["uploads_php"]["htaccess"] = true'
status 203.0.113.10 "$MOZ" "$U/" > /dev/null
check "setting on: block back"       1 "$(count_in '# BEGIN WP Bouncer' "$HT")"
check "  ...owner's lines kept"      1 "$(count_in 'Options -Indexes' "$HT")"
echo "<?php define( 'WP_BOUNCER_DISABLE', true );" > "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
status 203.0.113.10 "$MOZ" "$U/" > /dev/null
check "WP_BOUNCER_DISABLE removes it" 0 "$(count_in 'WP Bouncer' "$HT")"
rm -f "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
status 203.0.113.10 "$MOZ" "$U/" > /dev/null
check "  ...and it returns after"    1 "$(count_in '# BEGIN WP Bouncer' "$HT")"
# A host where the block makes every upload fail: the check takes it out again.
touch "$W/wp-content/e2e-htaccess-500"
check "  (stand-in host breaks uploads)" 500 "$(curl -s -o /dev/null -w '%{http_code}' "$U/wp-content/uploads/")"
$WP cron event run wp_bouncer_uploads_check > /dev/null
check "broken host: block removed"   0 "$(count_in 'WP Bouncer' "$HT")"
check "  ...owner's lines kept"      1 "$(count_in 'Options -Indexes' "$HT")"
check "  ...not rewritten"           0 "$(status 203.0.113.10 "$MOZ" "$U/" > /dev/null; count_in 'WP Bouncer' "$HT")"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=rules" > /dev/null
check "  ...admin is told"           1 "$(count_in 'answered uploaded files (images too) with an error' "$WORK/admin.html")"
check "  ...and logged"              alert "$(log_value action "rule = 'uploads_php' AND reason LIKE 'Removed the uploads%'")"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_uploads_sync rules)&action=wp_bouncer_uploads_sync" > /dev/null
check "Test now on that host"        broken "$(probe)"
check "  ...block removed again"     0 "$(count_in 'WP Bouncer' "$HT")"
rm -f "$W/wp-content/e2e-htaccess-500"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_uploads_sync rules)&action=wp_bouncer_uploads_sync" > /dev/null
check "host fixed: Write it now"     1 "$(count_in '# BEGIN WP Bouncer' "$HT")"
check "  ...Test now: protected"     protected "$(probe)"
check "  ...warning gone"            0 "$(admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=rules" > /dev/null; count_in 'answered uploaded files (images too)' "$WORK/admin.html")"
rm -f "$MAILLOG"
$WP plugin deactivate wp-bouncer
check "deactivating removes it"      0 "$(count_in 'WP Bouncer' "$HT")"
check "  ...owner's lines kept"      1 "$(count_in 'Options -Indexes' "$HT")"
check "  ...and sends an alert"      1 "$(count_in 'WP Bouncer itself was deactivated' "$MAILLOG")"
$WP plugin activate wp-bouncer
status 203.0.113.10 "$MOZ" "$U/" > /dev/null
check "reactivating writes it again" 1 "$(count_in '# BEGIN WP Bouncer' "$HT")"

# Uploads that are scripts in disguise. WordPress would refuse some of these
# itself; the message shows WP Bouncer got there first.
printf 'GIF89a\x01\x00\x01\x00\x00\x00\x00;<?php echo 1; ?>' > "$WORK/pic.gif"
printf 'not really a picture' > "$WORK/cat.php.jpg"
"$PHP" -r 'file_put_contents($argv[1], base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="));' "$WORK/dot.png"
WP_LOUD="${WP% --quiet}"   # --quiet would hide the warning that carries the reason
check "WP-CLI import: .php.jpg refused" 1 "$($WP_LOUD media import "$WORK/cat.php.jpg" 2>&1 | grep -c 'WP Bouncer refused')"
check "WP-CLI import: PHP in a GIF refused" 1 "$($WP_LOUD media import "$WORK/pic.gif" 2>&1 | grep -c 'contains PHP code')"
check "WP-CLI import: real image fine" 0 "$($WP media import "$WORK/dot.png" > /dev/null 2>&1; echo $?)"
RN=$(curl -s -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$U/wp-admin/admin-ajax.php?action=rest-nonce")
rest_upload() { # rest_upload FILE NAME TYPE -> HTTP status of a media upload through the REST API
	curl -s -o "$WORK/rest.json" -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -H "X-WP-Nonce: $RN" \
		-H "Content-Disposition: attachment; filename=$2" -H "Content-Type: $3" --data-binary "@$1" "$U/?rest_route=/wp/v2/media"
}
check "REST upload: PHP in a GIF refused" 1 "$( [ "$(rest_upload "$WORK/pic.gif" pic.gif image/gif)" -ge 400 ] && count_in 'WP Bouncer refused' "$WORK/rest.json" || echo 0)"
check "REST upload: real image fine" 201 "$(rest_upload "$WORK/dot.png" dot.png image/png)"
check "refused uploads are logged"   uploads_php "$(log_value rule "rule = 'uploads_php'")"
check "  ...no PHP left in uploads"  0 "$(find "$UP" \( -name '*.php*' -o -name 'pic*.gif' \) ! -name index.php | wc -l | tr -d ' ')"

echo "==> Email alerts"
rm -f "$MAILLOG"
$WP user create eve_e2e eve@example.test --role=administrator --user_pass=e2e-pass-eve
check "new administrator: one email" 1 "$(mail_count)"
check "  ...subject"                 1 "$(count_in 'WP Bouncer alert: New administrator account created' "$MAILLOG")"
check "  ...names the account"       1 "$(count_in 'Username: eve_e2e, email: eve@example.test' "$MAILLOG")"
check "  ...to the admin email"      1 "$(count_in '"to":["e2e@example.test"]' "$MAILLOG")"
check "  ...says it came from WP-CLI" 1 "$(count_in 'From IP:    command line' "$MAILLOG")"
check "  ...logged as an alert"      alert "$(log_value action "rule = 'alerts'")"
rm -f "$MAILLOG"
$WP user create sub_e2e sub@example.test --role=subscriber --user_pass=e2e-pass-sub
check "new subscriber: no email"     0 "$(mail_count)"
$WP user set-role sub_e2e administrator
check "promotion: one email"         1 "$(count_in 'Account promoted to administrator' "$MAILLOG")"
rm -f "$MAILLOG"
$WP user set-role sub_e2e editor
check "demotion: no email"           0 "$(mail_count)"
$WP user add-role sub_e2e administrator
check "added admin role: email"      1 "$(count_in 'Account given the administrator role' "$MAILLOG")"
rm -f "$MAILLOG"
$WP plugin activate hello
check "plugin activated: email"      1 "$(count_in 'Plugin activated: Hello Dolly' "$MAILLOG")"
$WP plugin deactivate hello
check "plugin deactivated: email"    1 "$(count_in 'Plugin deactivated: Hello Dolly' "$MAILLOG")"
mkdir -p "$WORK/e2e-sample/e2e-sample"
printf '<?php\n/**\n * Plugin Name: E2E Sample\n * Version: 1.2.3\n */\n' > "$WORK/e2e-sample/e2e-sample/e2e-sample.php"
rm -f "$WORK/e2e-sample.zip"; (cd "$WORK/e2e-sample" && zip -qr "$WORK/e2e-sample.zip" e2e-sample)
rm -f "$MAILLOG"
$WP plugin install "$WORK/e2e-sample.zip" --activate
check "install + activate: one email" 1 "$(mail_count)"
check "  ...listing both"            1 "$(count_in 'WP Bouncer alert: 2 security events' "$MAILLOG")"
check "  ...install named"           1 "$(count_in 'Plugin installed: E2E Sample' "$MAILLOG")"
rm -f "$MAILLOG"
$WP plugin deactivate e2e-sample
$WP plugin delete e2e-sample
check "plugin deleted: email"        1 "$(count_in 'Plugin deleted: e2e-sample/e2e-sample.php' "$MAILLOG")"
rm -f "$MAILLOG"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_test_alert general)&action=wp_bouncer_test_alert" > /dev/null
check "Send a test email button"     1 "$(redirect_has "Test%20email%20sent")"
check "  ...email captured"          1 "$(count_in 'WP Bouncer alert: Test alert' "$MAILLOG")"
check "  ...shows who and where"     1 "$(count_in 'admin_e2e (user ID 1)' "$MAILLOG")"
set_settings '$s["alerts"]["recipients"] = ["security@example.test", "owner@example.test"]'
rm -f "$MAILLOG"
$WP user create eve2_e2e eve2@example.test --role=administrator --user_pass=e2e-pass-eve
check "custom recipients"            1 "$(count_in '"to":["security@example.test","owner@example.test"]' "$MAILLOG")"
echo "<?php define( 'WP_BOUNCER_DISABLE', true );" > "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
rm -f "$MAILLOG"
$WP user create eve3_e2e eve3@example.test --role=administrator --user_pass=e2e-pass-eve
check "alerts work with DISABLE on"  1 "$(mail_count)"
rm -f "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
$WP eval 'set_transient( "wpb_alert_count", 20, HOUR_IN_SECONDS );'
rm -f "$MAILLOG"
$WP user create eve4_e2e eve4@example.test --role=administrator --user_pass=e2e-pass-eve
check "over 20 an hour: not emailed" 0 "$(mail_count)"
check "  ...but still logged"        1 "$($WP eval 'global $wpdb; echo (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log WHERE action = \"alert\" AND reason LIKE \"%eve4_e2e%\"");')"
$WP eval 'delete_transient( "wpb_alert_count" );'
set_settings '$s["alerts"]["enabled"] = false'
rm -f "$MAILLOG"
$WP user create eve5_e2e eve5@example.test --role=administrator --user_pass=e2e-pass-eve
check "alerts off: no email"         0 "$(mail_count)"
set_settings '$s["alerts"] = ["enabled" => true, "recipients" => [], "new_admin" => true, "plugin_changes" => true, "plugin_updates" => true]'
for u in eve_e2e sub_e2e eve2_e2e eve3_e2e eve4_e2e eve5_e2e; do $WP user delete "$u" --yes > /dev/null 2>&1; done
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=log&log_action=alert" > /dev/null
check "Activity Log shows alerts"    1 "$( [ "$(grep -o 'wpb-badge-alert' "$WORK/admin.html" | wc -l)" -ge 5 ] && echo 1 || echo 0 )"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=dashboard" > /dev/null
check "Dashboard still loads"        200 "$(admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=dashboard")"

echo "==> Traffic log"
traffic_value() { # traffic_value COLUMN "WHERE ..." -> newest matching value from the traffic log
	$WP eval 'global $wpdb; echo $wpdb->get_var("SELECT '"$1"' FROM {$wpdb->prefix}bouncer_traffic WHERE '"$2"' ORDER BY id DESC LIMIT 1");'
}
traffic_count() { traffic_value "COUNT(*)" "$1"; }
check "purge job scheduled"          1 "$($WP cron event list --hook=wp_bouncer_traffic_purge --format=count)"
$WP eval 'WPBouncer\Plugin::instance()->traffic_log()->clear();'
status 203.0.113.81 "$MOZ" "$U/" > /dev/null
check "off by default"               0 "$(traffic_count "1=1")"
set_settings '$s["traffic"]["enabled"] = true'
status 203.0.113.81 "$MOZ" "$U/" -e "https://www.example.com/where-they-came-from" > /dev/null
check "page view recorded"           "200 browser /" "$(traffic_value status "ip = '203.0.113.81'") $(traffic_value client "ip = '203.0.113.81'") $(traffic_value uri "ip = '203.0.113.81'")"
check "  ...with the referrer"       "https://www.example.com/where-they-came-from" "$(traffic_value referrer "ip = '203.0.113.81'")"
check "  ...and the User-Agent"      "$MOZ" "$(traffic_value user_agent "ip = '203.0.113.81'")"
status 203.0.113.82 "$MOZ" "$U/no-such-page/" > /dev/null
check "404 recorded"                 404 "$(traffic_value status "ip = '203.0.113.82'")"
status 203.0.113.82 "$MOZ" "$U/wp-admin/" > /dev/null
check "redirect recorded"            302 "$(traffic_value status "ip = '203.0.113.82' AND uri = '/wp-admin/'")"
status 203.0.113.83 "$MOZ" "$U/.env" > /dev/null
check "blocked request recorded"     403 "$(traffic_value status "ip = '203.0.113.83'")"
status 203.0.113.84 "" "$U/" > /dev/null
check "no User-Agent: unknown, 403"  "unknown 403" "$(traffic_value client "ip = '203.0.113.84'") $(traffic_value status "ip = '203.0.113.84'")"
status 203.0.113.85 "$GOOGLEBOT" "$U/" > /dev/null
check "Googlebot: search engine"     search_engine "$(traffic_value client "ip = '203.0.113.85'")"
status 203.0.113.86 "curl/8.4.0" "$U/" > /dev/null
check "curl: script or tool"         tool "$(traffic_value client "ip = '203.0.113.86'")"
status 203.0.113.87 "$MOZ" "$U/wp-login.php?action=rp&key=TOPSECRET123&login=nobody" > /dev/null
check "reset key not stored"         0 "$(traffic_count "uri LIKE '%TOPSECRET%'")"
check "  ...URL kept without it"     1 "$(traffic_count "uri = '/wp-login.php?action=rp&key=[removed]&login=nobody'")"
curl -s -o /dev/null -H "X-Real-IP: 203.0.113.88" -A "$MOZ" "$U/wp-cron.php?doing_wp_cron=1"
check "WP-Cron not recorded"         0 "$(traffic_count "ip = '203.0.113.88'")"
set_settings '$s["traffic"]["skip_background"] = false'
curl -s -o /dev/null -H "X-Real-IP: 203.0.113.88" -A "$MOZ" "$U/wp-cron.php?doing_wp_cron=1"
check "  ...unless asked"            1 "$(traffic_count "ip = '203.0.113.88'")"
set_settings '$s["traffic"]["skip_background"] = true'
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=traffic" > /dev/null
check "admin's request recorded"     1 "$(traffic_value user_id "ip = '198.51.100.50'")"
check "Traffic tab lists requests"   1 "$( [ "$(grep -o 'wpb-status-[0-9]xx' "$WORK/admin.html" | wc -l)" -ge 8 ] && echo 1 || echo 0 )"
check "  ...shows the referrer"      1 "$(count_in 'https://www.example.com/where-they-came-from' "$WORK/admin.html")"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=traffic&client=search_engine" > /dev/null
check "filter by client"             "1 0" "$(grep -o 'class="wpb-badge wpb-client-search_engine"' "$WORK/admin.html" | wc -l | tr -d ' ') $(grep -o 'class="wpb-badge wpb-client-browser"' "$WORK/admin.html" | wc -l | tr -d ' ')"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=traffic&status=4xx" > /dev/null
check "filter by response"           0 "$(grep -o 'wpb-status-[235]xx' "$WORK/admin.html" | wc -l | tr -d ' ')"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=traffic&ip=203.0.113.82" > /dev/null
check "filter by IP"                 2 "$(grep -o 'class="wpb-badge wpb-status-' "$WORK/admin.html" | wc -l | tr -d ' ')"
EXPORT=$(grep -o 'href="[^"]*action=wp_bouncer_export_traffic[^"]*"' "$WORK/admin.html" | head -1 | sed 's/^href="//; s/"$//; s/&amp;/\&/g; s/&#038;/\&/g')
curl -s -o "$WORK/traffic.csv" -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$EXPORT"
check "CSV export"                   "time_utc,ip,client,method,url,status,referrer,user_agent,user_id" "$(head -1 "$WORK/traffic.csv")"
check "  ...keeps the filter"        2 "$(grep -c '203.0.113.82' "$WORK/traffic.csv")"
set_settings '$s["traffic"]["skip_admins"] = true'
$WP eval 'WPBouncer\Plugin::instance()->traffic_log()->clear();'
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=traffic" > /dev/null
check "skip administrators"          0 "$(traffic_count "ip = '198.51.100.50'")"
set_settings '$s["traffic"]["skip_admins"] = false'
# "wp cron event run" reschedules a recurring event for now + 1 hour and then unschedules the old slot. When
# two runs start within the same second the new slot IS the old one, the event vanishes and the next run
# fails with "Invalid cron event" (seen on fast CI runners). Putting the event in the past first keeps the slots apart.
run_purge() {
	$WP eval 'wp_clear_scheduled_hook( "wp_bouncer_traffic_purge" ); wp_schedule_event( time() - 60, "hourly", "wp_bouncer_traffic_purge" );'
	$WP cron event run wp_bouncer_traffic_purge > /dev/null
}
# Old rows: 8 days, 2 days and 1 hour ago.
$WP eval 'global $wpdb; foreach ( array( 8 * DAY_IN_SECONDS, 2 * DAY_IN_SECONDS, HOUR_IN_SECONDS ) as $age ) { $wpdb->insert( $wpdb->prefix . "bouncer_traffic", array( "created_at" => gmdate( "Y-m-d H:i:s", time() - $age ), "ip" => "192.0.2.1", "uri" => "/age-" . $age ) ); }'
run_purge
check "7-day retention purges"       "0 1 1" "$(traffic_count "uri = '/age-691200'") $(traffic_count "uri = '/age-172800'") $(traffic_count "uri = '/age-3600'")"
set_settings '$s["traffic"]["retention_days"] = 1'
run_purge
check "1-day retention purges"       "0 1" "$(traffic_count "uri = '/age-172800'") $(traffic_count "uri = '/age-3600'")"
set_settings '$s["traffic"]["retention_days"] = 99'   # stored behind the form's back
$WP eval 'global $wpdb; $wpdb->insert( $wpdb->prefix . "bouncer_traffic", array( "created_at" => gmdate( "Y-m-d H:i:s", time() - 8 * DAY_IN_SECONDS ), "ip" => "192.0.2.1", "uri" => "/age-old" ) );'
run_purge
check "never kept past 7 days"       0 "$(traffic_count "uri = '/age-old'")"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_save traffic)&action=wp_bouncer_save&tab=traffic&wp_bouncer[traffic][enabled]=1&wp_bouncer[traffic][retention_days]=3&wp_bouncer[traffic][skip_background]=1" > /dev/null
check "Traffic tab saves settings"   "1 3" "$($WP eval '$t = WPBouncer\Settings::load()->get("traffic"); echo (int) $t["enabled"], " ", $t["retention_days"];')"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_clear_traffic traffic)&action=wp_bouncer_clear_traffic" > /dev/null
check "Clear traffic log"            0 "$(traffic_count "ip <> '198.51.100.50'")"
set_settings '$s["traffic"]["enabled"] = false'
status 203.0.113.89 "$MOZ" "$U/" > /dev/null
check "switched off: not recorded"   0 "$(traffic_count "ip = '203.0.113.89'")"

echo "==> IP trust (header ignored without trusted proxies, loopback, setup notice)"
ipsetup_nonce() { nonce_for wp_bouncer_ip_setup dashboard; }
stored_ip() { $WP eval '$s = get_option( "wp_bouncer_settings" ); echo $s["ip_source"] . "|" . implode( ",", $s["trusted_proxies"] );'; }
# Loopback as the forwarded address is refused: the request resolves to the proxy, which is never
# banned itself; requests carrying a refused header are counted and banned under "rejected:<proxy>".
check "loopback header: probe refused"  403 "$(status 127.0.0.1 "$MOZ" "$U/.env")"
check "  ...refused-header subject banned" 403 "$(status 127.0.0.1 "$MOZ" "$U/")"
check "  ...but visitors via the proxy fine" 200 "$(status 203.0.113.150 "$MOZ" "$U/")"
check "private header: probe refused"   403 "$(status 10.1.2.3 "$MOZ" "$U/.env")"
check "  ...proxy is not banned"        200 "$(status 203.0.113.151 "$MOZ" "$U/")"
# No trusted proxies: the header is ignored, the connection address (127.0.0.1) is used and not banned.
set_settings '$s["trusted_proxies"] = []'
check "no proxies: probe still refused" 403 "$(status 203.0.113.141 "$MOZ" "$U/.env")"
check "  ...but nobody is banned"       200 "$(status 203.0.113.141 "$MOZ" "$U/")"
check "  ...and not the proxy either"   200 "$(status 203.0.113.142 "$MOZ" "$U/")"
# The notice, on every admin screen.
check "dashboard loads"                 200 "$(admin "$U/wp-admin/index.php")"
check "setup notice shown"              1 "$(grep -c 'wpb-ip-setup' "$WORK/admin.html")"
check "  ...not dismissible"            0 "$(grep 'wpb-ip-setup' "$WORK/admin.html" | grep -c 'is-dismissible')"
check "  ...offers to trust the peer"   1 "$(grep -c 'Trust 127.0.0.1 as my proxy' "$WORK/admin.html")"
check "  ...or to use the connection"   1 "$(grep -c 'I have no proxy' "$WORK/admin.html")"
check "no PHP errors in the notice"     0 "$(grep -c 'Fatal error\|Warning:\|Notice:\|Deprecated:' "$WORK/admin.html")"
check "fix needs a valid nonce"         403 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=deadbeef00&action=wp_bouncer_ip_setup&fix=trust_peer&header=x_real_ip")"
check "  ...nothing changed"            "x_real_ip|" "$(stored_ip)"
# No handler is registered for logged-out visitors. WordPress 5.9+ answers an unhandled admin-post action
# with 400; 5.8 and older run no hook and send an empty 200. Either way nothing runs (checked below).
logged_out_code=$(curl -s -o "$WORK/logged-out.html" -w '%{http_code}' -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -d "_wpnonce=$(ipsetup_nonce)&action=wp_bouncer_ip_setup&fix=trust_peer&header=x_real_ip" "$U/wp-admin/admin-post.php")
if [ "$logged_out_code" = 200 ] && [ ! -s "$WORK/logged-out.html" ]; then logged_out_code=400; fi
check "fix is not reachable logged out"   400 "$logged_out_code"
check "  ...and changed nothing"        "x_real_ip|" "$(stored_ip)"
check "Trust-peer button works"         302 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(ipsetup_nonce)&action=wp_bouncer_ip_setup&fix=trust_peer&header=x_real_ip&peer=127.0.0.1")"
check "  ...proxy added"                "x_real_ip|127.0.0.1" "$(stored_ip)"
check "  ...visitor IPs honoured again" 403 "$(status 203.0.113.143 "$MOZ" "$U/.env")"
check "  ...and bans work again"        403 "$(status 203.0.113.143 "$MOZ" "$U/")"
check "  ...notice gone"                0 "$(admin "$U/wp-admin/index.php" > /dev/null; grep -c 'wpb-ip-setup' "$WORK/admin.html")"
set_settings '$s["trusted_proxies"] = []'
check "No-proxy button works"           302 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(ipsetup_nonce)&action=wp_bouncer_ip_setup&fix=use_remote_addr")"
check "  ...source is the connection"   "remote_addr|" "$(stored_ip)"
# remote_addr behind a same-host proxy: loopback plus a forwarding header is not the server itself.
check "remote_addr: forwarded probe"    403 "$(status 203.0.113.144 "$MOZ" "$U/.env")"
check "  ...notice offers the header"   1 "$(admin "$U/wp-admin/index.php" > /dev/null; grep -c 'Read the IP from X-Real-IP and trust 127.0.0.1' "$WORK/admin.html")"
# A request from the server itself (loopback, no forwarding header) still skips every rule.
check "server itself: not a probe"      404 "$(curl -s -o /dev/null -w '%{http_code}' -A "$MOZ" "$U/.env")"
set_settings '$s["ip_source"] = "x_real_ip"; $s["trusted_proxies"] = ["127.0.0.1"]'
check "restored: header honoured"       403 "$(status 203.0.113.145 "$MOZ" "$U/.env")"
check "  ...others unaffected"          200 "$(status 203.0.113.146 "$MOZ" "$U/")"

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
define( 'WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS', true );
add_filter( 'wp_bouncer_update_manifest_url', function () { return '$FILES_URL/update.json'; } );
add_filter( 'wp_bouncer_update_package_prefix', function () { return '$FILES_URL/'; } );
add_filter( 'http_request_host_is_external', '__return_true' );
PHPEOF

publish() { # publish VERSION -> a plugin zip with that version and its update.json on the stand-in server
	local v=$1 rel="$WORK/release/wp-bouncer"
	rm -rf "$WORK/release" && mkdir -p "$WORK/release"
	cp -R "$PLUGIN_DIR" "$rel"
	sed -i.bak -e "s/^ \* Version: .*/ * Version:           $v/" -e "s/'WP_BOUNCER_VERSION', '[^']*'/'WP_BOUNCER_VERSION', '$v'/" "$rel/wp-bouncer.php"
	sed -i.bak -e "s/VERSION = '[^']*'/VERSION = '$v'/" "$rel/src/Plugin.php"
	find "$rel" -name '*.bak' -delete
	printf '## [%s] - 2026-01-01\n\n### Added\n- Release %s for the e2e update test.\n' "$v" "$v" > "$WORK/release/CHANGELOG.md"
	# The manifest check wants exactly <prefix>v<version>/wp-bouncer-<version>.zip.
	mkdir -p "$FILES/v$v"
	rm -f "$FILES/v$v/wp-bouncer-$v.zip"
	(cd "$WORK/release" && zip -qrX "$FILES/v$v/wp-bouncer-$v.zip" wp-bouncer)
	"$PHP" "$REPO_DIR/scripts/build-manifest.php" --zip "$FILES/v$v/wp-bouncer-$v.zip" --plugin-dir "$rel" \
		--changelog "$WORK/release/CHANGELOG.md" --package-url "$FILES_URL/v$v/wp-bouncer-$v.zip" \
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
		-d "action=update-plugin&plugin=wp-bouncer%2Fwp-bouncer.php&slug=wp-bouncer&_ajax_nonce=$nonce" "$U/wp-admin/admin-ajax.php" | tee "$WORK/update-now.json"
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
rm -f "$MAILLOG"
check "Update now succeeds"          1    "$(update_now | grep -c '"success":true')"
check "  ...new version installed"   9.0.0 "$(installed_version)"
check "  ...still active"            active "$($WP plugin get wp-bouncer --field=status)"
check "  ...update alert sent"       1    "$(count_in 'Plugin updated: WP Bouncer' "$MAILLOG")"
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
# wp_maybe_auto_update() also updates WordPress itself, themes and translations; on an old WordPress
# under test it would upgrade core to the latest release mid-run, so only plugins are allowed.
$WP eval 'define( "DOING_CRON", true ); add_filter( "auto_update_core", "__return_false" ); add_filter( "auto_update_theme", "__return_false" ); add_filter( "auto_update_translation", "__return_false" ); wp_maybe_auto_update();'
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
