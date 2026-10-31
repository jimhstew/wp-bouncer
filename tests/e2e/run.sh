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
#   WPB_E2E_WP_VERSION=latest latest | nightly | a version such as 7.0 or 7.1.3.
#                         WordPress is unpacked into $WPB_E2E_DIR/wordpress-<db>-<version>, so a
#                         reused work directory never mixes databases or versions.
#   WPB_E2E_CACHE=dir     Download cache (default builds/e2e-cache, which is git-ignored). WordPress,
#                         wp-cli and the SQLite plugin are fetched once and reused. Every file is
#                         checked against its checksum each time it is used and fetched again if it
#                         does not match, so a corrupted cache is never used. WordPress is cached
#                         per version; "latest" is resolved through api.wordpress.org (falling back
#                         to the newest cached release when offline); "nightly" is reused for 3 hours.
#   WPB_E2E_ONLY="Updates,Traffic"  Local debugging only: run setup plus just the sections whose
#                         "==> " heading contains any of these comma-separated words (case-insensitive).
#                         The summary says it was a partial run. Sections that need earlier state run
#                         it themselves: "Emergency switch" runs "Brute-force protection" first and
#                         "Admin screens" runs "Bad visitors" first. Others stand alone (a few counts,
#                         such as the Activity Log, only make sense after the whole suite).
#                         CI never sets it.
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
	*) echo "WPB_E2E_WP_VERSION must be latest, nightly or a version like 7.0"; exit 1 ;;
esac
case "$DB_NAME" in ""|*[!A-Za-z0-9_]*) echo "WPB_E2E_DB_NAME may only contain letters, digits and _"; exit 1 ;; esac
W="$WORK/wordpress-$DB-$WPV"
WP="$PHP -d memory_limit=512M $WORK/wp-cli.phar --path=$W --quiet"

CACHE=${WPB_E2E_CACHE:-$REPO_DIR/builds/e2e-cache}
ONLY=${WPB_E2E_ONLY:-}
SECTIONS_RAN=""

pass=0
fail=0
SERVER_PID=""

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
selected() { # selected HEADING -> 0 if WPB_E2E_ONLY names it (or is empty: everything runs)
	[ -z "$ONLY" ] && return 0
	local h t; h=$(lower "$1")
	local IFS=,
	for t in $ONLY; do
		t=$(lower "$t"); t=${t# }; t=${t% }
		[ -n "$t" ] && case "$h" in *"$t"*) return 0 ;; esac
	done
	return 1
}
want() { # want HEADING -> prints the heading and returns 0 if the section should run
	local reason=""
	if ! selected "$1"; then
		# Sections whose state later sections build on run when those are selected.
		case "$1" in
			"Brute-force protection") selected "Emergency switch" && reason="needed by Emergency switch" ;;
			"Bad visitors") selected "Admin screens" && reason="needed by Admin screens" ;;
		esac
		[ -n "$reason" ] || return 1
		reason=" ($reason)"
	fi
	SECTIONS_RAN="$SECTIONS_RAN$1$reason
"
	echo "==> $1$reason"
}
if [ -n "$ONLY" ]; then   # fail early on a word that matches nothing
	headings=$(grep -o '^if want "[^"]*"' "${BASH_SOURCE[0]}" | cut -d'"' -f2)
	IFS=, read -r -a terms <<< "$ONLY"
	for t in "${terms[@]}"; do
		t=$(lower "$t"); t=${t# }; t=${t% }
		[ -n "$t" ] && [ -z "$(lower "$headings" | grep -F -- "$t")" ] && { printf 'WPB_E2E_ONLY: no section matches "%s". Sections:\n%s\n' "$t" "$headings"; exit 1; }
	done
	echo "!!! PARTIAL RUN: WPB_E2E_ONLY=\"$ONLY\". Not a substitute for the full suite."
fi

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

login() { # login IP USER PASS [curl args...] -> writes page to $WORK/login.html, prints status
	local ip=$1 user=$2 pass=$3; shift 3
	curl -s -o "$WORK/login.html" -w '%{http_code}' -H "X-Real-IP: $ip" -A "Mozilla/5.0" \
		-b "wordpress_test_cookie=WP%20Cookie%20check" "$@" \
		-d "log=$user&pwd=$pass&wp-submit=Log+In&testcookie=1" "$U/wp-login.php"
}

settings_php() { # settings_php 'PHP code that edits $s' -> PHP that loads, edits and saves the settings (to join with other code in one wp eval)
	printf '%s' "\$s = get_option('wp_bouncer_settings'); $1; update_option('wp_bouncer_settings', \$s);"
}
set_settings() { # set_settings 'PHP code that edits $s' ['PHP to run first']
	$WP eval "${2:-} $(settings_php "$1")"
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

mkdir -p "$CACHE" || { echo "cannot create download cache $CACHE"; exit 1; }
matches() { [ "$(hash_of "$1" "$2" 2>/dev/null)" = "$3" ]; }   # matches ALGO FILE EXPECTED
# cached_file CACHEFILE ALGO EXPECTED URL LABEL -> a verified copy at CACHEFILE. A cached file that does
# not match its checksum is deleted and fetched again; a fresh download that does not match is fatal.
cached_file() {
	if [ -f "$1" ] && matches "$2" "$1" "$3"; then return 0; fi
	[ -f "$1" ] && echo "    cached $5 failed its checksum: downloading it again"
	rm -f "$1"
	curl -sfLo "$1.part" "$4" || { rm -f "$1.part"; echo "download $5 failed"; exit 1; }
	verify "$2" "$1.part" "$3" "$5"
	mv "$1.part" "$1"
}
cached_file "$CACHE/wp-cli-${WPCLI_VERSION}.phar" 512 "$WPCLI_SHA512" \
	"https://github.com/wp-cli/wp-cli/releases/download/v${WPCLI_VERSION}/wp-cli-${WPCLI_VERSION}.phar" "wp-cli ${WPCLI_VERSION}"
cp "$CACHE/wp-cli-${WPCLI_VERSION}.phar" wp-cli.phar
# The copy that runs must match the pin too.
verify 512 wp-cli.phar "$WPCLI_SHA512" "wp-cli ${WPCLI_VERSION}"

# WordPress tarball for one release, cached with the .sha1 WordPress.org published for it.
cached_wordpress() { # cached_wordpress VERSION -> path of a verified tarball in $WP_TARBALL
	local v=$1 f="$CACHE/wordpress-$1.tar.gz" want
	WP_TARBALL=$f
	if [ -f "$f" ] && [ -f "$f.sha1" ]; then
		want=$(tr -d '[:space:]' < "$f.sha1")
		if [ -n "$want" ] && matches 1 "$f" "$want"; then return 0; fi
		echo "    cached WordPress $v failed its checksum: downloading it again"
	fi
	rm -f "$f" "$f.sha1"
	fetch_wordpress "https://wordpress.org/wordpress-$v.tar.gz" "$f.part" || { rm -f "$f.part"; echo "download WordPress ($v) failed"; exit 1; }
	hash_of 1 "$f.part" > "$f.sha1.part"   # fetch_wordpress just proved this equals the digest WordPress.org published
	mv "$f.part" "$f"; mv "$f.sha1.part" "$f.sha1"
}
resolve_latest() { # newest stable WordPress version, from the update API; empty on failure
	curl -sfL --max-time 20 "https://api.wordpress.org/core/version-check/1.7/" | "$PHP" -r '$j = json_decode( stream_get_contents( STDIN ), true ); $v = $j["offers"][0]["version"] ?? ""; echo preg_match( "/^[0-9]+(\\.[0-9]+){1,2}$/", $v ) ? $v : "";' 2>/dev/null
}
if [ "$WPV" = nightly ]; then rm -rf "$W"; fi   # a moving target: always unpack it again
if [ ! -d "$W" ]; then
	DL="$WORK/download.$$"
	rm -rf "$DL"; mkdir -p "$DL"
	if [ "$WPV" = nightly ]; then
		NF="$CACHE/wordpress-nightly.zip"
		# Reuse for 3 hours, but only if it still unzips and matches the hash recorded when it was fetched.
		if [ -f "$NF" ] && [ -n "$(find "$NF" -mmin -180 2>/dev/null)" ] && [ -f "$NF.sha256" ] \
			&& matches 256 "$NF" "$(tr -d '[:space:]' < "$NF.sha256")" && unzip -tq "$NF" > /dev/null 2>&1; then :
		else
			rm -f "$NF" "$NF.sha256"
			fetch_wordpress "$WP_URL" "$NF.part" && unzip -tq "$NF.part" > /dev/null 2>&1 || { rm -f "$NF.part"; echo "download WordPress ($WPV) failed"; exit 1; }
			hash_of 256 "$NF.part" > "$NF.sha256"; mv "$NF.part" "$NF"
		fi
		unzip -q "$NF" -d "$DL" || { echo "unpacking WordPress ($WPV) failed"; exit 1; }
	else
		if [ "$WPV" = latest ]; then
			LATEST=$(resolve_latest)
			if [ -z "$LATEST" ]; then   # offline: the newest cached release, which is still checksum-verified
				LATEST=$(ls -t "$CACHE"/wordpress-[0-9]*.tar.gz 2>/dev/null | head -1 | sed -E 's#.*/wordpress-(.*)\.tar\.gz#\1#')
				[ -n "$LATEST" ] || { echo "cannot find out the latest WordPress version and nothing is cached"; exit 1; }
				echo "    (could not reach api.wordpress.org: using cached WordPress $LATEST)"
			fi
			echo "    WordPress latest = $LATEST"
			cached_wordpress "$LATEST"
		else
			cached_wordpress "$WPV"
		fi
		tar xzf "$WP_TARBALL" -C "$DL" || { echo "unpacking WordPress ($WPV) failed"; exit 1; }
	fi
	mv "$DL/wordpress" "$W" || { echo "unpacking WordPress ($WPV) failed"; exit 1; }
	rm -rf "$DL"
fi
if [ "$DB" = sqlite ]; then
	if [ ! -d "$W/wp-content/plugins/sqlite-database-integration" ]; then
		SQ="$CACHE/sqlite-database-integration.${SQLITE_PLUGIN_VERSION}.zip"
		cached_file "$SQ" 256 "$SQLITE_PLUGIN_SHA256" "https://downloads.wordpress.org/plugin/sqlite-database-integration.${SQLITE_PLUGIN_VERSION}.zip" "sqlite-database-integration ${SQLITE_PLUGIN_VERSION}"
		unzip -q "$SQ" -d "$W/wp-content/plugins/"
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
# Pretty permalinks, as almost every live site has: with plain ones, WordPress
# answers most unknown paths with the home page or a redirect, not a 404.
$WP plugin activate wp-bouncer
$WP eval 'update_option("siteurl", "'"$U"'"); update_option("home", "'"$U"'"); global $wp_rewrite; $wp_rewrite->set_permalink_structure("/%postname%/"); flush_rewrite_rules(false); $d = WPBouncer\Settings::defaults(); $d["ip_source"] = "x_real_ip"; $d["trusted_proxies"] = ["127.0.0.1"]; update_option("wp_bouncer_settings", $d); global $wpdb; $wpdb->query("DELETE FROM {$wpdb->prefix}bouncer_log"); $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE \"%transient%wpb\_%\"");'
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
# OPcache stays on (it halves the run time: WordPress is not recompiled on every request) but checks the
# file's timestamp on every request (validate_timestamps=1, revalidate_freq=0) and resolves paths again
# (revalidate_path=1). The update tests swap the linked plugin folder for a copy; with OPcache's defaults
# (a 2 second revalidation interval, cached path lookups) it kept serving the compiled plugin under the old,
# linked path, so __FILE__ pointed at the source folder and the updater could not recognise its own plugin
# file ("The plugin is at the latest version"). With these settings the Updates section passed on every run.
PHP_CLI_SERVER_WORKERS=4 "$PHP" -d max_execution_time=30 -d upload_max_filesize=2M -d post_max_size=8M -d display_errors=0 \
	-d opcache.enable=1 -d opcache.validate_timestamps=1 -d opcache.revalidate_freq=0 -d opcache.revalidate_path=1 -S "127.0.0.1:$PORT" -t "$W" "$WORK/router.php" > "$WORK/server.log" 2>&1 &
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

J="$WORK/cookies.txt"
admin_login() { # the admin session the admin screens use (cookie jar $J)
	rm -f "$J"
	curl -s -o /dev/null -c "$J" -b "wordpress_test_cookie=WP%20Cookie%20check" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" \
		-d "log=admin_e2e&pwd=e2e-pass-123&wp-submit=Log+In&testcookie=1" "$U/wp-login.php"
}
[ -n "$ONLY" ] && admin_login   # a partial run may skip the section that normally logs in
# Helpers for the admin screens, shared by several sections (so a partial run has them).
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

count_in() { # count_in TEXT FILE -> matching lines in FILE (0 if it doesn't exist)
	if [ -f "$2" ]; then grep -cF -- "$1" "$2"; else echo 0; fi
}
mail_count() { count_in '"subject"' "$MAILLOG"; }
open_panels() { # open_panels -> comma-separated rule rows of the Rules tab in $WORK/admin.html whose Settings panel is open
	"$PHP" -r 'preg_match_all("/<div class=\"wpb-rule\" id=\"(rule-[a-z_]+)\".*?(?=<div class=\"wpb-rule\" id=|<\/section>)/s", file_get_contents($argv[1]), $m, PREG_SET_ORDER); $o = array(); foreach ($m as $r) { if (preg_match("/<details class=\"wpb-rule-settings\" open>/", $r[0])) { $o[] = $r[1]; } } echo implode(",", $o);' "$WORK/admin.html"
}
# Reads (and a few plain writes) that need no WordPress code go straight to the database: booting
# WordPress through WP-CLI costs about 250 ms a time, this about 20 ms. Use a "wp eval" only where the
# plugin's own code has to run. Tables are wp_*. dbq prints one line per row, columns separated by tabs
# (NULL as an empty string):
#   dbq "SELECT ..."                  rows of a query
#   dbq "DELETE ..." / "INSERT ..."   run a statement
#   dbq_opt NAME 'PHP using $o'       evaluate PHP on the unserialized value of option NAME ($o is null when it is missing)
cat > "$WORK/dbq.php" <<'PHPEOF'
<?php
mysqli_report( MYSQLI_REPORT_OFF );
$mode = $argv[1];
$arg  = $argv[2];
$expr = $argv[3] ?? '';
if ( 'sqlite' === getenv( 'WPB_Q_DB' ) ) {
	$pdo = new PDO( 'sqlite:' . getenv( 'WPB_Q_SQLITE' ) );
	$pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	$pdo->setAttribute( PDO::ATTR_TIMEOUT, 20 );
	$run = static function ( string $sql ) use ( $pdo ) {
		if ( preg_match( '/^\s*select/i', $sql ) ) {
			return $pdo->query( $sql )->fetchAll( PDO::FETCH_NUM );
		}
		$pdo->exec( $sql );
		return array();
	};
} else {
	$h = getenv( 'WPB_Q_HOST' ); $port = 3306;
	if ( preg_match( '/^(.*):([0-9]+)$/', $h, $m ) ) { $h = $m[1]; $port = (int) $m[2]; }
	$c = mysqli_init();
	if ( ! @$c->real_connect( $h, getenv( 'WPB_Q_USER' ), getenv( 'WPB_Q_PASS' ), getenv( 'WPB_Q_NAME' ), $port ) ) { fwrite( STDERR, "dbq: connect failed\n" ); exit( 1 ); }
	$c->set_charset( 'utf8mb4' );
	$run = static function ( string $sql ) use ( $c ) {
		$r = $c->query( $sql );
		if ( false === $r ) { fwrite( STDERR, 'dbq: ' . $c->error . "\n" ); exit( 1 ); }
		return true === $r ? array() : $r->fetch_all( MYSQLI_NUM );
	};
}
if ( 'opt' === $mode ) {
	$q   = "SELECT option_value FROM wp_options WHERE option_name = '" . str_replace( "'", "''", $arg ) . "'";
	$row = $run( $q )[0] ?? null;
	$o   = null === $row ? null : maybe_unserialize_e2e( $row[0] );
	eval( $expr );
	exit( 0 );
}
foreach ( $run( $arg ) as $row ) {
	echo implode( "\t", array_map( 'strval', $row ) ), "\n";
}
function maybe_unserialize_e2e( $v ) {
	$u = @unserialize( $v );
	return ( false === $u && 'b:0;' !== $v ) ? $v : $u;
}
PHPEOF
if [ "$DB" = sqlite ]; then
	# The SQLite plugin keeps the file at the path its db-path.php returns (newer versions), or in wp-content/database/.ht.sqlite.
	export WPB_Q_DB=sqlite WPB_Q_SQLITE="$("$PHP" -r 'define( "ABSPATH", $argv[1] . "/" ); $d = $argv[1] . "/wp-content/database/"; echo is_file( $d . "db-path.php" ) ? require $d . "db-path.php" : $d . ".ht.sqlite";' "$W")"
else
	export WPB_Q_DB=mysql WPB_Q_HOST="$DB_HOST" WPB_Q_USER="$DB_USER" WPB_Q_PASS="$DB_PASSWORD" WPB_Q_NAME="$DB_NAME"
fi
dbq() { # dbq SQL -> rows (the first row's single value, usually), tab-separated
	local out; out=$("$PHP" "$WORK/dbq.php" sql "$1") || { echo "dbq failed: $1" >&2; return 1; }
	printf '%s' "${out%$'\n'}"   # the last newline goes, as with $(...) anywhere else; inner ones stay
}
dbq_opt() { "$PHP" "$WORK/dbq.php" opt "$1" "$2"; }
log_value() { # log_value COLUMN "WHERE ..." -> first matching value from the bouncer log
	dbq "SELECT $1 FROM wp_bouncer_log WHERE $2 ORDER BY id DESC LIMIT 1"
}

if want "Normal traffic"; then
check "home page"                    200 "$(status 203.0.113.10 "$MOZ" "$U/")"
check "search"                       200 "$(status 203.0.113.10 "$MOZ" "$U/?s=hello+world")"
check "REST posts endpoint"          200 "$(status 203.0.113.10 "$MOZ" "$U/?rest_route=/wp/v2/posts")"

fi
if want "Bad visitors"; then
check "scanner User-Agent"           403 "$(status 203.0.113.21 "sqlmap/1.7" "$U/")"
check "empty User-Agent"             403 "$(status 203.0.113.22 "" "$U/")"
check "xmlrpc.php"                   403 "$(status 203.0.113.23 "$MOZ" "$U/xmlrpc.php")"
check "?author=1 scan"               403 "$(status 203.0.113.24 "$MOZ" "$U/?author=1")"
check "REST user listing"            403 "$(status 203.0.113.25 "$MOZ" "$U/?rest_route=/wp/v2/users")"
check "WAF: XSS"                     403 "$(status 203.0.113.26 "$MOZ" "$U/?s=%3Cscript%3Ealert(1)%3C/script%3E")"
check "WAF: SQL injection"           403 "$(status 203.0.113.27 "$MOZ" "$U/?id=1%27%20UNION%20SELECT%20user_pass%20FROM%20wp_users--")"
check "WAF: path traversal"          403 "$(status 203.0.113.28 "$MOZ" "$U/?file=../../../../etc/passwd")"
check "users sitemap removed"        404 "$(status 203.0.113.10 "$MOZ" "$U/wp-sitemap-users-1.xml")"
check "xmlrpc.php/PATH_INFO"         403 "$(status 203.0.113.44 "$MOZ" "$U/xmlrpc.php/x")"
check "?author=1abc scan"            403 "$(status 203.0.113.45 "$MOZ" "$U/?author=1abc")"
check "?author_name= scan"           403 "$(status 203.0.113.46 "$MOZ" "$U/?author_name=admin_e2e")"
check "fake /wp-admin/ path scan"     403 "$(status 203.0.113.49 "$MOZ" "$U/index.php/wp-admin/?author=1")"
check "?author=1 in a POST body"     403 "$(status 203.0.113.50 "$MOZ" "$U/" -X POST -d author=1)"
WAF_PAD=$(head -c 12000 /dev/zero | tr '\0' 'a')
check "WAF: XSS after 12 KB padding" 403 "$(status 203.0.113.47 "$MOZ" "$U/" -X POST --data-urlencode "comment=${WAF_PAD}<script>alert(1)</script>")"
check "WAF: long benign POST"        200 "$(status 203.0.113.48 "$MOZ" "$U/" -X POST --data-urlencode "comment=${WAF_PAD} hello world")"
check "WAF: JSON body SQL injection" 403 "$(status 203.0.113.51 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: application/json' --data '{"title":"x","meta":{"k":"1'"'"' UNION SELECT user_pass FROM wp_users--"}}')"
check "WAF: benign JSON body"        401 "$(status 203.0.113.52 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: application/json' --data '{"title":"Hello world","content":"A normal post"}')"
check "WAF: JSON payload in a content-type list" 403 "$(status 203.0.113.53 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: text/plain, application/json' --data '{"title":"1'"'"' UNION SELECT user_pass FROM wp_users--"}')"
check "WAF: JSON payload under text/plain" 403 "$(status 203.0.113.54 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: text/plain' --data '{"title":"<script>alert(1)</script>"}')"
WAF_DEEP=$(head -c 600 /dev/zero | tr '\0' '[')$(head -c 600 /dev/zero | tr '\0' ']')
check "WAF: JSON nested past 512 levels" 403 "$(status 203.0.113.55 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: application/json' --data "$WAF_DEEP")"
check "WAF: broken JSON gets no verdict" 400 "$(status 203.0.113.56 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: application/json' --data '{"title":')"
# A non-admin (editor) saving a post with block-editor markup through the REST API is not blocked.
# One WP-CLI call creates both users (if a reused work directory lacks them) and their application passwords.
read -r -d '' E2E_USERS < <($WP eval '
	$out = array();
	foreach ( array( "editor_e2e" => array( "editor", "e2e-editor-123" ), "sub_e2e" => array( "subscriber", "e2e-sub-123" ) ) as $login => $def ) {
		$u  = get_user_by( "login", $login );
		$id = $u ? $u->ID : wp_insert_user( array( "user_login" => $login, "user_email" => explode( "_", $login )[0] . "@example.test", "role" => $def[0], "user_pass" => $def[1] ) );
		$pw = WP_Application_Passwords::create_new_application_password( $id, array( "name" => "e2e-rest" ) );
		$out[] = $id;
		$out[] = $pw[0];
	}
	echo implode( "\n", $out );
') || true
{ read -r EDITOR_ID; read -r APPPW; read -r SUB_ID; read -r SUBPW; } <<< "$E2E_USERS"
EJ="$WORK/editor-cookies.txt"
curl -s -o /dev/null -c "$EJ" -b "wordpress_test_cookie=WP%20Cookie%20check" -H "X-Real-IP: 198.51.100.57" -A "$MOZ" \
	-d "log=editor_e2e&pwd=e2e-editor-123&wp-submit=Log+In&testcookie=1" "$U/wp-login.php"
ENONCE=$(curl -s -b "$EJ" -H "X-Real-IP: 198.51.100.57" -A "$MOZ" "$U/wp-admin/admin-ajax.php?action=rest-nonce")
WAF_POST='{"title":"Editor post","status":"draft","content":"<!-- wp:paragraph --><p>Some <strong>bold</strong> text, <a href=\"https://example.org/?a=1&amp;b=2\">a link</a>.</p><!-- /wp:paragraph -->"}'
check "editor saves a post over REST" 201 "$(curl -s -o /dev/null -w '%{http_code}' -b "$EJ" -H "X-Real-IP: 198.51.100.57" -A "$MOZ" -H "X-WP-Nonce: $ENONCE" -H 'Content-Type: application/json' --data "$WAF_POST" "$U/?rest_route=/wp/v2/posts")"
WAF_CODE='{"title":"Code tutorial","status":"draft","content":"<!-- wp:html --><iframe src=\"https://example.org/\"></iframe><!-- /wp:html --><!-- wp:code --><pre>eval(x); SELECT a FROM t UNION SELECT b FROM u</pre><!-- /wp:code -->"}'
check "editor saves HTML and code over REST (JSON scan skips editors)" 201 "$(curl -s -o /dev/null -w '%{http_code}' -b "$EJ" -H "X-Real-IP: 198.51.100.57" -A "$MOZ" -H "X-WP-Nonce: $ENONCE" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/?rest_route=/wp/v2/posts")"
# A subscriber is not an editor: the same JSON is refused by the WAF (a WordPress refusal would be a JSON "code" error instead).
SJ="$WORK/sub-cookies.txt"
curl -s -o /dev/null -c "$SJ" -b "wordpress_test_cookie=WP%20Cookie%20check" -H "X-Real-IP: 198.51.100.58" -A "$MOZ" \
	-d "log=sub_e2e&pwd=e2e-sub-123&wp-submit=Log+In&testcookie=1" "$U/wp-login.php"
SNONCE=$(curl -s -b "$SJ" -H "X-Real-IP: 198.51.100.58" -A "$MOZ" "$U/wp-admin/admin-ajax.php?action=rest-nonce")
curl -s -o "$WORK/sub-waf.html" -b "$SJ" -H "X-Real-IP: 198.51.100.58" -A "$MOZ" -H "X-WP-Nonce: $SNONCE" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/?rest_route=/wp/v2/posts"
check "subscriber JSON with code is refused by the WAF" 0 "$(grep -c 'rest_cannot_create' "$WORK/sub-waf.html")"
check "anonymous JSON with code is blocked" 403 "$(status 203.0.113.59 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: application/json' --data "$WAF_CODE")"
# Application-password (Basic) auth must still work with the firewall loaded, and the post must belong to the editor.
mkdir -p "$W/wp-content/mu-plugins"
echo "<?php add_filter( 'wp_is_application_passwords_available', '__return_true' );" > "$W/wp-content/mu-plugins/wpb-e2e-apppw.php"
[ -n "${WPB_E2E_CONTROL:-}" ] && $WP plugin deactivate wp-bouncer
APP_OUT=$(curl -s -w ' HTTP:%{http_code}' -u "editor_e2e:$APPPW" -H "X-Real-IP: 198.51.100.61" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_POST" "$U/?rest_route=/wp/v2/posts")
check "application-password REST save creates the post" 201 "$(echo "$APP_OUT" | sed 's/.*HTTP://')"
check "  ...as the editor"            1 "$(echo "$APP_OUT" | grep -c '"author":'"$EDITOR_ID"'[,}]')"
APP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:$APPPW" -H "X-Real-IP: 198.51.100.61" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/?rest_route=/wp/v2/posts")
check "application-password editor is exempt from the JSON scan" 201 "$APP_CODE"
# An application-password subscriber is not an editor: the same JSON is refused (by the WAF, not by WordPress).
curl -s -o "$WORK/sub-app.html" -u "sub_e2e:$SUBPW" -H "X-Real-IP: 198.51.100.62" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/?rest_route=/wp/v2/posts"
check "app-password subscriber with code: refused by the WAF" 0 "$(grep -c 'rest_cannot_create' "$WORK/sub-app.html")"
# A Basic header with a wrong password: the user stays 0, so the body is scanned as a visitor's (our block page, not core's 401).
check "wrong Basic password with a payload is refused" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:wrong-password" -H "X-Real-IP: 198.51.100.63" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/?rest_route=/wp/v2/posts")"
check "wrong Basic password, benign body: core's 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:wrong-password" -H "X-Real-IP: 198.51.100.63" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_POST" "$U/?rest_route=/wp/v2/posts")"
# A Basic header and a rest_route on a request that never reaches the REST API gets no special treatment.
check "fake Basic header + rest_route on admin-ajax is scanned" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:wrong-password" -H "X-Real-IP: 198.51.100.65" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/wp-admin/admin-ajax.php?rest_route=/x")"
check "fake Basic header + rest_route on admin-post is scanned" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:wrong-password" -H "X-Real-IP: 198.51.100.65" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/wp-admin/admin-post.php?rest_route=/x")"
# Credentials only count where core accepts application passwords (REST, XML-RPC).
check "valid editor credentials on a front-end path give no exemption" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:$APPPW" -H "X-Real-IP: 198.51.100.64" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/contact-us/")"
check "valid editor credentials on admin-ajax give no exemption" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:$APPPW" -H "X-Real-IP: 198.51.100.66" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/wp-admin/admin-ajax.php")"
check "valid editor credentials + rest_route on admin-ajax give no exemption" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:$APPPW" -H "X-Real-IP: 198.51.100.66" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_CODE" "$U/wp-admin/admin-ajax.php?rest_route=/x")"
# Wrong application passwords are counted as login failures, so after the limit the client is locked out and even the right password is refused.
for i in 1 2 3 4 5; do curl -s -o /dev/null -u "editor_e2e:wrongwrongwrongwrong$i" -H "X-Real-IP: 198.51.100.67" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_POST" "$U/?rest_route=/wp/v2/posts"; done
check "locked out after wrong application passwords: the right one is refused" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "editor_e2e:$APPPW" -H "X-Real-IP: 198.51.100.67" -A "$MOZ" -H 'Content-Type: application/json' --data "$WAF_POST" "$U/?rest_route=/wp/v2/posts")"
[ -n "${WPB_E2E_CONTROL:-}" ] && $WP plugin activate wp-bouncer
check "JSON padded with blanks past 1 MB is blocked (anonymous, text/plain)" 403 "$( (head -c 1100000 /dev/zero | tr '\0' ' '; echo '{"a":1}') | status 203.0.113.60 "$MOZ" "$U/?rest_route=/wp/v2/posts" -X POST -H 'Content-Type: text/plain' --data-binary @-)"

fi
if want "Brute-force protection"; then
for i in 1 2 3 4; do login 198.51.100.5 admin_e2e "wrong$i" > /dev/null; done
check "generic login error"          1 "$(grep -c 'username or password you entered is incorrect' "$WORK/login.html")"
check "5th failure still answered"   200 "$(login 198.51.100.5 admin_e2e wrong5)"
check "locked out after 5 failures"  403 "$(login 198.51.100.5 admin_e2e e2e-pass-123)"
login 198.51.100.6 admin x > /dev/null
check "banned username locks out"    403 "$(login 198.51.100.6 admin_e2e e2e-pass-123)"
check "other IPs can still log in"   302 "$(login 198.51.100.7 admin_e2e e2e-pass-123)"
check "cross-site login refused"     200 "$(login 198.51.100.8 admin_e2e e2e-pass-123 -H "Sec-Fetch-Site: cross-site")"
check "  ...with the cross-site error" 1 "$(grep -c 'from another site is not allowed' "$WORK/login.html")"
for i in 1 2 3 4 5 6; do login 198.51.100.8 admin_e2e "wrong$i" -H "Origin: https://evil.example" > /dev/null; done
check "  ...never locks the visitor out" 302 "$(login 198.51.100.8 admin_e2e e2e-pass-123)"
check "login post with Origin: null refused" 200 "$(login 198.51.100.9 admin_e2e e2e-pass-123 -H "Origin: null")"
check "  ...with the cross-site error" 1 "$(grep -c 'from another site is not allowed' "$WORK/login.html")"
check "login with this site's Origin works" 302 "$(login 198.51.100.9 admin_e2e e2e-pass-123 -H "Origin: $U" -H "Sec-Fetch-Site: same-origin")"
# RT-08: twelve parallel guesses from one address. Only the first five may reach the password check.
rm -f "$WORK"/burst-*.html
BURST_PIDS=""
for i in $(seq 1 12); do
	curl -s -o "$WORK/burst-$i.html" -H "X-Real-IP: 198.51.100.8" -A "Mozilla/5.0" -d "log=admin_e2e&pwd=wrong$i&wp-submit=Log+In&testcookie=1" "$U/wp-login.php" &
	BURST_PIDS="$BURST_PIDS $!"
done
wait $BURST_PIDS   # not a bare wait: the web server is also a background job
BURST_CHECKED=$(grep -l 'username or password you entered is incorrect' "$WORK"/burst-*.html 2>/dev/null | wc -l | tr -d ' ')
check "parallel burst: at most 5 checked" 1 "$( [ "$BURST_CHECKED" -le 5 ] && echo 1 || echo 0 )"
check "parallel burst: locked out"    403 "$(login 198.51.100.8 admin_e2e e2e-pass-123)"
# RT-07: failures from different addresses in one IPv6 /64 add up.
for i in 1 2 3 4 5; do login "2001:db8:77:1::$i" admin_e2e "wrong$i" > /dev/null; done
check "IPv6 /64 locked out"           403 "$(login 2001:db8:77:1::ffff admin_e2e e2e-pass-123)"
check "another /64 is not locked"     200 "$(login 2001:db8:77:2::1 admin_e2e wrong1)"

fi
if want "Privacy minimisation"; then
# A mistyped password in the username field must not reach the log, and a secret in a blocked URL is stored redacted.
for i in 1 2 3 4 5; do login 198.51.100.15 "hunter2-e2e-typo" "wrong$i" > /dev/null; done
check "lockout row written"          1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE ip = '198.51.100.15' AND action = 'lockout'")"
check "unknown username not stored"  0 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE reason LIKE '%hunter2-e2e-typo%'")"
check "lockout reason is a count"    1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE ip = '198.51.100.15' AND reason LIKE '%unknown username%'")"
check "scanner with a secret in URL" 403 "$(status 203.0.113.61 "sqlmap/1.7" "$U/?key=E2ESECRETKEY&token=E2ESECRETTOKEN&ok=1")"
check "secret not stored"            0 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE uri LIKE '%E2ESECRET%'")"
check "URI stored redacted"          "/?key=[removed]&token=[removed]&ok=1" "$(dbq "SELECT uri FROM wp_bouncer_log WHERE ip = '203.0.113.61' ORDER BY id DESC LIMIT 1")"

fi
if want "Emergency switch (WP_BOUNCER_DISABLE)"; then
# A must-use plugin loads before plugins, the same as a define in wp-config.php.
mkdir -p "$W/wp-content/mu-plugins"
echo "<?php define( 'WP_BOUNCER_DISABLE', true );" > "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
check "locked-out IP can log in"     302 "$(login 198.51.100.6 admin_e2e e2e-pass-123)"
check "scanner gets in"              200 "$(status 203.0.113.41 "sqlmap/1.7" "$U/")"
check "xmlrpc.php reachable"         1   "$( [ "$(status 203.0.113.42 "$MOZ" "$U/xmlrpc.php")" != 403 ] && echo 1 || echo 0 )"
rm -f "$W/wp-content/mu-plugins/wpb-e2e-disable.php"
check "switch removed: locked again" 403 "$(login 198.51.100.6 admin_e2e e2e-pass-123)"
check "switch removed: scanner out"  403 "$(status 203.0.113.43 "sqlmap/1.7" "$U/")"
$WP eval 'WPBouncer\Plugin::instance()->login_guard()->clear("198.51.100.5");'
check "unlocked IP can log in"       302 "$(login 198.51.100.5 admin_e2e e2e-pass-123)"

fi
if want "Country blocking"; then
set_settings '$s["rules"]["country"] = ["enabled" => true, "mode" => "block", "countries" => ["CN"], "block_unknown" => false, "scope" => "site"]' \
	'$g = WPBouncer\Plugin::instance()->geo_database(); $g->import_file("'"$FIXTURES"'/geo-sample.csv"); update_option(WPBouncer\Plugin::GEO_META_OPTION, ["rows" => $g->count(), "source" => "fixture", "imported" => time()]);'
check "blocked country (CN)"         403 "$(status 1.0.2.5 "$MOZ" "$U/")"
check "other country (AU)"           200 "$(status 1.0.0.5 "$MOZ" "$U/")"
check "unknown country"              200 "$(status 8.8.8.8 "$MOZ" "$U/")"
set_settings '$s["rules"]["country"]["scope"] = "login"'
check "login-only scope: page ok"    200 "$(status 1.0.2.6 "$MOZ" "$U/")"
check "login-only scope: login"      403 "$(status 1.0.2.6 "$MOZ" "$U/wp-login.php")"
set_settings '$s["rules"]["country"]["enabled"] = false'

fi
if want "Rate limiting"; then
set_settings '$s["rules"]["rate_limit"] = ["enabled" => true, "max_requests" => 10, "window_seconds" => 60, "ban_minutes" => 1]'
codes=""; for _ in $(seq 1 11); do codes="$codes$(status 203.0.113.88 "$MOZ" "$U/") "; done
check "10 requests allowed, 11th throttled" "200 200 200 200 200 200 200 200 200 200 429 " "$codes"
set_settings '$s["rules"]["rate_limit"]["enabled"] = false'

fi
if want "Monitor mode"; then
set_settings '$s["mode"] = "monitor"'
check "monitor mode lets scanner in" 200 "$(status 203.0.113.77 "sqlmap/1.7" "$U/")"
check "...but logs it"               monitored "$(dbq "SELECT action FROM wp_bouncer_log WHERE ip = '203.0.113.77' ORDER BY id LIMIT 1")"
set_settings '$s["mode"] = "enforce"'

fi
if want "Settings audit (WP-CLI)"; then
# WPB-8: a settings write outside the admin UI is logged with a non-blank actor.
dbq "DELETE FROM wp_bouncer_log WHERE rule = 'settings'" >/dev/null
$WP option patch update wp_bouncer_settings mode monitor >/dev/null
check "wp option patch: one settings row" 1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE rule = 'settings'")"
AUDIT_REASON=$(dbq "SELECT reason FROM wp_bouncer_log WHERE rule = 'settings' ORDER BY id DESC LIMIT 1")
check "  ...names the actor (not blank)" 1 "$(printf '%s' "$AUDIT_REASON" | grep -Ec '^Settings changed by [^ :]+')"
check "  ...and the key path"            1 "$(printf '%s' "$AUDIT_REASON" | grep -c 'mode')"
check "  ...as an alert row"             alert "$(dbq "SELECT action FROM wp_bouncer_log WHERE rule = 'settings' ORDER BY id DESC LIMIT 1")"
$WP option patch update wp_bouncer_settings mode enforce >/dev/null
check "reverting the mode adds a second row" 2 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE rule = 'settings'")"
$WP option patch update wp_bouncer_settings mode enforce >/dev/null
check "a no-change write adds no row" 2 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE rule = 'settings'")"

fi
if want "Per-rule switches"; then
set_settings '$s["rules"]["user_agent"]["enabled"] = false'
check "User-Agent rule off"          200 "$(status 203.0.113.31 "sqlmap/1.7" "$U/")"
set_settings '$s["rules"]["user_agent"]["enabled"] = true'

fi
if want "Sensitive-file probes"; then
check "/.env refused"                403 "$(status 203.0.113.61 "$MOZ" "$U/.env")"
check "  ...one probe does not ban"  200 "$(status 203.0.113.61 "$MOZ" "$U/")"
check "  ...second probe refused"    403 "$(status 203.0.113.61 "$MOZ" "$U/.env")"
check "  ...prober banned site-wide" 403 "$(status 203.0.113.61 "$MOZ" "$U/")"
check "cross-site probe refused"     403 "$(status 203.0.113.70 "$MOZ" "$U/.env" -H "Sec-Fetch-Site: cross-site")"
check "cross-site probe again"       403 "$(status 203.0.113.70 "$MOZ" "$U/.env" -H "Sec-Fetch-Site: cross-site")"
check "  ...not banned by two"       200 "$(status 203.0.113.70 "$MOZ" "$U/")"
for i in 1 2 3; do status 203.0.113.70 "$MOZ" "$U/.env" -H "Sec-Fetch-Site: cross-site" > /dev/null; done
check "  ...fifth: visitor not banned" 200 "$(status 203.0.113.70 "$MOZ" "$U/")"
check "  ...link click still works"  200 "$(status 203.0.113.70 "$MOZ" "$U/" -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Dest: document")"
check "  ...forged header refused"    403 "$(status 203.0.113.70 "$MOZ" "$U/" -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Dest: image")"
check "own Origin beats cross-site"  403 "$(status 203.0.113.171 "$MOZ" "$U/.env" -H "Sec-Fetch-Site: cross-site" -H "Origin: $U")"
check "  ...so it counts normally"    403 "$(status 203.0.113.171 "$MOZ" "$U/.env" -H "Sec-Fetch-Site: cross-site" -H "Origin: $U")"
check "  ...and bans after two"       403 "$(status 203.0.113.171 "$MOZ" "$U/")"
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

fi
if want "404 flood"; then
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

fi
if want "Admin screens"; then
admin_login
for tab in dashboard general rules countries log traffic tools; do
	out="$WORK/tab-$tab.html"
	code=$(curl -s -o "$out" -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$U/wp-admin/admin.php?page=wp-bouncer&tab=$tab")
	check "admin tab '$tab' loads"     200 "$code"
	check "admin tab '$tab' no PHP errors" 0 "$(grep -c 'Fatal error\|Warning:\|Notice:\|Deprecated:' "$out")"
done
# WPB-10b: drag-to-resize columns. Header attributes on the two tables only; the script is served from the plugin folder.
for tab in log traffic; do
	check "$tab tab loads the column script"   1 "$(grep -c 'assets/columns.js?ver=' "$WORK/tab-$tab.html")"
	check "  ...with the header attribute"     1 "$( [ "$(grep -c 'data-wpb-col="request"' "$WORK/tab-$tab.html")" -ge 1 ] && echo 1 || echo 0 )"
	check "  ...and a hidden reset button"     1 "$(grep -c 'class="button wpb-cols-reset" hidden' "$WORK/tab-$tab.html")"
	check "  ...with its table name, and no nonce" 1 "$(grep -c "wpBouncerCols = {\"table\":\"$tab\"" "$WORK/tab-$tab.html")"
	check "  ...in any script data"            0 "$(grep -o 'wpBouncerCols = {.*' "$WORK/tab-$tab.html" | grep -ci 'nonce')"
done
for tab in dashboard rules; do
	check "$tab tab has no column script or attributes" 0 "$(grep -c 'columns.js\|data-wpb-col\|wpBouncerCols' "$WORK/tab-$tab.html")"
done
check "column script is served"            200 "$(curl -s -o "$WORK/columns.js" -w '%{http_code}' -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$U/wp-content/plugins/wp-bouncer/assets/columns.js")"
check "  ...and is the real file"            1 "$(grep -c 'wpb_cols' "$WORK/columns.js")"
check "log lists blocked entries" 1 "$( [ "$(grep -o 'wpb-badge-blocked' "$WORK/tab-log.html" | wc -l)" -gt 5 ] && echo 1 || echo 0 )"
check "admin is never banned for probes" 404 "$(status 198.51.100.50 "$MOZ" "$U/.env" -b "$J")"
check "  ...still gets in"           200 "$(status 198.51.100.50 "$MOZ" "$U/wp-admin/" -b "$J")"
check "dashboard shows the environment checks" 1 "$(grep -c 'id="wpb-environment"' "$WORK/tab-dashboard.html")"
check "  ...with the database row"   1 "$( [ "$(grep -c 'Database version' "$WORK/tab-dashboard.html")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...and a fixed intro"        1 "$(grep -c 'checks WP Bouncer runs' "$WORK/tab-dashboard.html")"
check "front page has no environment data" 0 "$(curl -s -H "X-Real-IP: 203.0.113.30" -A "$MOZ" "$U/" | grep -c 'wpb-environment\|WP Bouncer runs\|DISALLOW_FILE_EDIT')"

# Dashboard widget (WPB-4): renders for the admin without JavaScript, from the blocks logged above.
WIDGET_FLUSH="DELETE FROM wp_options WHERE option_name LIKE '%wpb_widget_stats%'"   # DashboardWidget::flush(): its transients and their timeouts
dbq "$WIDGET_FLUSH"
admin "$U/wp-admin/index.php" > /dev/null
check "dashboard widget renders for the admin" 1 "$(grep -c 'id="wp_bouncer_dashboard"' "$WORK/admin.html")"
check "  ...with the status line"      1 "$( [ "$(grep -c 'rules on)' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...with counts from the log"  1 "$( [ "$(grep -c 'in the last 24 hours' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...and a link to the Activity Log" 1 "$( [ "$(grep -c 'tab=log' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...and no PHP errors"         0 "$(grep -c 'Fatal error\|Warning:\|Notice:\|Deprecated:' "$WORK/admin.html")"
# Stored XSS: hostile values in every log column. The widget escapes the fields it shows and never shows the rest.
dbq "INSERT INTO wp_bouncer_log (created_at, ip, country, rule, action, reason, method, uri, user_agent) VALUES ('$(date -u '+%Y-%m-%d %H:%M:%S')', '<img src=x onerror=wpbip()>', '', '<script>wpbrule()</script>', 'blocked', '<script>wpbreason()</script>', 'GET', '/<script>wpburi()</script>', '<script>wpbua()</script>')"
dbq "$WIDGET_FLUSH"
admin "$U/wp-admin/index.php" > /dev/null
check "widget escapes a hostile rule name"  1 "$(grep -c '&lt;script&gt;wpbrule()&lt;/script&gt;' "$WORK/admin.html")"
check "  ...and a hostile IP"               1 "$( [ "$(grep -c '&lt;img src=x onerror=wpbip()&gt;' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...no raw script or img from the log" 0 "$(grep -c '<script>wpb\|<img src=x onerror=wpbip' "$WORK/admin.html")"
check "  ...never shows the URI, UA or reason" 0 "$(grep -c 'wpburi\|wpbua\|wpbreason' "$WORK/admin.html")"
dbq "DELETE FROM wp_bouncer_log WHERE rule LIKE '%wpbrule%'"
dbq "$WIDGET_FLUSH"

fi
if want "Rules tab"; then
# WPB-2: the Rules tab in categories. curl runs no JavaScript, so everything here is also the no-JS check:
# the settings sit in closed <details> panels, and a browser (or curl, using FormFields) submits them anyway.
admin_login
RULES_URL="$U/wp-admin/admin.php?page=wp-bouncer&tab=rules"
FORMFIELDS="$REPO_DIR/tests/Support/FormFields.php"
RT_BAK="$WORK/settings-before-rules-tab.json"
RT_LOG_MAX=$(log_value id "1 = 1"); RT_LOG_MAX=${RT_LOG_MAX:-0}
dbq_opt wp_bouncer_settings 'echo json_encode($o);' > "$RT_BAK"
settings_json() { # the stored settings as JSON with sorted keys, so two states compare as text
	dbq_opt wp_bouncer_settings '$f = function (array &$a) use (&$f) { ksort($a); foreach ($a as &$v) { if (is_array($v)) { $f($v); } } }; $s = (array) $o; $f($s); echo json_encode($s);'
}
rules_state() { # rules_state defaults|fixture -> every rule at its default, or at tests/fixtures/rules-non-default.php (other settings kept)
	$WP eval '$s = (array) get_option("wp_bouncer_settings"); $d = WPBouncer\Settings::defaults(); $s["rules"] = $d["rules"]; if ("'"$1"'" === "fixture") { $f = require "'"$FIXTURES"'/rules-non-default.php"; foreach ($f["rules"] as $id => $r) { $s["rules"][$id] = array_merge($s["rules"][$id], $r); } } update_option("wp_bouncer_settings", WPBouncer\Settings::sanitize($s));'
}
submit_rules() { # submit_rules [field name to leave out ...] -> status of posting the Rules form as a browser would
	admin "$RULES_URL" > /dev/null
	"$PHP" "$FORMFIELDS" "$WORK/admin.html" form.wpb-rules-form "$@" > "$WORK/rules-post.txt"
	admin "$U/wp-admin/admin-post.php" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$WORK/rules-post.txt"
}
changed_paths() { # changed_paths BEFORE_JSON AFTER_JSON -> comma-separated settings paths that differ
	"$PHP" -r '$f = function ($a, $p = "") use (&$f) { $o = array(); foreach ($a as $k => $v) { if (is_array($v) && $v !== array() && array_keys($v) !== range(0, count($v) - 1)) { $o += $f($v, $p . $k . "."); } else { $o[$p . $k] = $v; } } return $o; }; $a = $f(json_decode($argv[1], true)); $b = $f(json_decode($argv[2], true)); $c = array(); foreach (array_unique(array_merge(array_keys($a), array_keys($b))) as $k) { if (($a[$k] ?? null) !== ($b[$k] ?? null)) { $c[] = $k; } } echo implode(",", $c);' "$1" "$2"
}

rules_state defaults
admin "$RULES_URL" > /dev/null
for id in ip_blocklist country user_agent login_lockout xmlrpc user_enumeration sensitive_files not_found rate_limit waf uploads_php; do
	check "rule anchor #rule-$id exists once" 1 "$(grep -o "id=\"rule-$id\"" "$WORK/admin.html" | wc -l | tr -d ' ')"
done
for slug in block-lists login-accounts scanners-floods payloads-hardening; do
	check "category anchor #wpb-cat-$slug exists once" 1 "$(grep -o "id=\"wpb-cat-$slug\"" "$WORK/admin.html" | wc -l | tr -d ' ')"
done
check "no Other category without third-party rules" 0 "$(grep -c 'id="wpb-cat-other"' "$WORK/admin.html")"
check "every switch is named after its rule"         1 "$(grep -c 'name="wp_bouncer\[rules\]\[waf\]\[enabled\]"[^>]*><span class="wpb-slider" aria-hidden="true"></span><span class="screen-reader-text">Web application firewall</span>' "$WORK/admin.html")"
check "  ...and is a switch for screen readers (10: country is a status card)" 10 "$(grep -o 'role="switch" name="wp_bouncer\[rules\]\[[a-z_]*\]\[enabled\]"' "$WORK/admin.html" | wc -l | tr -d ' ')"
check "no-JS: expand/collapse buttons start hidden" 1 "$(grep -c 'class="wpb-expand" hidden' "$WORK/admin.html")"
check "no-JS: every Settings panel is a native <details>" 10 "$(grep -o '<details class="wpb-rule-settings"' "$WORK/admin.html" | wc -l | tr -d ' ')"
check "  ...all closed by default"      "" "$(open_panels)"
check "  ...no input is disabled"        0 "$(grep -c '<input[^>]* disabled' "$WORK/admin.html")"
check "country rule is a status card with no input" 0 "$(grep -c 'name="wp_bouncer\[rules\]\[country\]' "$WORK/admin.html")"
check "  ...linking to the Countries tab" 1 "$( [ "$(grep -c 'Configure on the Countries tab' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "Settings link ?wpb_rule= opens that panel" rule-uploads_php "$(admin "$RULES_URL&wpb_rule=uploads_php" > /dev/null; open_panels)"
check "  ...an unknown rule opens nothing"        "" "$(admin "$RULES_URL&wpb_rule=nope%22%3E%3Cscript%3E" > /dev/null; open_panels)"
check "  ...and echoes nothing unescaped"           0 "$(grep -c 'nope"><script>' "$WORK/admin.html")"

# The round trip: render, submit as a browser would, save. Nothing may change, or a closed panel switched a rule off.
BEFORE=$(settings_json)
check "Rules form saved unchanged (defaults): redirected" 302 "$(submit_rules)"
check "  ...changes no setting"       same "$( [ "$(settings_json)" = "$BEFORE" ] && echo same || echo different )"
rules_state fixture
BEFORE=$(settings_json)
check "Rules form saved unchanged (every rule non-default): redirected" 302 "$(submit_rules)"
check "  ...changes no setting"       same "$( [ "$(settings_json)" = "$BEFORE" ] && echo same || echo different )"
rules_state defaults
BEFORE=$(settings_json)
submit_rules 'wp_bouncer[rules][waf][enabled]' > /dev/null
check "  ...a switch missing from the POST is switched off (so the check above can fail)" rules.waf.enabled "$(changed_paths "$BEFORE" "$(settings_json)")"
rules_state fixture
BEFORE=$(settings_json)
submit_rules 'wp_bouncer[rules][not_found][max_404]' > /dev/null
check "one field left out changes only that field" rules.not_found.max_404 "$(changed_paths "$BEFORE" "$(settings_json)")"

# Dashboard: same categories, same switches.
rules_state defaults
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=dashboard" > /dev/null
for name in 'Block lists' 'Login and accounts' 'Scanners and floods' 'Attack payloads and hardening'; do
	check "dashboard shows category '$name'" 1 "$( [ "$(grep -cF "$name" "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
done
check "dashboard has a Turn on/off button per rule" 11 "$(grep -c 'name="action" value="wp_bouncer_toggle_rule"' "$WORK/admin.html")"
xmlrpc_on() { dbq_opt wp_bouncer_settings 'echo $o["rules"]["xmlrpc"]["enabled"] ? "on" : "off";'; }
check "xmlrpc starts on"               on "$(xmlrpc_on)"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_toggle_rule dashboard)&action=wp_bouncer_toggle_rule&rule=xmlrpc" > /dev/null
check "dashboard button turns it off"  off "$(xmlrpc_on)"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_toggle_rule dashboard)&action=wp_bouncer_toggle_rule&rule=xmlrpc" > /dev/null
check "  ...and back on"               on "$(xmlrpc_on)"

# Put everything back, including the audit rows and mail the saves above caused.
$WP eval 'update_option("wp_bouncer_settings", json_decode(file_get_contents("'"$RT_BAK"'"), true));'
dbq "DELETE FROM wp_bouncer_log WHERE rule = 'settings' AND id > $RT_LOG_MAX"
rm -f "$MAILLOG" "$RT_BAK" "$WORK/rules-post.txt"

fi
if want "Geo import through the Tools screen"; then
# One 500-row batch per step, so even a small file needs several steps.
mkdir -p "$W/wp-content/mu-plugins"
cat > "$W/wp-content/mu-plugins/wpb-e2e.php" <<'PHPEOF'
<?php
add_filter( 'wp_bouncer_geo_step_seconds', '__return_zero' );
// Let download_url() fetch from the local stand-in for download.db-ip.com.
add_filter( 'http_request_host_is_external', '__return_true' );
// The importer only fetches https from allow-listed hosts; let it use the local http stand-in.
add_filter( 'wp_bouncer_geo_import_allow_http', '__return_true' );
add_filter( 'wp_bouncer_geo_import_hosts', static function ( $hosts ) { $hosts[] = '127.0.0.1'; return $hosts; } );
// wp_safe_remote_get() only talks to ports 80, 443 and 8080 by default.
add_filter( 'http_allowed_safe_ports', static function ( $ports ) { $ports[] = (int) wp_parse_url( home_url(), PHP_URL_PORT ); return $ports; } );
// A tiny unpack cap while this flag file exists.
add_filter( 'wp_bouncer_geo_max_bytes', static function ( $max ) { return file_exists( WP_CONTENT_DIR . '/wpb-small-cap' ) ? 100000 : $max; } );
PHPEOF
# 3000 ranges 5.0.0.0/24 .. 5.11.183.0/24, all NL, gzipped like the DB-IP file.
"$PHP" -r '$o = ""; for ($i = 0; $i < 3000; $i++) { $b = intdiv($i, 256); $c = $i % 256; $o .= "5.$b.$c.0,5.$b.$c.255,NL\n"; } file_put_contents($argv[1], gzencode($o));' "$FILES/geo.csv.gz"
printf '<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>\n' > "$WORK/not-geo.csv"
head -c 3000000 /dev/urandom | gzip -1 > "$WORK/too-big.csv.gz"   # over upload_max_filesize (2M)
head -c 9000000 /dev/urandom > "$WORK/way-too-big.csv"              # over post_max_size (8M)

geo_rows() { dbq "SELECT COUNT(*) FROM wp_bouncer_geo"; }
import_running() { dbq_opt wp_bouncer_geo_import 'echo ( is_array( $o ) && ! empty( $o["file"] ) ) ? 1 : 0;'; }   # GeoImport::status() is not null
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
redirect_err() { # ok, or the redirect (with the plugin's message) when the last response reports an error
	local loc; loc=$(grep -i '^location:' "$WORK/admin.headers" | tr -d '\r')
	case "$loc" in *wpb_err*) echo "$loc" | cut -c1-300 ;; *) echo ok ;; esac
}
at_least() { [ "$2" -ge "$1" ] 2>/dev/null && echo ok || echo "$2"; }
TOOLS_POST="$U/wp-admin/admin-post.php?action=wp_bouncer_geo_import"

before=$(geo_rows)
check "non-geo file is refused"      302 "$(upload "$WORK/not-geo.csv")"
check "  ...with an explanation"     1   "$(redirect_has "wpb_msg=geo_error")"
check "  ...and old data kept"       "$before" "$(geo_rows)"
upload "$WORK/too-big.csv.gz" > /dev/null
check "over upload limit explained"  1   "$(redirect_has "wpb_msg=geo_upload_error")"
upload "$WORK/way-too-big.csv" > /dev/null
check "over post limit explained"    1   "$(redirect_has "wpb_msg=geo_upload_error")"
check "  ...and old data kept"       "$before" "$(geo_rows)"

check "upload starts an import"      302 "$(upload "$FILES/geo.csv.gz")"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=tools" > /dev/null
check "Tools shows progress"         1   "$(grep -c 'id="wpb-geo-progress"' "$WORK/admin.html")"
check "import needs several steps"   ok  "$(at_least 6 "$(run_steps)")"
check "all 3000 ranges loaded"       3000 "$(geo_rows)"
check "import no longer running"     0   "$(import_running)"
check "meta records the file"        "3000 geo.csv.gz" "$(dbq_opt wp_bouncer_geo_meta '$o = (array) $o; echo $o["rows"], " ", $o["source"];')"
check "working file removed"         0   "$(find "$W/wp-content/uploads/wp-bouncer" -name '*.csv' | wc -l | tr -d ' ')"
check "work folder has .htaccess"    1   "$(grep -c 'Require all denied' "$W/wp-content/uploads/wp-bouncer/.htaccess")"
check "lookup uses new data"         NL  "$($WP eval 'echo WPBouncer\Plugin::instance()->geo_database()->lookup("5.4.7.9");')"

# The previous import left 3000 rows, so empty the table first: otherwise "all ranges" would pass without this import.
dbq "DELETE FROM wp_bouncer_geo"   # GeoDatabase::truncate() (TRUNCATE is not portable to SQLite)
check "import by URL starts"         302 "$(from_url "$FILES_URL/geo.csv.gz")"
check "  ...without an error"        ok  "$(redirect_err)"
check "  ...and an import is running" 1   "$(import_running)"
check "  ...and finishes"            ok  "$(at_least 6 "$(run_steps)")"
check "  ...with all ranges"         3000 "$(geo_rows)"
from_url "$FILES_URL/missing.csv.gz" > /dev/null
check "bad URL explained"            1   "$(redirect_has "wpb_msg=geo_download_failed")"
check "  ...and old data kept"       3000 "$(geo_rows)"
"$PHP" -r 'file_put_contents($argv[1], gzencode(str_repeat("1.0.0.0,1.0.0.255,AU\n", 50000), 9));' "$FILES/bomb.csv.gz"
touch "$W/wp-content/wpb-small-cap"
from_url "$FILES_URL/bomb.csv.gz" > /dev/null
check "oversize unpack refused"      1   "$(redirect_has "wpb_msg=geo_error")"
check "  ...old data kept"           3000 "$(geo_rows)"
check "  ...working file removed"    0   "$(find "$W/wp-content/uploads/wp-bouncer" -name '*.csv' | wc -l | tr -d ' ')"
rm -f "$W/wp-content/wpb-small-cap" "$FILES/bomb.csv.gz"

upload "$FILES/geo.csv.gz" > /dev/null
check "no-JS step button works"      302 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_geo_step)&action=wp_bouncer_geo_step")"
check "stop button works"            302 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_geo_cancel)&action=wp_bouncer_geo_cancel")"
check "  ...keeps partial data"      500 "$(geo_rows)"
check "  ...marked incomplete"       1   "$(dbq_opt wp_bouncer_geo_meta 'echo (int) ( false !== strpos( $o["source"], "incomplete" ) );')"
check "  ...import not running"      0   "$(import_running)"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=tools" > /dev/null
check "step with nothing running"    1   "$(curl -s -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -d "action=wp_bouncer_geo_step&_ajax_nonce=$(ajax_nonce)" "$U/wp-admin/admin-ajax.php" | grep -c '"success":false')"
check "AJAX step needs a nonce"      403 "$(curl -s -o /dev/null -w '%{http_code}' -b "$J" -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -d "action=wp_bouncer_geo_step&_ajax_nonce=bad" "$U/wp-admin/admin-ajax.php")"
rm -f "$W/wp-content/mu-plugins/wpb-e2e.php"

fi
if want "No PHP in uploads"; then
UP="$W/wp-content/uploads"
HT="$UP/.htaccess"
rm -f "$HT" "$W/wp-content/e2e-htaccess-500"  # left by an earlier run in a reused WPB_E2E_DIR
dbq "DELETE FROM wp_options WHERE option_name = 'wp_bouncer_uploads_htaccess'"
status 203.0.113.10 "$MOZ" "$U/" > /dev/null   # any request writes the block if needed
check "block written to uploads/.htaccess" 1 "$(count_in '# BEGIN WP Bouncer' "$HT")"
probe() { # probe -> result of the Rules tab's "Test now" button
	admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_uploads_probe rules)&action=wp_bouncer_uploads_probe" > /dev/null
	dbq_opt wp_bouncer_uploads_probe 'echo $o["result"];'
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
age_failure() { $WP eval '$o = WPBouncer\Hardening\UploadsGuard::STATE_OPTION; $st = (array) get_option( $o ); $st["fail_time"] = time() - 400; update_option( $o, $st );'; }
$WP cron event run wp_bouncer_uploads_check > /dev/null
check "one 5xx: block kept (re-check)" 3 "$(count_in 'WP Bouncer' "$HT")"
age_failure
$WP cron event run wp_bouncer_uploads_check > /dev/null
check "broken host: block removed"   0 "$(count_in 'WP Bouncer' "$HT")"
check "  ...owner's lines kept"      1 "$(count_in 'Options -Indexes' "$HT")"
check "  ...not rewritten"           0 "$(status 203.0.113.10 "$MOZ" "$U/" > /dev/null; count_in 'WP Bouncer' "$HT")"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=rules" > /dev/null
check "  ...admin is told"           1 "$(count_in 'answered uploaded files (images too) with an error' "$WORK/admin.html")"
check "  ...with a link to the rule"   1 "$( [ "$(grep -c 'wpb_rule=uploads_php#rule-uploads_php' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...and its panel is open"     rule-uploads_php "$(open_panels)"
check "  ...and logged"              alert "$(log_value action "rule = 'uploads_php' AND reason LIKE 'Removed the uploads%'")"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_uploads_sync rules)&action=wp_bouncer_uploads_sync" > /dev/null
probe > /dev/null
age_failure
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

fi
if want "Email alerts"; then
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
check "Send a test email button"     1 "$(redirect_has "wpb_msg=test_sent")"
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
check "plugin budget spent: admin alert still sent" 1 "$(mail_count)"
$WP eval 'set_transient( "wpb_alert_count_critical", 20, HOUR_IN_SECONDS );'
rm -f "$MAILLOG"
$WP user create eve5_e2e eve5@example.test --role=administrator --user_pass=e2e-pass-eve
check "over 20 an hour: not emailed" 0 "$(mail_count)"
check "  ...but still logged"        1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE action = 'alert' AND reason LIKE '%eve4_e2e%'")"
set_settings '$s["alerts"]["enabled"] = false' 'delete_transient( "wpb_alert_count" );'
rm -f "$MAILLOG"
$WP user create eve5_e2e eve5@example.test --role=administrator --user_pass=e2e-pass-eve
check "alerts off: no email"         0 "$(mail_count)"
set_settings '$s["alerts"] = ["enabled" => true, "recipients" => [], "new_admin" => true, "plugin_changes" => true, "plugin_updates" => true]'
$WP user delete eve_e2e sub_e2e eve2_e2e eve3_e2e eve4_e2e eve5_e2e --yes > /dev/null 2>&1
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=log&log_action=alert" > /dev/null
check "Activity Log shows alerts"    1 "$( [ "$(grep -o 'wpb-badge-alert' "$WORK/admin.html" | wc -l)" -ge 5 ] && echo 1 || echo 0 )"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=dashboard" > /dev/null
check "Dashboard still loads"        200 "$(admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=dashboard")"

fi
if want "Traffic log"; then
traffic_value() { # traffic_value COLUMN "WHERE ..." -> newest matching value from the traffic log
	dbq "SELECT $1 FROM wp_bouncer_traffic WHERE $2 ORDER BY id DESC LIMIT 1"
}
traffic_row() { # traffic_row "col1, col2" "WHERE ..." -> newest matching row, columns tab-separated
	dbq "SELECT $1 FROM wp_bouncer_traffic WHERE $2 ORDER BY id DESC LIMIT 1"
}
traffic_count() { traffic_value "COUNT(*)" "$1"; }
check "purge job scheduled"          1 "$(dbq_opt cron '$n = 0; foreach ( (array) $o as $hooks ) { if ( is_array( $hooks ) && isset( $hooks["wp_bouncer_traffic_purge"] ) ) { $n += count( $hooks["wp_bouncer_traffic_purge"] ); } } echo $n;')"
dbq "DELETE FROM wp_bouncer_traffic"   # TrafficLog::clear()
status 203.0.113.81 "$MOZ" "$U/" > /dev/null
check "off by default"               0 "$(traffic_count "1=1")"
set_settings '$s["traffic"]["enabled"] = true'
status 203.0.113.81 "$MOZ" "$U/" -e "https://www.example.com/where-they-came-from" > /dev/null
check "page view recorded"           "200 browser /" "$(traffic_row "status, client, uri" "ip = '203.0.113.81'" | tr '\t' ' ')"
check "  ...with the referrer"       "https://www.example.com/where-they-came-from" "$(traffic_value referrer "ip = '203.0.113.81'")"
check "  ...and the User-Agent"      "$MOZ" "$(traffic_value user_agent "ip = '203.0.113.81'")"
status 203.0.113.82 "$MOZ" "$U/no-such-page/" > /dev/null
check "404 recorded"                 404 "$(traffic_value status "ip = '203.0.113.82'")"
status 203.0.113.82 "$MOZ" "$U/wp-admin/" > /dev/null
check "redirect recorded"            302 "$(traffic_value status "ip = '203.0.113.82' AND uri = '/wp-admin/'")"
status 203.0.113.83 "$MOZ" "$U/.env" > /dev/null
check "blocked request recorded"     403 "$(traffic_value status "ip = '203.0.113.83'")"
status 203.0.113.84 "" "$U/" > /dev/null
check "no User-Agent: unknown, 403"  "unknown 403" "$(traffic_row "client, status" "ip = '203.0.113.84'" | tr '\t' ' ')"
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
dbq "DELETE FROM wp_bouncer_traffic"
admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=traffic" > /dev/null
check "skip administrators"          0 "$(traffic_count "ip = '198.51.100.50'")"
set_settings '$s["traffic"]["skip_admins"] = false'
# The purge runs its hook directly (the "purge job scheduled" check above covers the cron registration).
# It used to go through "wp cron event run", which loses the event when two runs land in the same second.
# The plugin reads its settings once per request, so a change only applies to the NEXT process: each eval below
# purges first and then stores the setting the following purge needs. That also keeps this to one WP-CLI call per purge.
run_purge() { # run_purge ['PHP to run before the purge'] ['PHP to run after it']
	$WP eval "${1:-} wp_clear_scheduled_hook( 'wp_bouncer_traffic_purge' ); wp_schedule_event( time() - 60, 'hourly', 'wp_bouncer_traffic_purge' ); do_action( 'wp_bouncer_traffic_purge' ); ${2:-}"
}
# Old rows: 8 days, 2 days and 1 hour ago. Afterwards: skip_admins off again and a 1-day retention for the next purge.
run_purge 'global $wpdb; foreach ( array( 8 * DAY_IN_SECONDS, 2 * DAY_IN_SECONDS, HOUR_IN_SECONDS ) as $age ) { $wpdb->insert( $wpdb->prefix . "bouncer_traffic", array( "created_at" => gmdate( "Y-m-d H:i:s", time() - $age ), "ip" => "192.0.2.1", "uri" => "/age-" . $age ) ); }' \
	"$(settings_php '$s["traffic"]["skip_admins"] = false; $s["traffic"]["retention_days"] = 1')"
check "7-day retention purges"       "0 1 1" "$(traffic_count "uri = '/age-691200'") $(traffic_count "uri = '/age-172800'") $(traffic_count "uri = '/age-3600'")"
# Afterwards: retention 99 stored behind the form's back, and a row older than the 7-day cap.
run_purge '' "$(settings_php '$s["traffic"]["retention_days"] = 99') global \$wpdb; \$wpdb->insert( \$wpdb->prefix . 'bouncer_traffic', array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 8 * DAY_IN_SECONDS ), 'ip' => '192.0.2.1', 'uri' => '/age-old' ) );"
check "1-day retention purges"       "0 1" "$(traffic_count "uri = '/age-172800'") $(traffic_count "uri = '/age-3600'")"
run_purge
check "never kept past 7 days"       0 "$(traffic_count "uri = '/age-old'")"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_save traffic)&action=wp_bouncer_save&tab=traffic&wp_bouncer[traffic][enabled]=1&wp_bouncer[traffic][retention_days]=3&wp_bouncer[traffic][skip_background]=1" > /dev/null
check "Traffic tab saves settings"   "1 3" "$(dbq_opt wp_bouncer_settings '$t = $o["traffic"]; echo (int) $t["enabled"], " ", $t["retention_days"];')"
admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(nonce_for wp_bouncer_clear_traffic traffic)&action=wp_bouncer_clear_traffic" > /dev/null
check "Clear traffic log"            0 "$(traffic_count "ip <> '198.51.100.50'")"
set_settings '$s["traffic"]["enabled"] = false'
status 203.0.113.89 "$MOZ" "$U/" > /dev/null
check "switched off: not recorded"   0 "$(traffic_count "ip = '203.0.113.89'")"

fi
if want "IP trust (header ignored without trusted proxies, loopback, setup notice)"; then
ipsetup_nonce() { nonce_for wp_bouncer_ip_setup dashboard; }
stored_ip() { dbq_opt wp_bouncer_settings 'echo $o["ip_source"] . "|" . implode( ",", $o["trusted_proxies"] );'; }
# Loopback as the forwarded address is refused: the request resolves to the proxy, which is never
# banned itself; requests carrying a refused header are counted and banned under "rejected:<proxy>".
check "loopback header: probe refused"  403 "$(status 127.0.0.1 "$MOZ" "$U/.env")"
check "  ...second probe: subject banned" 403 "$(status 127.0.0.1 "$MOZ" "$U/.env")"
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
# PHP's own error format ("Warning: message in /path/file.php on line N", with <b> tags when html_errors is on),
# not any text that happens to contain "Notice:" or "Warning:". Matching lines are shown when the check fails.
php_errors_in() { # php_errors_in FILE -> number of PHP errors printed in FILE
	local re='(Fatal error|Warning|Notice|Deprecated)(</b>)?: .* in .* on line [0-9]+' n
	n=$(grep -cE "$re" "$1")
	[ "$n" != 0 ] && grep -E -m5 "$re" "$1" | cut -c1-300 >&2
	echo "$n"
}
check "no PHP errors in the notice"     0 "$(php_errors_in "$WORK/admin.html")"
check "fix needs a valid nonce"         403 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=deadbeef00&action=wp_bouncer_ip_setup&fix=trust_peer&header=x_real_ip")"
check "  ...nothing changed"            "x_real_ip|" "$(stored_ip)"
# No handler is registered for logged-out visitors, so WordPress answers an unhandled admin-post action with 400.
logged_out_code=$(curl -s -o "$WORK/logged-out.html" -w '%{http_code}' -H "X-Real-IP: 198.51.100.50" -A "$MOZ" -d "_wpnonce=$(ipsetup_nonce)&action=wp_bouncer_ip_setup&fix=trust_peer&header=x_real_ip" "$U/wp-admin/admin-post.php")
check "fix is not reachable logged out"   400 "$logged_out_code"
check "  ...and changed nothing"        "x_real_ip|" "$(stored_ip)"
check "Trust-peer button works"         302 "$(admin "$U/wp-admin/admin-post.php" -d "_wpnonce=$(ipsetup_nonce)&action=wp_bouncer_ip_setup&fix=trust_peer&header=x_real_ip&peer=127.0.0.1")"
check "  ...proxy added"                "x_real_ip|127.0.0.1" "$(stored_ip)"
check "  ...visitor IPs honoured again" 403 "$(status 203.0.113.143 "$MOZ" "$U/.env")"
check "  ...second probe refused"       403 "$(status 203.0.113.143 "$MOZ" "$U/.env")"
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

fi
if want "Updates (a local server stands in for GitHub releases)"; then
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
# The update alert needs plugin_updates on; the Email alerts section leaves it so, and a partial run may skip that section.
# Auto-updates are switched off first: an earlier run in a reused WPB_E2E_DIR may have left them on.
set_settings '$s["alerts"] = ["enabled" => true, "recipients" => [], "new_admin" => true, "plugin_changes" => true, "plugin_updates" => true]' \
	'update_option( "auto_update_plugins", array_values( array_diff( (array) get_option( "auto_update_plugins", array() ), array( "wp-bouncer/wp-bouncer.php" ) ) ) );'
plugin_version() { sed -n 's/^ \* Version: *//p' "$INSTALLED/wp-bouncer.php" | head -1 | tr -d '\r'; }   # what "wp plugin get --field=version" reads
plugin_status() { dbq_opt active_plugins 'echo in_array( "wp-bouncer/wp-bouncer.php", (array) $o, true ) ? "active" : "inactive";'; }
CURRENT=$(plugin_version)

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
	dbq_opt _site_transient_update_plugins '$t = $o; $f = "wp-bouncer/wp-bouncer.php"; echo isset( $t->response[ $f ] ) ? $t->response[ $f ]->new_version : ( isset( $t->no_update[ $f ] ) ? "none" : "unsupported" );'
}
installed_version() { plugin_version; }
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
check "Dashboard > Updates lists it" 1    "$(grep -c 'You have version [0-9][0-9A-Za-z.+-]* installed. Update to 9.0.0' "$WORK/admin.html")"
admin "$U/wp-admin/plugin-install.php?tab=plugin-information&plugin=wp-bouncer&section=changelog" > /dev/null
check "View details shows changelog" 1    "$(grep -c 'Release 9.0.0 for the e2e update test' "$WORK/admin.html")"

sed -i.bak 's/"sha256": "[0-9a-f]*"/"sha256": "0000000000000000000000000000000000000000000000000000000000000000"/' "$FILES/update.json" && rm -f "$FILES/update.json.bak"
dbq "DELETE FROM wp_options WHERE option_name LIKE '%wp_bouncer_update_manifest%'"   # delete_site_transient( Updater::CACHE )
check "tampered zip is refused"      1    "$(update_now | grep -c 'failed its integrity check')"
check "  ...old version still there" "$CURRENT" "$(installed_version)"
check "  ...and still running"       403  "$(status 203.0.113.51 "sqlmap/1.7" "$U/")"

publish 9.0.0
dbq "DELETE FROM wp_options WHERE option_name LIKE '%wp_bouncer_update_manifest%'"   # delete_site_transient( Updater::CACHE )
rm -f "$MAILLOG"
check "Update now succeeds"          1    "$(update_now | grep -c '"success":true')"
check "  ...new version installed"   9.0.0 "$(installed_version)"
check "  ...still active"            active "$(plugin_status)"
check "  ...update alert sent"       1    "$(count_in 'Plugin updated: WP Bouncer' "$MAILLOG")"
check "  ...settings kept"           x_real_ip "$(dbq_opt wp_bouncer_settings 'echo $o["ip_source"];')"
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
check "  ...still active"            active "$(plugin_status)"
check "  ...still blocking"          403  "$(status 203.0.113.53 "sqlmap/1.7" "$U/")"

echo "<?php define( 'WP_BOUNCER_DISABLE_UPDATES', true );" > "$W/wp-content/mu-plugins/wpb-e2e-noupdates.php"
publish 9.2.0
refresh_updates
check "WP_BOUNCER_DISABLE_UPDATES"   unsupported "$(offered)"
rm -f "$W/wp-content/mu-plugins/wpb-e2e-noupdates.php" "$W/wp-content/mu-plugins/wpb-e2e-update.php"

fi
if want "Privacy tools (export and erase personal data)"; then
# Runs the registered callbacks on the real database (SQLite or MySQL): no DELETE ... LIMIT, no unsupported SQL.
# One WP-CLI call prepares the rows, runs the exporter and both erasers and prints one result per line.
mapfile -t PRIV < <($WP eval '
	global $wpdb;
	$u = get_user_by("login", "admin_e2e");
	$wpdb->delete($wpdb->prefix . "bouncer_traffic", array("user_id" => $u->ID));
	for ($i = 0; $i < 3; $i++) { $wpdb->insert($wpdb->prefix . "bouncer_traffic", array("created_at" => gmdate("Y-m-d H:i:s"), "ip" => "192.0.2.77", "uri" => "/priv" . $i, "user_id" => $u->ID)); }
	$wpdb->insert($wpdb->prefix . "bouncer_log", array("created_at" => gmdate("Y-m-d H:i:s"), "ip" => "192.0.2.77", "rule" => "login_lockout", "action" => "lockout", "reason" => "5 failed logins (last username \"admin_e2e\")", "uri" => "/wp-login.php?x=1"));
	$e = apply_filters("wp_privacy_personal_data_exporters", array()); $r = $e["wp-bouncer-traffic"]["callback"]("e2e@example.test", 1); echo count($r["data"]), "\n";
	$r = apply_filters("wp_privacy_personal_data_erasers", array())["wp-bouncer-log"]["callback"]("e2e@example.test", 1); $row = $wpdb->get_row("SELECT reason, uri FROM {$wpdb->prefix}bouncer_log WHERE ip = \"192.0.2.77\"", ARRAY_A); echo (int) $r["items_retained"], " ", $row["reason"], " |", $row["uri"], "\n";
	$r = apply_filters("wp_privacy_personal_data_erasers", array())["wp-bouncer-traffic"]["callback"]("e2e@example.test", 1); echo $r["items_removed"], " ", (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_traffic WHERE ip = \"192.0.2.77\""), "\n";
	$wpdb->delete($wpdb->prefix . "bouncer_log", array("ip" => "192.0.2.77"));
')
check "exporter returns the rows"    3 "${PRIV[0]:-}"
check "log eraser redacts the login"  '1 5 failed logins (last username "[erased]") |' "${PRIV[1]:-}"
check "traffic eraser deletes rows"  "3 0" "${PRIV[2]:-}"

fi
if want "Admin logins (WPB-13)"; then
# Interactive logins by real HTTP, the Activity Log filter, the new-location mail, and the personal-data eraser on the real database.
admin_login
ADMIN_ID=$(dbq "SELECT ID FROM wp_users WHERE user_login = 'admin_e2e'")
$WP eval 'delete_user_option(get_user_by("login", "admin_e2e")->ID, "wpb_login_seen");' > /dev/null
dbq "DELETE FROM wp_bouncer_log WHERE rule = 'admin_login'" > /dev/null
rm -f "$MAILLOG"
check "admin login works"                      302 "$(login 198.18.7.71 admin_e2e e2e-pass-123)"
check "  ...writes one login row"              1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE rule = 'admin_login' AND action = 'login' AND ip = '198.18.7.71'")"
check "  ...naming the user and the method"    1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE ip = '198.18.7.71' AND reason LIKE 'User ID $ADMIN_ID: admin_e2e — interactive password%'")"
check "  ...first login starts the history"    1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE ip = '198.18.7.71' AND reason LIKE '%first recorded login%'")"
check "  ...and sends no mail"                 0 "$(mail_count)"
check "second login, same range: another row"  2 "$( login 198.18.7.99 admin_e2e e2e-pass-123 > /dev/null; dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE rule = 'admin_login'")"
check "  ...no mail"                           0 "$(mail_count)"
check "login from a new range"                 302 "$(login 198.18.8.71 admin_e2e e2e-pass-123)"
check "  ...sends one mail"                    1 "$(mail_count)"
check "  ...with the alert subject"            1 "$(count_in 'Administrator login from a new location' "$MAILLOG")"
check "  ...naming the user and the range"     1 "$(count_in 'User: admin_e2e (user ID' "$MAILLOG")"
check "  ...and the IP"                        1 "$( [ "$(count_in '198.18.8.71' "$MAILLOG")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...without any password"              0 "$(count_in 'e2e-pass-123' "$MAILLOG")"
check "  ...row says new location"             1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE ip = '198.18.8.71' AND reason LIKE '%new location: IP range 198.18.8.0/24%'")"
rm -f "$MAILLOG"
login 198.18.8.88 admin_e2e e2e-pass-123 > /dev/null
check "  ...the range is now known: no mail"   0 "$(mail_count)"
check "wrong password writes no login row"     0 "$(login 198.18.8.131 admin_e2e wrong-pass > /dev/null; dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE rule = 'admin_login' AND ip = '198.18.8.131'")"
$WP user create sub13_e2e sub13@example.test --role=subscriber --user_pass=e2e-pass-sub13 > /dev/null
check "subscriber login works"                 302 "$(login 198.18.8.141 sub13_e2e e2e-pass-sub13)"
check "  ...writes no login row"               0 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE rule = 'admin_login' AND ip = '198.18.8.141'")"
check "  ...and no login mail"                 0 "$(count_in 'Administrator login from a new location' "$MAILLOG")"
# Activity Log: the Action filter selects login rows alone; the badge is text.
check "log filtered to logins loads"           200 "$(admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=log&log_action=login")"
check "  ...lists login badges"                1 "$( [ "$(grep -o 'wpb-badge-login' "$WORK/admin.html" | wc -l)" -ge 3 ] && echo 1 || echo 0 )"
check "  ...with the text label"               1 "$( [ "$(grep -c '>Admin login</span>' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "  ...and no blocked rows"               0 "$(grep -c 'wpb-badge-blocked' "$WORK/admin.html")"
check "  ...offers the filter option"          1 "$( [ "$(grep -c '<option value="login"' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
check "unfiltered log has no PHP errors"       0 "$(admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=log" > /dev/null; grep -c 'Fatal error\|Warning:\|Notice:\|Deprecated:' "$WORK/admin.html")"
# Eraser: user ID 12 loses its rows and history; ID 1 (the admin) and ID 120 keep theirs.
mapfile -t ERASE < <($WP eval '
	global $wpdb;
	$wpdb->query("DELETE FROM {$wpdb->users} WHERE ID IN (12, 120)");
	$wpdb->insert($wpdb->users, array("ID" => 12, "user_login" => "twelve_e2e", "user_pass" => "x", "user_nicename" => "twelve", "user_email" => "twelve@example.test", "user_registered" => "2026-01-01 00:00:00", "display_name" => "Twelve"));
	clean_user_cache(12);
	$one = (int) get_user_by("login", "admin_e2e")->ID;
	$wpdb->delete($wpdb->prefix . "bouncer_log", array("rule" => "admin_login"));
	foreach (array(array($one, 2), array(12, 3), array(120, 1)) as $p) { for ($i = 0; $i < $p[1]; $i++) { $wpdb->insert($wpdb->prefix . "bouncer_log", array("created_at" => gmdate("Y-m-d H:i:s"), "ip" => "192.0.2.150", "rule" => "admin_login", "action" => "login", "reason" => "User ID " . $p[0] . ": u — interactive password")); } }
	update_user_option(12, "wpb_login_seen", array("since" => time() - 10, "e" => array(array("r" => "192.0.2.0/24", "c" => "", "t" => time() - 5))));
	$e = apply_filters("wp_privacy_personal_data_exporters", array())["wp-bouncer-admin-logins"]["callback"]("twelve@example.test", 1); echo count($e["data"]), " ", (int) $e["done"], "\n";
	$r = apply_filters("wp_privacy_personal_data_erasers", array())["wp-bouncer-admin-logins"]["callback"]("twelve@example.test", 1); echo $r["items_removed"], " ", (int) $r["done"], "\n";
	echo (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log WHERE reason LIKE \"User ID 12:%\""), " ", (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log WHERE reason LIKE \"User ID $one:%\""), " ", (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log WHERE reason LIKE \"User ID 120:%\""), "\n";
	$h = get_user_option("wpb_login_seen", 12); echo json_encode($h["e"] ?? null), "\n";
	$wpdb->query("DELETE FROM {$wpdb->users} WHERE ID = 12");
	$wpdb->delete($wpdb->prefix . "bouncer_log", array("ip" => "192.0.2.150"));
')
check "exporter: history, since and 3 rows"    "5 1" "${ERASE[0]:-}"
check "eraser removes ID 12's three rows"      "3 1" "${ERASE[1]:-}"
check "  ...keeps ID 1's (2) and ID 120's (1)" "0 2 1" "${ERASE[2]:-}"
check "  ...and empties the stored history (a tombstone, not 'never recorded')" "[]" "${ERASE[3]:-}"
# After an erase the next login from a new range still alerts (RT-02), and the erase leaves an audit row.
$WP eval 'apply_filters("wp_privacy_personal_data_erasers", array())["wp-bouncer-admin-logins"]["callback"](get_user_by("login", "admin_e2e")->user_email, 1);' > /dev/null
check "  ...the erase leaves an Activity Log row" 1 "$(dbq "SELECT COUNT(*) FROM wp_bouncer_log WHERE action = 'alert' AND reason LIKE 'Administrator login data erased for user ID $ADMIN_ID %'")"
rm -f "$MAILLOG"
check "login after an erase works"             302 "$(login 198.18.9.71 admin_e2e e2e-pass-123)"
check "  ...from a new range still alerts"     1 "$(mail_count)"

fi
if want "Threat map (WPB-11)"; then
# The Activity Log map on real HTTP: dots for seeded countries, the base map as a local <img>, the date filter
# moving the table, nothing external in the panel's markup, and the schema 3 to 4 upgrade on this database.
admin_login
$WP eval 'update_option( "wp_bouncer_geo_meta", array( "rows" => 5, "source" => "test", "imported" => time() ) ); global $wpdb; $wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_log" ); WPBouncer\Admin\ThreatMapPanel::flush();' > /dev/null
MAP_NOW=$(date -u +'%Y-%m-%d %H:%M:%S')
MAP_OLD=$(date -u -d '20 days ago' +'%Y-%m-%d')
map_page() { # map_page URL -> like admin, after clearing the per-user 5 s throttle on map cache misses
	dbq "DELETE FROM wp_options WHERE option_name LIKE '%wpb_map_thr_%'" > /dev/null
	admin "$@"
}
map_row() { # map_row IP COUNTRY ACTION 'created_at'
	dbq "INSERT INTO wp_bouncer_log (created_at, ip, rule, action, country, reason) VALUES ('$4', '$1', 'waf', '$3', '$2', 'map e2e')" > /dev/null
}
for i in 1 2 3; do map_row 198.18.50.1 ZA blocked "$MAP_NOW"; done
map_row 198.18.50.2 ZA lockout "$MAP_NOW"
for i in 1 2; do map_row 198.18.50.3 NZ blocked "$MAP_NOW"; done
for i in 1 2 3 4 5; do map_row 198.18.50.4 AU monitored "$MAP_NOW"; done
map_row 198.18.50.5 JP alert "$MAP_NOW"
map_row 198.18.50.6 CA login "$MAP_NOW"
map_row 198.18.50.7 "" blocked "$MAP_NOW"
map_row 198.18.50.7 "" blocked "$MAP_NOW"
map_row 198.18.50.99 CL blocked "$MAP_OLD 12:00:00"
MAP_URL="$U/wp-admin/admin.php?page=wp-bouncer&tab=log"
check "Activity Log with the map loads"          200 "$(map_page "$MAP_URL")"
check "  ...no PHP errors"                       0 "$(grep -c 'Fatal error\|Warning:\|Notice:\|Deprecated:' "$WORK/admin.html")"
check "  ...has the panel and the dots layer"    1 "$(grep -c 'class="wpb-map-dots"' "$WORK/admin.html")"
check "  ...a dot for ZA with its count"         1 "$(grep -c 'aria-label="South Africa (ZA): 4 threats"' "$WORK/admin.html")"
check "  ...a dot for NZ"                        1 "$(grep -c 'data-cc="NZ"' "$WORK/admin.html")"
check "  ...no dot for monitored, alert, login rows" 0 "$(grep -c 'data-cc="AU"\|data-cc="JP"\|data-cc="CA"' "$WORK/admin.html")"
check "  ...a row 20 days back is inside the default window" 1 "$(grep -c 'data-cc="CL"' "$WORK/admin.html")"
check "  ...unknown location is counted"         1 "$(grep -c 'Unknown location: 2 threats' "$WORK/admin.html")"
check "  ...the window says last 30 days"        1 "$(grep -c 'Last 30 days' "$WORK/admin.html")"
check "  ...base map is an <img> from the plugin" 1 "$(grep -c '<img class="wpb-map-base" src="'"$U"'/wp-content/plugins/wp-bouncer/assets/map/world.svg?ver=' "$WORK/admin.html")"
check "  ...script and style are loaded"         2 "$(grep -c 'assets/threat-map.js?ver=\|assets/threat-map.css?ver=' "$WORK/admin.html")"
MAP_EXT=$("$PHP" -r '
	$h = file_get_contents($argv[1]); $o = $argv[2];
	preg_match("#<section class=\"wpb-map\".*?</section>#s", $h, $m);
	preg_match_all("#(?:https?:)?//[^\s\"\x27<>]+#", $m[0] ?? "", $u);
	echo count(array_filter($u[0], fn($x) => 0 !== strpos($x, $o)));
' "$WORK/admin.html" "$U")
check "  ...no external URL in the map markup"   0 "$MAP_EXT"
check "base map file is served"                  200 "$(curl -s -o "$WORK/world.svg" -w '%{http_code}' -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$U/wp-content/plugins/wp-bouncer/assets/map/world.svg")"
check "  ...and is an SVG without scripts"       0 "$(grep -ci '<script\|onload\|href=' "$WORK/world.svg")"
check "map script is served"                     200 "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Real-IP: 198.51.100.50" -A "$MOZ" "$U/wp-content/plugins/wp-bouncer/assets/threat-map.js")"
for tab in rules traffic tools dashboard; do
	admin "$U/wp-admin/admin.php?page=wp-bouncer&tab=$tab" > /dev/null
	check "$tab tab has no map script or panel"  0 "$(grep -c 'threat-map\|wpb-map-dots' "$WORK/admin.html")"
done
check "front page has no map script"             0 "$(curl -s -H "X-Real-IP: 203.0.113.10" -A "$MOZ" "$U/" | grep -c 'threat-map')"
# Filters: the map follows country and action, and ignores the search box and the IP filter.
map_page "$MAP_URL&country=NZ" > /dev/null
check "country filter: only NZ has a dot"        1 "$(grep -c 'data-cc=' "$WORK/admin.html")"
map_page "$MAP_URL&log_action=lockout" > /dev/null
check "action=lockout: only ZA, one threat"      1 "$(grep -c 'aria-label="South Africa (ZA): 1 threat"' "$WORK/admin.html")"
map_page "$MAP_URL&log_action=monitored" > /dev/null
check "action=monitored: message, no dots"       1 "$(grep -c 'nothing matches the action filter' "$WORK/admin.html")"
map_page "$MAP_URL&s=zzz-no-such-text&log_ip=192.0.2.250" > /dev/null
check "search and IP are ignored by the map"     1 "$(grep -c 'aria-label="South Africa (ZA): 4 threats"' "$WORK/admin.html")"
check "  ...and the note says so"                1 "$(grep -c 'Ignores the search box and the IP filter' "$WORK/admin.html")"
# Date range: the From/To inputs, and the table AND the map follow log_from/log_to.
map_page "$MAP_URL" > /dev/null
check "log toolbar has From and To date inputs"  2 "$(grep -o '<input type="date" name="log_from"\|<input type="date" name="log_to"' "$WORK/admin.html" | wc -l)"
check "unfiltered table lists the 20-day-old row" 1 "$( [ "$(grep -c '198.18.50.99' "$WORK/admin.html")" -ge 1 ] && echo 1 || echo 0 )"
map_page "$MAP_URL&log_from=$MAP_OLD&log_to=$MAP_OLD" > /dev/null
check "range on that day: the map has the CL dot" 1 "$(grep -c 'data-cc="CL"' "$WORK/admin.html")"
check "  ...and no ZA dot"                       0 "$(grep -c 'data-cc="ZA"' "$WORK/admin.html")"
check "  ...the inputs are refilled"             1 "$(grep -c 'name="log_from"[^>]*value="'"$MAP_OLD"'"' "$WORK/admin.html")"
# WPB-11 BUG while this fails: the date range is read by traffic_filters_from_request(), not log_filters_from_request().
check "  ...and the TABLE shows the CL row"     1 "$( [ "$(grep -o '198\.18\.50\.99' "$WORK/admin.html" | wc -l)" -ge 1 ] && echo 1 || echo 0 )"
check "  ...and not the ZA rows"                 0 "$(grep -o '198\.18\.50\.1\b' "$WORK/admin.html" | wc -l)"
map_page "$MAP_URL&log_from=$(date -u +%F)" > /dev/null
# WPB-11 BUG while this fails (same cause as above).
check "range from today: table drops the old row" 0 "$(grep -c '198.18.50.99' "$WORK/admin.html")"
map_page "$MAP_URL&log_from=2026-03-05&log_to=2026-03-01" > /dev/null
check "reversed range: notice shown"             1 "$(grep -c 'The end date is before the start date' "$WORK/admin.html")"
map_page "$MAP_URL&log_from=2026-02-30" > /dev/null
check "impossible date: notice shown"            1 "$(grep -c 'A date was not valid' "$WORK/admin.html")"
map_page "$MAP_URL&log_from=%3Cscript%3Ealert(1)%3C/script%3E" > /dev/null
check "hostile date: not echoed"                 0 "$(grep -c '<script>alert(1)' "$WORK/admin.html")"
# A visitor who is not logged in gets no map.
check "logged out: the log page redirects to login" 302 "$(curl -s -o "$WORK/anon.html" -w '%{http_code}' -H "X-Real-IP: 203.0.113.12" -A "$MOZ" "$MAP_URL")"
check "  ...and shows no map"                    0 "$(grep -c 'wpb-map' "$WORK/anon.html")"
# Upgrade 3 to 4: the action_created key is created and the redaction is not restarted. One eval does it all,
# because every WP-CLI call boots the plugin, and a site on version 3 is upgraded on that boot.
mapfile -t UPG < <($WP eval '
	global $wpdb;
	$idx = static function () use ( $wpdb ) { $k = array(); foreach ( $wpdb->get_results( "SHOW INDEX FROM {$wpdb->prefix}bouncer_log", ARRAY_A ) as $r ) { $k[ $r["Key_name"] ][ (int) $r["Seq_in_index"] ] = $r["Column_name"]; } return isset( $k["action_created"] ) ? implode( ",", $k["action_created"] ) : "none"; };
	echo $idx(), "\n";
	$wpdb->query( "ALTER TABLE {$wpdb->prefix}bouncer_log DROP INDEX action_created" );
	delete_option( "wp_bouncer_migration_3" );
	update_option( "wp_bouncer_db_version", "3" );
	echo $idx(), "\n";
	$before = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" );
	WPBouncer\Installer::maybe_upgrade();
	echo $idx(), "\n", get_option( "wp_bouncer_db_version" ), "\n";
	echo false === get_option( "wp_bouncer_migration_3" ) ? "missing" : "present", "\n";
	echo (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" ) === $before ? "kept" : "lost", "\n";
	echo false === wp_next_scheduled( "wp_bouncer_migrate_data" ) ? "unscheduled" : "scheduled", "\n";
' 2>&1)
check "fresh install has the action_created key" "action,created_at,country" "${UPG[0]:-}"
check "  ...dropped for the test"                "none" "${UPG[1]:-}"
check "upgrade from 3 recreates the key"         "action,created_at,country" "${UPG[2]:-}"
check "  ...records version 4"                   4 "${UPG[3]:-}"
check "  ...redaction is not restarted"          missing "${UPG[4]:-}"
check "  ...rows are kept"                       kept "${UPG[5]:-}"
check "  ...no redaction job scheduled"          unscheduled "${UPG[6]:-}"
check "  ...the Activity Log still renders"      200 "$(map_page "$MAP_URL")"
dbq "DELETE FROM wp_bouncer_log WHERE reason = 'map e2e'" > /dev/null
$WP eval 'WPBouncer\Admin\ThreatMapPanel::flush();' > /dev/null

fi
if want "PHP debug log"; then
# WordPress also writes informational lines here (e.g. "Automatic updates starting..."); only PHP problems count.
PHP_PROBLEMS='PHP (Fatal error|Parse error|Warning|Notice|Deprecated)'
touch "$W/debug.log"
# WP-CLI's own deprecation notices (newer PHP than the phar was built for) are
# test-tool noise, not the site's; anything raised in WordPress or the plugin counts.
site_problems() { grep -E "$PHP_PROBLEMS" "$W/debug.log" | grep -v 'wp-cli\.phar' || true; }
check "no PHP warnings or notices" 0 "$(site_problems | grep -c .)"
# One line per distinct message and location, most frequent first.
site_problems | sed -E 's/^\[[^]]*\] //' | sort | uniq -c | sort -rn | head -10 | cut -c1-300

fi

echo
if [ -n "$ONLY" ]; then
	echo "!!! PARTIAL RUN (WPB_E2E_ONLY=\"$ONLY\"). Sections that ran:"
	printf '%s' "$SECTIONS_RAN" | sed 's/^/      /'
fi
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
