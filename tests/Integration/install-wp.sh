#!/usr/bin/env bash
#
# Downloads WordPress core for the integration suite and creates its database.
#
#   tests/Integration/install-wp.sh [latest | x.y | x.y.z | nightly]
#
# What it does
#   1. Downloads and unpacks WordPress core into $WP_CORE_DIR
#      (default: <repo>/builds/wp-core/<version>). No svn needed.
#   2. Creates the database $WPB_TESTS_DB_NAME if it does not exist, using PHP's
#      mysqli. No mysql client binary needed.
#   3. Prints the environment variables to run the suite with.
#
# The WordPress *test library* is not downloaded here: it comes from the
# wp-phpunit/wp-phpunit Composer package (a mirror of core's tests/phpunit
# per WordPress release). For the newest WordPress, `composer install` is enough.
# For an older WordPress, pin wp-phpunit to the same minor version first:
#
#   composer require --dev -W wp-phpunit/wp-phpunit:5.9.*
#   (or: WPB_PIN_WP_PHPUNIT=1 tests/Integration/install-wp.sh 5.9)
#
# Environment (all optional)
#   PHP                    php binary (default: php)
#   COMPOSER               composer command used for pinning (default: composer)
#   WP_CORE_DIR            where core is unpacked
#   WPB_TESTS_DB_HOST      default 127.0.0.1   (host:port allowed, e.g. 127.0.0.1:3307)
#   WPB_TESTS_DB_USER      default root
#   WPB_TESTS_DB_PASSWORD  default empty
#   WPB_TESTS_DB_NAME      default wpb_tests
#   WPB_PIN_WP_PHPUNIT=1   also pin wp-phpunit to the requested x.y (not for latest/nightly)
#
# WARNING: the integration suite DROPS and recreates every table in the
# database named by WPB_TESTS_DB_NAME. Use a throwaway database.

set -euo pipefail

VERSION="${1:-latest}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PHP="${PHP:-php}"
COMPOSER="${COMPOSER:-composer}"

DB_HOST="${WPB_TESTS_DB_HOST:-127.0.0.1}"
DB_USER="${WPB_TESTS_DB_USER:-root}"
DB_PASS="${WPB_TESTS_DB_PASSWORD:-}"
DB_NAME="${WPB_TESTS_DB_NAME:-wpb_tests}"

case "$VERSION" in
	latest)  URL="https://wordpress.org/latest.tar.gz"; EXT=tar.gz ;;
	nightly) URL="https://wordpress.org/nightly-builds/wordpress-latest.zip"; EXT=zip ;;
	[0-9]*.[0-9]*)
		# 5.9 and 6.0 style releases are published as wordpress-5.9.tar.gz.
		URL="https://wordpress.org/wordpress-${VERSION}.tar.gz"; EXT=tar.gz ;;
	*) echo "Unknown version '$VERSION' (use latest, nightly, x.y or x.y.z)" >&2; exit 2 ;;
esac

WP_CORE_DIR="${WP_CORE_DIR:-$ROOT/builds/wp-core/$VERSION}"

if [ -f "$WP_CORE_DIR/wp-settings.php" ] && [ "$VERSION" != "nightly" ] && [ "$VERSION" != "latest" ]; then
	echo "WordPress $VERSION already in $WP_CORE_DIR"
else
	tmp="$(mktemp -d "${TMPDIR:-/tmp}/wpb-wp.XXXXXX")"
	trap 'rm -rf "$tmp"' EXIT
	echo "Downloading $URL"
	curl -fsSL -o "$tmp/wp.$EXT" "$URL"
	# WordPress.org publishes a .sha1 next to each release tarball (nightly builds have none).
	if [ "$VERSION" != nightly ]; then
		want="$(curl -fsSL "$URL.sha1" | tr -d '[:space:]')"
		if command -v sha1sum > /dev/null; then have="$(sha1sum "$tmp/wp.$EXT" | cut -d' ' -f1)"; else have="$(shasum -a 1 "$tmp/wp.$EXT" | cut -d' ' -f1)"; fi
		if [ -z "$want" ] || [ "$want" != "$have" ]; then echo "Checksum mismatch for $URL (expected '$want', got '$have')" >&2; exit 1; fi
		echo "Checksum OK (sha1 $have)"
	fi
	mkdir -p "$tmp/x"
	if [ "$EXT" = zip ]; then unzip -q "$tmp/wp.zip" -d "$tmp/x"; else tar -xzf "$tmp/wp.tar.gz" -C "$tmp/x"; fi
	rm -rf "$WP_CORE_DIR"
	mkdir -p "$(dirname "$WP_CORE_DIR")"
	mv "$tmp/x/wordpress" "$WP_CORE_DIR"
	echo "Unpacked to $WP_CORE_DIR"
fi

# Create the database with mysqli (the mysql client is not required).
"$PHP" -r '
	mysqli_report( MYSQLI_REPORT_OFF );
	list( $host, $user, $pass, $name ) = array_slice( $argv, 1 );
	$port = 3306;
	if ( false !== strpos( $host, ":" ) ) { list( $host, $port ) = explode( ":", $host, 2 ); $port = (int) $port; }
	$db = mysqli_connect( $host, $user, $pass, "", $port );
	if ( ! $db ) { fwrite( STDERR, "Cannot connect to MySQL at $host:$port: " . mysqli_connect_error() . "\n" ); exit( 1 ); }
	if ( ! preg_match( "/^[A-Za-z0-9_]+$/", $name ) ) { fwrite( STDERR, "Bad database name\n" ); exit( 1 ); }
	if ( ! $db->query( "CREATE DATABASE IF NOT EXISTS `$name` DEFAULT CHARACTER SET utf8mb4" ) ) { fwrite( STDERR, $db->error . "\n" ); exit( 1 ); }
	echo "Database $name ready on $host:$port\n";
' "$DB_HOST" "$DB_USER" "$DB_PASS" "$DB_NAME"

if [ "${WPB_PIN_WP_PHPUNIT:-}" = 1 ]; then
	case "$VERSION" in
		[0-9]*.[0-9]*)
			minor="$(echo "$VERSION" | cut -d. -f1-2)"
			(cd "$ROOT" && $COMPOSER require --dev -W --no-interaction "wp-phpunit/wp-phpunit:${minor}.*") ;;
		*) echo "Not pinning wp-phpunit for '$VERSION' (it follows the newest release)." ;;
	esac
fi

cat <<MSG

Run the suite with:
  export WP_CORE_DIR='$WP_CORE_DIR'
  export WPB_TESTS_DB_HOST='$DB_HOST' WPB_TESTS_DB_USER='$DB_USER' WPB_TESTS_DB_NAME='$DB_NAME'
  export WPB_TESTS_DB_PASSWORD=...
  vendor/bin/phpunit -c phpunit-integration.xml.dist
MSG
