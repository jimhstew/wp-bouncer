<?php
/**
 * Configuration for the WordPress test library (integration suite).
 *
 * Everything comes from environment variables so CI and local runs share it:
 *
 *   WP_CORE_DIR            WordPress core (see install-wp.sh)
 *   WPB_TESTS_DB_HOST      default 127.0.0.1 (host:port allowed)
 *   WPB_TESTS_DB_USER      default root
 *   WPB_TESTS_DB_PASSWORD  default empty
 *   WPB_TESTS_DB_NAME      default wpb_tests
 *
 * WARNING: the test library DROPS every WordPress table in that database on
 * each run. Use a throwaway database.
 *
 * @package WPBouncer\Tests
 */

/**
 * Read an environment variable with a default.
 *
 * @param string $name    Variable.
 * @param string $default Fallback when unset or empty.
 */
function wpb_tests_env( string $name, string $default ): string {
	$value = getenv( $name );
	return false === $value || '' === $value ? $default : $value;
}

$wpb_core = rtrim( wpb_tests_env( 'WP_CORE_DIR', dirname( __DIR__, 2 ) . '/builds/wp-core/latest' ), '/\\' );
if ( ! is_file( $wpb_core . '/wp-settings.php' ) ) {
	fwrite( STDERR, "WordPress core not found in '{$wpb_core}'. Run tests/Integration/install-wp.sh or set WP_CORE_DIR.\n" );
	exit( 1 );
}

define( 'ABSPATH', $wpb_core . '/' );

define( 'DB_HOST', wpb_tests_env( 'WPB_TESTS_DB_HOST', '127.0.0.1' ) );
define( 'DB_USER', wpb_tests_env( 'WPB_TESTS_DB_USER', 'root' ) );
define( 'DB_PASSWORD', (string) getenv( 'WPB_TESTS_DB_PASSWORD' ) );
define( 'DB_NAME', wpb_tests_env( 'WPB_TESTS_DB_NAME', 'wpb_tests' ) );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

$table_prefix = 'wptests_';

define( 'WP_TESTS_DOMAIN', 'example.org' );
define( 'WP_TESTS_EMAIL', 'admin@example.org' );
define( 'WP_TESTS_TITLE', 'WP Bouncer Tests' );
define( 'WP_PHP_BINARY', PHP_BINARY );
define( 'WPLANG', '' );
define( 'WP_DEBUG', true );

// Keep the sandbox free of auto-updates and external requests.
define( 'AUTOMATIC_UPDATER_DISABLED', true );
define( 'WP_AUTO_UPDATE_CORE', false );
