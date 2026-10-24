<?php
/**
 * Bootstrap for the WordPress integration suite.
 *
 * Loads the official WordPress test library (wp-phpunit), then the plugin on
 * muplugins_loaded, then runs the plugin's activation so its tables exist.
 *
 * This does NOT load tests/bootstrap.php: that one fakes ABSPATH for the unit suite.
 *
 * @package WPBouncer\Tests
 */

$wpb_root = dirname( __DIR__, 2 );

if ( ! is_readable( $wpb_root . '/vendor/autoload.php' ) ) {
	fwrite( STDERR, "Run `composer install` first.\n" );
	exit( 1 );
}
require_once $wpb_root . '/vendor/autoload.php';

$wpb_lib = getenv( 'WP_PHPUNIT__DIR' );
if ( false === $wpb_lib || ! is_dir( $wpb_lib ) ) {
	fwrite( STDERR, "wp-phpunit is not installed (composer require --dev wp-phpunit/wp-phpunit).\n" );
	exit( 1 );
}

// Point the test library at our config (both the newer constant and the older env var).
define( 'WP_TESTS_CONFIG_FILE_PATH', __DIR__ . '/wp-tests-config.php' );
putenv( 'WP_PHPUNIT__TESTS_CONFIG=' . __DIR__ . '/wp-tests-config.php' );

require_once $wpb_lib . '/includes/functions.php';

tests_add_filter(
	'muplugins_loaded',
	static function () use ( $wpb_root ): void {
		require $wpb_root . '/wp-bouncer/wp-bouncer.php';
	}
);

require $wpb_lib . '/includes/bootstrap.php';

// The test library reinstalls the core tables on every run but knows nothing
// about ours, so start from a clean slate and activate the plugin properly.
global $wpdb;
foreach ( array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic' ) as $wpb_table ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$wpb_table}" ); // phpcs:ignore WordPress.DB
}
delete_option( \WPBouncer\Installer::DB_VERSION_OPTION );
\WPBouncer\Installer::activate();
