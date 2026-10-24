<?php
/**
 * Removes every trace of WP Bouncer when the plugin is deleted from the Plugins screen.
 *
 * @package WPBouncer
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// The classes below need PHP 8.3. On an older PHP leave the data alone rather than fatal.
if ( version_compare( preg_replace( '/-.*$/', '', (string) phpversion() ), '8.3', '<' ) ) {
	return;
}

global $wpdb;

// Remove our block from uploads/.htaccess (anything else in that file stays).
require_once __DIR__ . '/src/Autoloader.php';
\WPBouncer\Autoloader::register( __DIR__ . '/src' );
\WPBouncer\Hardening\UploadsGuard::teardown();

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- one-off uninstall cleanup of the plugin's own tables and transients; nothing to cache.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_log" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_geo" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_traffic" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_counters" );

delete_option( 'wp_bouncer_settings' );
delete_option( 'wp_bouncer_db_version' );
delete_option( 'wp_bouncer_geo_meta' );
delete_site_transient( 'wp_bouncer_update_manifest' );

// An unfinished geo import leaves a progress record and a working CSV.
$wpb_import = get_option( 'wp_bouncer_geo_import' );
if ( is_array( $wpb_import ) && ! empty( $wpb_import['file'] ) && is_string( $wpb_import['file'] ) ) {
	wp_delete_file( $wpb_import['file'] );
}
delete_option( 'wp_bouncer_geo_import' );
delete_option( 'wp_bouncer_last_purge' );
delete_option( 'wp_bouncer_migration_3' );
delete_option( 'wp_bouncer_migration_3_lock' );
delete_option( 'wp_bouncer_counter_failed' );
$wpb_uploads = wp_upload_dir( null, false );
$wpb_dir     = $wpb_uploads['basedir'] . '/wp-bouncer';
if ( is_dir( $wpb_dir ) ) {
	foreach ( (array) scandir( $wpb_dir ) as $wpb_name ) {
		if ( is_file( $wpb_dir . '/' . $wpb_name ) ) {
			wp_delete_file( $wpb_dir . '/' . $wpb_name );
		}
	}
	@rmdir( $wpb_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions -- best-effort cleanup: the folder may be missing or not empty, and failure is harmless.
}

// Counters, lockouts and bans are transients named wpb_<md5>.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_wpb\\_%' OR option_name LIKE '\\_transient\\_timeout\\_wpb\\_%'" );
// phpcs:enable WordPress.DB.DirectDatabaseQuery

wp_clear_scheduled_hook( 'wp_bouncer_daily_maintenance' );
wp_clear_scheduled_hook( 'wp_bouncer_uploads_check' );
wp_clear_scheduled_hook( 'wp_bouncer_traffic_purge' );
wp_clear_scheduled_hook( 'wp_bouncer_migrate_data' );
wp_clear_scheduled_hook( 'wp_bouncer_counter_purge' );
