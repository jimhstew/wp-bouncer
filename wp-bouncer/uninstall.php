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

require_once __DIR__ . '/src/Autoloader.php';
\WPBouncer\Autoloader::register( __DIR__ . '/src' );

if ( ! function_exists( 'wp_bouncer_uninstall_site' ) ) {
	/**
	 * Remove everything WP Bouncer keeps for the current site (tables, options,
	 * transients, cron events, working folder and its block in uploads/.htaccess).
	 *
	 * On multisite it runs once per site, inside switch_to_blog().
	 */
	function wp_bouncer_uninstall_site(): void {
		global $wpdb;

		// Remove our block from uploads/.htaccess (anything else in that file stays).
		// Forced: the plugin's files are being deleted, so its block must not outlive it.
		\WPBouncer\Hardening\UploadsGuard::teardown( true );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- one-off uninstall cleanup of the plugin's own tables and transients; nothing to cache.
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_log" );
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_geo" );
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_traffic" );
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bouncer_counters" );

		delete_option( 'wp_bouncer_settings' );
		delete_option( 'wp_bouncer_db_version' );
		delete_option( 'wp_bouncer_geo_meta' );

		$wpb_uploads = wp_upload_dir( null, false );
		$wpb_dir     = $wpb_uploads['basedir'] . '/wp-bouncer';

		// An unfinished geo import leaves a progress record and a working CSV (inside our own folder only).
		$wpb_import = get_option( 'wp_bouncer_geo_import' );
		if ( is_array( $wpb_import ) && ! empty( $wpb_import['file'] ) && is_string( $wpb_import['file'] ) ) {
			wp_delete_file_from_directory( $wpb_import['file'], $wpb_dir );
		}
		delete_option( 'wp_bouncer_geo_import' );
		delete_option( 'wp_bouncer_last_purge' );
		delete_option( 'wpb_disabled_alerted' );
		delete_option( 'wp_bouncer_migration_3' );
		delete_option( 'wp_bouncer_migration_3_lock' );
		delete_option( 'wp_bouncer_counter_failed' );
		if ( is_dir( $wpb_dir ) ) {
			foreach ( (array) scandir( $wpb_dir ) as $wpb_name ) {
				if ( is_file( $wpb_dir . '/' . $wpb_name ) ) {
					wp_delete_file( $wpb_dir . '/' . $wpb_name );
				}
			}
			@rmdir( $wpb_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions -- best-effort cleanup: the folder may be missing or not empty, and failure is harmless.
		}

		// Our transients (and their timeout rows): counters, lockouts and bans are wpb_<32 hex>; the rest
		// have fixed names. Found with a loose LIKE (no escaping, so it works on SQLite too) and then
		// matched exactly, in id order and in batches, so another plugin's wpb_* transient is left alone.
		$wpb_exact  = '/^_transient_(?:timeout_)?(?:wpb_(?:[0-9a-f]{32}|ctrfb_.+|flash_\d+|alert_count(?:_critical)?|widget_stats.*)|wp_bouncer_(?:export_[0-9a-f]{32}|erase_range_\d+))$/';
		$wpb_cursor = 0;
		do {
			$wpb_rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_id, option_name FROM {$wpdb->options} WHERE option_id > %d AND (option_name LIKE %s OR option_name LIKE %s) ORDER BY option_id LIMIT 1000",
					$wpb_cursor,
					'_transient_%wpb_%',
					'_transient_%wp_bouncer_%'
				),
				ARRAY_A
			);
			$wpb_more = 1000 === count( $wpb_rows );
			$wpb_ids  = array();
			foreach ( $wpb_rows as $wpb_row ) {
				$wpb_cursor = (int) $wpb_row['option_id'];
				if ( 1 === preg_match( $wpb_exact, (string) $wpb_row['option_name'] ) ) {
					$wpb_ids[] = $wpb_cursor;
				}
			}
			if ( $wpb_ids ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_id IN (" . implode( ',', array_fill( 0, count( $wpb_ids ), '%d' ) ) . ')', $wpb_ids ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- one %d per id.
			}
		} while ( $wpb_more );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange

		foreach ( array( 'wp_bouncer_daily_maintenance', 'wp_bouncer_uploads_check', 'wp_bouncer_traffic_purge', 'wp_bouncer_migrate_data', 'wp_bouncer_counter_purge' ) as $wpb_hook ) {
			wp_clear_scheduled_hook( $wpb_hook );
		}
	}
}

if ( is_multisite() ) {
	// Every site has its own tables, options, cron events and uploads folder. Sites are done in
	// pages with the runtime cache flushed between them; the cleanup is idempotent, so if a very
	// large network runs out of time, running the uninstall again picks up where it stopped.
	\WPBouncer\Installer::for_each_site( 'wp_bouncer_uninstall_site' );
} else {
	wp_bouncer_uninstall_site();
}
delete_site_transient( 'wp_bouncer_update_manifest' );
// The environment notice's dismissal is user meta, which is network-wide: once is enough.
delete_metadata( 'user', 0, 'wpb_env_notice_dismissed', '', true );
