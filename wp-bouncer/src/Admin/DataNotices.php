<?php
/**
 * Admin-side upkeep and notices for the stored data.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Installer;
use WPBouncer\Storage\RedactionMigration;
use WPBouncer\Storage\TableCounter;

defined( 'ABSPATH' ) || exit;

/**
 * For administrators only:
 * - continues an unfinished data migration with one small slice per admin request (a site
 *   where WP-Cron doesn't run would otherwise never finish it) and says so in a notice;
 * - warns when the login counter table failed, because lockouts then use the weaker
 *   transient fallback.
 */
final class DataNotices {

	/** Register the hooks. */
	public function register(): void {
		add_action( 'admin_init', array( $this, 'continue_migration' ) );
		add_action( 'admin_notices', array( $this, 'render' ) );
	}

	/** Run a short slice of a pending migration (admin_init). */
	public function continue_migration(): void {
		if ( ! current_user_can( 'manage_options' ) || ! RedactionMigration::pending() ) {
			return;
		}
		RedactionMigration::schedule();
		( new RedactionMigration( Installer::user_lookup() ) )->run( 1.0 );
	}

	/** Print the notices (admin_notices). */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( RedactionMigration::pending() ) {
			echo '<div class="notice notice-info"><p>' . esc_html__( 'WP Bouncer is removing secrets from old log entries after the update. It continues in the background and in each admin page load, and this notice goes away when it is done.', 'wp-bouncer' ) . '</p></div>';
		}
		if ( $this->counter_table_failed() ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'WP Bouncer could not use its login counter table, so login lockouts are using a less exact fallback. Deactivate and reactivate WP Bouncer to recreate the table.', 'wp-bouncer' ) . '</p></div>';
		}
	}

	/** Did the counter table fail, and is it still unusable? Clears the flag once the table is back. */
	private function counter_table_failed(): bool {
		if ( false === get_option( TableCounter::FAILED_OPTION ) ) {
			return false;
		}
		global $wpdb;
		$table = TableCounter::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- a one-off existence check on the plugin's own table.
		if ( $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) ) {
			delete_option( TableCounter::FAILED_OPTION );
			return false;
		}
		return true;
	}
}
