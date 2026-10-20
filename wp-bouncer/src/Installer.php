<?php
/**
 * Activation, upgrade and deactivation routines.
 *
 * @package WPBouncer
 */

namespace WPBouncer;

defined( 'ABSPATH' ) || exit;

/**
 * Creates the plugin tables and schedules housekeeping.
 *
 * Tables:
 * - {prefix}bouncer_log  Every block, lockout and monitored match.
 * - {prefix}bouncer_geo  IP ranges -> country, loaded from a CSV you supply.
 *                        Bounds are 32-char hex strings (see GeoDatabase).
 */
final class Installer {

	/** Bump when the schema changes. maybe_upgrade() re-runs dbDelta. */
	public const DB_VERSION = '1';

	public const DB_VERSION_OPTION = 'wp_bouncer_db_version';

	public const CRON_HOOK = 'wp_bouncer_daily_maintenance';

	/** Activation hook. */
	public static function activate(): void {
		self::create_tables();
		if ( false === get_option( Settings::OPTION ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', true );
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/** Deactivation hook. Data is kept; uninstall.php removes it. */
	public static function deactivate(): void {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/** Re-run table creation after a plugin update that changed the schema. */
	public static function maybe_upgrade(): void {
		if ( get_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION ) {
			self::create_tables();
		}
	}

	/** Create or update the tables with dbDelta. */
	public static function create_tables(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$log     = $wpdb->prefix . 'bouncer_log';
		$geo     = $wpdb->prefix . 'bouncer_geo';

		// dbDelta is picky: two spaces after PRIMARY KEY, one column per line.
		dbDelta(
			"CREATE TABLE {$log} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created_at datetime NOT NULL,
  ip varchar(45) NOT NULL DEFAULT '',
  country char(2) NOT NULL DEFAULT '',
  rule varchar(32) NOT NULL DEFAULT '',
  action varchar(16) NOT NULL DEFAULT 'blocked',
  reason varchar(255) NOT NULL DEFAULT '',
  method varchar(10) NOT NULL DEFAULT '',
  uri varchar(2048) NOT NULL DEFAULT '',
  user_agent varchar(512) NOT NULL DEFAULT '',
  PRIMARY KEY  (id),
  KEY created_at (created_at),
  KEY ip (ip),
  KEY rule (rule)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$geo} (
  ip_from char(32) NOT NULL,
  ip_to char(32) NOT NULL,
  country char(2) NOT NULL,
  PRIMARY KEY  (ip_from)
) {$charset};"
		);

		update_option( self::DB_VERSION_OPTION, self::DB_VERSION, true );
	}
}
