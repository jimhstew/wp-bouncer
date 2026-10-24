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
 * - {prefix}bouncer_traffic  Requests that reached WordPress, kept up to a week
 *                        (see Traffic\TrafficLog). Version 2 of the schema.
 * - {prefix}bouncer_counters  Atomic login-attempt counters on sites without a
 *                        persistent object cache (see Storage\TableCounter). Version 3.
 *
 * All tables are per site on multisite ($wpdb->prefix is the site's prefix).
 *
 * Version 3 also redacts rows written by older versions (Storage\RedactionMigration).
 */
final class Installer {

	/** Bump when the schema changes. maybe_upgrade() re-runs dbDelta. */
	public const DB_VERSION = '3';

	public const DB_VERSION_OPTION = 'wp_bouncer_db_version';

	public const CRON_HOOK = 'wp_bouncer_daily_maintenance';

	/** Hourly purge of expired login counters. */
	public const COUNTER_PURGE_HOOK = 'wp_bouncer_counter_purge';

	/** Activation hook. */
	public static function activate(): void {
		self::create_tables();
		if ( false === get_option( Settings::OPTION ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', true );
		}
		self::schedule();
		self::migrate_data();
	}

	/** Schedule the housekeeping jobs that aren't scheduled yet. */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( self::COUNTER_PURGE_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::COUNTER_PURGE_HOOK );
		}
		if ( ! wp_next_scheduled( Traffic\TrafficRecorder::PURGE_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', Traffic\TrafficRecorder::PURGE_HOOK );
		}
	}

	/**
	 * Deactivation hook. Settings and the log are kept; uninstall.php removes them.
	 *
	 * @param bool $network_wide Deactivated for the whole network: do the same for every site.
	 */
	public static function deactivate( $network_wide = false ): void {
		if ( $network_wide && is_multisite() ) {
			self::for_each_site( array( self::class, 'deactivate_site' ) );
			return;
		}
		self::deactivate_site();
	}

	/**
	 * Run a callback inside every site of the network, 100 sites at a time.
	 *
	 * Sites are fetched page by page and the runtime object cache is flushed
	 * after each, so a network of thousands of sites doesn't run out of memory
	 * or time. The work is idempotent, so a run that is cut off can simply be repeated.
	 *
	 * @param callable $callback Called once per site with that site selected.
	 */
	public static function for_each_site( callable $callback ): void {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions -- a long loop over a big network; the host may forbid it, which is harmless.
		}
		$offset = 0;
		do {
			$ids  = get_sites(
				array(
					'fields' => 'ids',
					'number' => 100,
					'offset' => $offset,
				)
			);
			$more = 100 === count( $ids );
			foreach ( $ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				$callback();
				restore_current_blog();
				if ( function_exists( 'wp_cache_flush_runtime' ) ) {
					wp_cache_flush_runtime();
				}
			}
			$offset += 100;
		} while ( $more );
	}

	/** Deactivate for the current site: cron events and our block in uploads/.htaccess. */
	public static function deactivate_site(): void {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		wp_clear_scheduled_hook( Traffic\TrafficRecorder::PURGE_HOOK );
		wp_clear_scheduled_hook( Storage\RedactionMigration::HOOK );
		wp_clear_scheduled_hook( self::COUNTER_PURGE_HOOK );
		// Our block in uploads/.htaccess goes too (unless it is the network-wide one and
		// the user may not manage the firewall); it is written again on reactivation.
		Hardening\UploadsGuard::teardown();
	}

	/** Re-run table creation after a plugin update that changed the schema. */
	public static function maybe_upgrade(): void {
		if ( get_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION ) {
			self::create_tables();
			// Updates don't run the activation hook, so add jobs that are new in this version.
			self::schedule();
			self::migrate_data();
		}
	}

	/** Redact old rows: a short slice now, the rest from a cron event on a big site. */
	private static function migrate_data(): void {
		if ( Storage\RedactionMigration::pending() ) {
			// Schedule first: if this request is cut off, cron still finishes the job.
			Storage\RedactionMigration::schedule();
			( new Storage\RedactionMigration( self::user_lookup() ) )->run( 1.5 );
		}
	}

	/**
	 * Looks up an account by typed name for the migration.
	 *
	 * @return callable(string): ?string
	 */
	public static function user_lookup(): callable {
		return static function ( string $name ): ?string {
			$id   = username_exists( $name );
			$user = $id ? get_userdata( (int) $id ) : false;
			return $user ? (string) $user->user_login : null;
		};
	}

	/** Create or update the tables with dbDelta. */
	public static function create_tables(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$log     = $wpdb->prefix . 'bouncer_log';
		$geo     = $wpdb->prefix . 'bouncer_geo';
		$traffic = $wpdb->prefix . 'bouncer_traffic';
		$counter = $wpdb->prefix . 'bouncer_counters';

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

		dbDelta(
			"CREATE TABLE {$traffic} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created_at datetime NOT NULL,
  ip varchar(45) NOT NULL DEFAULT '',
  method varchar(10) NOT NULL DEFAULT '',
  uri varchar(2048) NOT NULL DEFAULT '',
  referrer varchar(2048) NOT NULL DEFAULT '',
  user_agent varchar(512) NOT NULL DEFAULT '',
  client varchar(16) NOT NULL DEFAULT '',
  status smallint(5) unsigned NOT NULL DEFAULT 0,
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  KEY created_at (created_at),
  KEY ip (ip),
  KEY client (client),
  KEY status (status),
  KEY user_id (user_id)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$counter} (
  counter_key char(32) NOT NULL,
  hits int(11) NOT NULL DEFAULT 0,
  expires_at bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY  (counter_key),
  KEY expires_at (expires_at)
) {$charset};"
		);

		// Any change of version starts the redaction. On a fresh install the tables are empty, so it ends at once.
		if ( self::DB_VERSION !== get_option( self::DB_VERSION_OPTION ) ) {
			Storage\RedactionMigration::begin();
		}
		update_option( self::DB_VERSION_OPTION, self::DB_VERSION, true );
	}
}
