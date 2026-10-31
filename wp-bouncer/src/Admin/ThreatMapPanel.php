<?php
/**
 * The "Threats by country" map on the Activity Log tab.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Installer;
use WPBouncer\Log\DateRange;
use WPBouncer\Log\ThreatMapSource;
use WPBouncer\Plugin;
use WPBouncer\Support\Clock;
use WPBouncer\ThreatMap\CachePolicy;
use WPBouncer\ThreatMap\Centroids;
use WPBouncer\ThreatMap\CountryTally;
use WPBouncer\ThreatMap\KeyIndex;
use WPBouncer\ThreatMap\MapModel;
use WPBouncer\ThreatMap\ThreatQuery;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress-facing adapter: capability check, transients (a capped group, a site-wide lock and a
 * per-user throttle), flush hooks and rendering. The numbers are computed server-side and drawn by PHP.
 * Admin only and read only: no AJAX or REST route, nothing on the firewall or front-end path.
 */
final class ThreatMapPanel {

	/** Option holding the index of cached boxes (not autoloaded). */
	public const KEYS_OPTION = 'wpb_map_keys';

	/** Option holding the generation counter (not autoloaded). Only flush() writes it, so a build can't write an old value back. */
	public const GEN_OPTION = 'wpb_map_gen';

	/** Site-wide lock: one map aggregate is built at a time (an option holding "time|token", or an object cache key). */
	public const LOCK_OPTION = 'wpb_map_lock';

	/** Prefix of the per-user throttle transient. */
	public const THROTTLE_PREFIX = 'wpb_map_thr_';

	/** Seconds the lock is held if the build never finishes. */
	private const LOCK_SECONDS = 30;

	/** Seconds a user waits between two cache misses. */
	private const THROTTLE_SECONDS = 5;

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Clock.
	 *
	 * @var Clock
	 */
	private Clock $clock;

	/**
	 * Where the numbers come from (tests pass a fake).
	 *
	 * @var ThreatMapSource|null
	 */
	private ?ThreatMapSource $source;

	/**
	 * Set up the panel.
	 *
	 * @param Plugin               $plugin Plugin instance.
	 * @param Clock|null           $clock  Clock (tests pass a frozen one).
	 * @param ThreatMapSource|null $source Data source (default: the plugin's log).
	 */
	public function __construct( Plugin $plugin, ?Clock $clock = null, ?ThreatMapSource $source = null ) {
		$this->plugin = $plugin;
		$this->clock  = $clock ?? new Clock();
		$this->source = $source;
	}

	/** Register the hooks that throw the cache away, like the dashboard widget's. */
	public function register(): void {
		add_action( 'wp_bouncer_log_cleared', array( self::class, 'flush' ) );
		add_action( 'wp_bouncer_settings_changed', array( self::class, 'flush' ) );
		// After Plugin::daily_maintenance() (priority 10) has purged the log.
		add_action( Installer::CRON_HOOK, array( self::class, 'flush' ), 20 );
	}

	/**
	 * Forget every cached map and make orphans unreachable (the generation is part of every key).
	 *
	 * Any code that deletes log rows must call this, as it calls DashboardWidget::flush().
	 */
	public static function flush(): void {
		$index = self::read_index();
		$next  = KeyIndex::flushed( $index );
		// Bump first: from here on no reader can reach an old box. The lock is left alone: a running build sees the new generation and discards its box.
		update_option( self::GEN_OPTION, $next['gen'], false );
		foreach ( array_keys( $index['keys'] ) as $name ) {
			delete_transient( $name );
		}
		update_option( self::KEYS_OPTION, array( 'keys' => array() ), false );
	}

	/**
	 * The generation and the key index, from their two options.
	 *
	 * @return array{gen: int, keys: array<string, int>}
	 */
	private static function read_index(): array {
		$keys = get_option( self::KEYS_OPTION, array() );
		return KeyIndex::normalise(
			array(
				'gen'  => (int) get_option( self::GEN_OPTION, 0 ),
				'keys' => is_array( $keys ) ? ( $keys['keys'] ?? array() ) : array(),
			)
		);
	}

	/**
	 * Print the panel.
	 *
	 * @param array<string, string> $log_filters The Activity Log filters (search and IP are ignored here).
	 * @param DateRange             $range       The date range.
	 */
	public function render( array $log_filters, DateRange $range ): void {
		if ( is_network_admin() || ! current_user_can( AdminController::CAPABILITY ) ) {
			return;
		}
		$query = ThreatQuery::from_filters( $log_filters, $range );
		$load  = 'ok';
		$tally = null;
		$built = 0;
		if ( $query->runnable() ) {
			$result = $this->load( $query );
			$load   = $result['load'];
			$tally  = $result['tally'];
			$built  = $result['built'];
		}
		$geo   = $this->plugin->geo_database_loaded();
		$state = MapModel::state( $query->runnable(), $load, $tally, $geo );
		$model = ( 'ok' === $state && null !== $tally ) ? MapModel::build( $tally ) : null;
		$now   = $this->clock->now();

		$base_file = dirname( $this->plugin->file() ) . '/assets/map/world.svg';
		$show_base = is_readable( $base_file );
		$base_url  = plugin_dir_url( $this->plugin->file() ) . 'assets/map/world.svg';

		$height = (int) Centroids::HEIGHT;
		$width  = (int) Centroids::WIDTH;

		require __DIR__ . '/views/partials/threat-map.php';
	}

	/**
	 * The tally for a query: cached when fresh, rebuilt when stale and nobody else is.
	 *
	 * @param ThreatQuery $query Runnable query.
	 * @return array{load: string, tally: CountryTally|null, built: int} load is ok | busy | error; built is the build time of the numbers.
	 */
	private function load( ThreatQuery $query ): array {
		$now      = $this->clock->now();
		$index    = self::read_index();
		$name     = $query->cache_key( $index['gen'] );
		$box      = CachePolicy::normalise_box( get_transient( $name ) );
		$thr_name = self::THROTTLE_PREFIX . get_current_user_id();
		$locked   = self::lock_held();
		$throttle = false !== get_transient( $thr_name );

		$decision = CachePolicy::decide( $box, $now, $locked, $throttle );
		if ( CachePolicy::BUSY === $decision ) {
			return array(
				'load'  => 'busy',
				'tally' => null,
				'built' => 0,
			);
		}
		if ( CachePolicy::BUILD !== $decision && null !== $box ) {
			return array(
				'load'  => 'ok',
				'tally' => CountryTally::from_array( $box['tally'] ),
				'built' => $box['built'],
			);
		}

		$token = self::acquire_lock();
		if ( null === $token ) {
			// Another request won the race to build: serve the stale numbers, or ask the user to retry.
			return null !== $box
				? array(
					'load'  => 'ok',
					'tally' => CountryTally::from_array( $box['tally'] ),
					'built' => $box['built'],
				)
				: array(
					'load'  => 'busy',
					'tally' => null,
					'built' => 0,
				);
		}
		set_transient( $thr_name, 1, self::THROTTLE_SECONDS );
		try {
			$source = $this->source ?? $this->plugin->log();
			$rows   = $source->threats_by_country( $query->filters(), $query->since(), $query->until() );
			if ( null === $rows ) {
				// A database error: cache nothing, show the stale numbers if there are any (never the error text).
				return null !== $box
					? array(
						'load'  => 'ok',
						'tally' => CountryTally::from_array( $box['tally'] ),
						'built' => $box['built'],
					)
					: array(
						'load'  => 'error',
						'tally' => null,
						'built' => 0,
					);
			}
			$tally = CountryTally::from_rows( $rows );
			/**
			 * Filters how long the threat map's numbers are cached, in seconds (60 to 3600).
			 * A very large log (more than DashboardWidget::FLOOD_ROWS threats in the window) is always cached for 3600.
			 *
			 * @param int $seconds Default 300.
			 */
			$ttl = CachePolicy::ttl( (int) apply_filters( 'wp_bouncer_map_cache_ttl', CachePolicy::DEFAULT_TTL ), $tally->total() );
			set_transient( $name, CachePolicy::make_box( $now, $ttl, $tally->to_array() ), DAY_IN_SECONDS );
			// Under the lock, read the index again: a flush during the build moved the generation, and this box is from before it.
			$current = self::read_index();
			if ( $current['gen'] !== $index['gen'] ) {
				delete_transient( $name );
				return array(
					'load'  => 'ok',
					'tally' => $tally,
					'built' => $now,
				);
			}
			$kept = KeyIndex::remember( $current, $name, $now );
			foreach ( $kept['evicted'] as $old ) {
				delete_transient( $old );
			}
			update_option( self::KEYS_OPTION, array( 'keys' => $kept['index']['keys'] ), false );
			return array(
				'load'  => 'ok',
				'tally' => $tally,
				'built' => $now,
			);
		} finally {
			self::release_lock( $token );
		}
	}

	/**
	 * Is a build running? Uses the object cache when there is a persistent one, else the option.
	 */
	private static function lock_held(): bool {
		if ( wp_using_ext_object_cache() ) {
			return false !== wp_cache_get( self::LOCK_OPTION, 'wpb_map' );
		}
		return (int) strtok( (string) get_option( self::LOCK_OPTION, '' ), '|' ) > time() - self::LOCK_SECONDS;
	}

	/**
	 * Take the build lock atomically (like AlertNotifier::claim_reminder_slot()).
	 *
	 * With a persistent object cache it is wp_cache_add(). Otherwise the row is created with
	 * INSERT IGNORE (core's add_option() is an upsert, so two requests could both win), and a stale
	 * row is replaced with a compare-and-swap UPDATE on the value that was read. Plain SQL that
	 * MySQL, MariaDB and SQLite all run.
	 *
	 * @return string|null A token to release it with, or null when another request holds it.
	 */
	public static function acquire_lock(): ?string {
		global $wpdb;
		$token = wp_generate_password( 12, false );
		if ( wp_using_ext_object_cache() ) {
			return wp_cache_add( self::LOCK_OPTION, $token, 'wpb_map', self::LOCK_SECONDS ) ? $token : null;
		}
		$value = time() . '|' . $token;
		// Two tries: the second covers a row that vanished between the insert and the read.
		for ( $try = 0; $try < 2; $try++ ) {
			$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO %i (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $wpdb->options, self::LOCK_OPTION, $value ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- atomic claim, see above.
			if ( 1 === $inserted ) {
				self::forget_lock_cache();
				return $token;
			}
			$held = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, self::LOCK_OPTION ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- read around the object cache on purpose: the claim must see the latest value.
			if ( null === $held ) {
				continue;
			}
			if ( (int) strtok( (string) $held, '|' ) > time() - self::LOCK_SECONDS ) {
				return null;
			}
			// Stale: its holder is gone. Of the requests that race to replace it, only one UPDATE matches the old value.
			$won = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $wpdb->options, $value, self::LOCK_OPTION, (string) $held ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- compare-and-swap, see above.
			self::forget_lock_cache();
			return 1 === $won ? $token : null;
		}
		return null;
	}

	/**
	 * Release the lock, only if this request still owns it.
	 *
	 * @param string $token Token from acquire_lock().
	 */
	public static function release_lock( string $token ): void {
		global $wpdb;
		if ( wp_using_ext_object_cache() ) {
			if ( wp_cache_get( self::LOCK_OPTION, 'wpb_map' ) === $token ) {
				wp_cache_delete( self::LOCK_OPTION, 'wpb_map' );
			}
			return;
		}
		$held = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, self::LOCK_OPTION ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- must see the latest value.
		if ( null === $held || substr( (string) $held, -strlen( $token ) - 1 ) !== '|' . $token ) {
			return;
		}
		// Conditional on the exact value: if another request took the lock meanwhile, nothing matches.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE option_name = %s AND option_value = %s', $wpdb->options, self::LOCK_OPTION, (string) $held ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- conditional delete, see above.
		self::forget_lock_cache();
	}

	/** Drop cached copies of the lock option so get_option() stays coherent after a direct write. */
	private static function forget_lock_cache(): void {
		wp_cache_delete( self::LOCK_OPTION, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}
}
