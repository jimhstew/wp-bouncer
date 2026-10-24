<?php
/**
 * Atomic counter in the {prefix}bouncer_counters table.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Storage;

defined( 'ABSPATH' ) || exit;

/**
 * For sites without a persistent object cache.
 *
 * Only statements that MySQL, MariaDB and SQLite all run (no ON DUPLICATE KEY
 * UPDATE, no UPDATE/DELETE ... LIMIT). Per-row atomicity of
 * "SET hits = hits + 1" comes from InnoDB row locks or SQLite's database lock.
 * The window reset is guarded by "expires_at <= now", and the reset moves
 * expires_at forward, so two racing resets can't both succeed.
 *
 * The SELECT after the increment can see other requests' increments made in between, so
 * it may overcount by the number of racing requests. That errs towards refusing a guess
 * sooner, which is the safe side for a brute-force limit, and it never undercounts.
 *
 * If the table is missing or a query fails (a half-finished upgrade, a restored backup),
 * the counter does not fail open: it raises the FAILED_OPTION flag, which the admin notice
 * shows, and counts in transients (not atomic, but no worse than 1.1.3).
 *
 * The table is per site (it uses $wpdb->prefix), like the login counters it
 * replaces. It holds one row per active subject and is purged daily.
 */
final class TableCounter implements AtomicCounterInterface {

	/** Table name without the prefix. */
	public const TABLE = 'bouncer_counters';

	/** Option set when a query on the table failed; the admin notice reads it. */
	public const FAILED_OPTION = 'wp_bouncer_counter_failed';

	/**
	 * Clock for tests; defaults to time().
	 *
	 * @var callable|null
	 */
	private $now;

	/**
	 * Set up the counter.
	 *
	 * @param callable|null $now Returns the current Unix time.
	 */
	public function __construct( ?callable $now = null ) {
		$this->now = $now;
	}

	/** Transient name prefix of the fallback counters. */
	private const FALLBACK_PREFIX = 'wpb_ctrfb_';

	/**
	 * Set once a query failed in this request, so the rest of the request uses the fallback.
	 *
	 * @var bool
	 */
	private bool $failed = false;

	/** Current Unix time. */
	private function now(): int {
		return null === $this->now ? time() : (int) ( $this->now )();
	}

	/** Full table name. */
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	/**
	 * Key as stored: a fixed-width digest.
	 *
	 * @param string $key Logical key.
	 */
	private static function hash( string $key ): string {
		return md5( $key );
	}

	/**
	 * Count one more event inside a fixed window.
	 *
	 * @param string $key Logical key.
	 * @param int    $ttl Window length in seconds.
	 * @return int The counter after the increment.
	 */
	public function add_or_increment( string $key, int $ttl ): int {
		global $wpdb;
		$table = self::table();
		$hash  = self::hash( $key );
		$now   = $this->now();
		$end   = $now + max( 1, $ttl );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- the counter must see other requests' writes at once, so it can't be cached.
		// Every statement is checked: if any fails (missing table, SQLITE_BUSY in a burst) the whole
		// operation moves to the transient fallback. A failed read never answers "1".
		// 1. Make sure the row exists.
		$ok = $wpdb->query( $wpdb->prepare( 'INSERT IGNORE INTO %i (counter_key, hits, expires_at) VALUES (%s, 0, %d)', $table, $hash, $end ) );
		// 2. Start a new window if the old one has ended.
		$ok = false === $ok ? false : $wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = 0, expires_at = %d WHERE counter_key = %s AND expires_at <= %d', $table, $end, $hash, $now ) );
		// 3. Count, atomically for the row.
		$ok   = false === $ok ? false : $wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits + 1 WHERE counter_key = %s', $table, $hash ) );
		$hits = false === $ok ? null : $wpdb->get_var( $wpdb->prepare( 'SELECT hits FROM %i WHERE counter_key = %s', $table, $hash ) );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		if ( null === $hits || ! is_numeric( $hits ) || '' !== $wpdb->last_error ) {
			return $this->fallback_increment( $hash, $ttl );
		}
		return max( 1, (int) $hits );
	}

	/**
	 * Give one count back (never below zero).
	 *
	 * @param string $key Logical key.
	 */
	public function decrement( string $key ): void {
		global $wpdb;
		if ( $this->failed ) {
			$this->fallback_decrement( self::hash( $key ) );
			return;
		}
		if ( false === $wpdb->query( $wpdb->prepare( 'UPDATE %i SET hits = hits - 1 WHERE counter_key = %s AND hits > 0', self::table(), self::hash( $key ) ) ) ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- see add_or_increment().
			$this->failed = true;
			$this->fallback_decrement( self::hash( $key ) );
		}
	}

	/**
	 * Current value inside the window, 0 when missing or expired.
	 *
	 * @param string $key Logical key.
	 */
	public function get( string $key ): int {
		global $wpdb;
		if ( $this->failed ) {
			return $this->fallback_get( self::hash( $key ) );
		}
		$hits = $wpdb->get_var( $wpdb->prepare( 'SELECT hits FROM %i WHERE counter_key = %s AND expires_at > %d', self::table(), self::hash( $key ), $this->now() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- see add_or_increment().
		if ( null === $hits && '' !== $wpdb->last_error ) {
			$this->failed = true;
			return $this->fallback_get( self::hash( $key ) );
		}
		return max( 0, (int) $hits );
	}

	/**
	 * Forget a counter.
	 *
	 * @param string $key Logical key.
	 */
	public function delete( string $key ): void {
		global $wpdb;
		if ( $this->failed ) {
			delete_transient( self::FALLBACK_PREFIX . self::hash( $key ) );
			return;
		}
		if ( false === $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE counter_key = %s', self::table(), self::hash( $key ) ) ) ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- see add_or_increment().
			$this->failed = true;
			delete_transient( self::FALLBACK_PREFIX . self::hash( $key ) );
		}
	}

	/**
	 * Delete rows whose window has ended (daily cron).
	 *
	 * @return int Rows deleted.
	 */
	public function purge_expired(): int {
		global $wpdb;
		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE expires_at < %d', self::table(), $this->now() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- see add_or_increment().
	}

	/**
	 * Note the failure and count in a transient instead (not atomic).
	 *
	 * @param string $hash Hashed key.
	 * @param int    $ttl  Window in seconds.
	 */
	private function fallback_increment( string $hash, int $ttl ): int {
		$this->failed = true;
		if ( false === get_option( self::FAILED_OPTION ) ) {
			add_option( self::FAILED_OPTION, time(), '', false );
		}
		$data = get_transient( self::FALLBACK_PREFIX . $hash );
		$now  = $this->now();
		if ( is_array( $data ) && (int) $data['e'] > $now ) {
			$data['n'] = (int) $data['n'] + 1;
			set_transient( self::FALLBACK_PREFIX . $hash, $data, max( 1, (int) $data['e'] - $now ) );
			return $data['n'];
		}
		set_transient(
			self::FALLBACK_PREFIX . $hash,
			array(
				'n' => 1,
				'e' => $now + max( 1, $ttl ),
			),
			max( 1, $ttl )
		);
		return 1;
	}

	/**
	 * Fallback counterpart of decrement().
	 *
	 * @param string $hash Hashed key.
	 */
	private function fallback_decrement( string $hash ): void {
		$data = get_transient( self::FALLBACK_PREFIX . $hash );
		if ( is_array( $data ) && (int) $data['n'] > 0 ) {
			$data['n'] = (int) $data['n'] - 1;
			set_transient( self::FALLBACK_PREFIX . $hash, $data, max( 1, (int) $data['e'] - $this->now() ) );
		}
	}

	/**
	 * Fallback counterpart of get().
	 *
	 * @param string $hash Hashed key.
	 */
	private function fallback_get( string $hash ): int {
		$data = get_transient( self::FALLBACK_PREFIX . $hash );
		return is_array( $data ) && (int) $data['e'] > $this->now() ? max( 0, (int) $data['n'] ) : 0;
	}
}
