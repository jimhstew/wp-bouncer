<?php
/**
 * A short-lived lock held in one row of the options table.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Storage;

defined( 'ABSPATH' ) || exit;

/**
 * Atomic claim with a time limit, and a release that only works for the owner.
 *
 * The row is created with INSERT IGNORE (core's add_option() is an upsert, so two requests could both
 * win). A row older than the time limit is replaced with a compare-and-swap UPDATE on the exact value
 * that was read, so only one of several racing requests wins. The release is a DELETE conditional on the
 * exact value, so a request whose stale lock was taken over cannot delete the new owner's lock.
 * Plain SQL that MySQL, MariaDB and SQLite all run. The row value is "time|token".
 */
final class OptionLock {

	/** Seconds a lock may be dated ahead of this server's clock before it counts as planted. */
	private const FUTURE_ALLOWANCE = 5;

	/**
	 * Option name.
	 *
	 * @var string
	 */
	private string $name;

	/**
	 * Seconds after which a lock counts as abandoned.
	 *
	 * @var int
	 */
	private int $ttl;

	/**
	 * Set up the lock.
	 *
	 * @param string $name Option name of the lock row.
	 * @param int    $ttl  Seconds a lock is honoured.
	 */
	public function __construct( string $name, int $ttl ) {
		$this->name = $name;
		$this->ttl  = $ttl;
	}

	/**
	 * Try to take the lock. Never waits.
	 *
	 * @return string|null A token to release it with, or null when another request holds it.
	 */
	public function claim(): ?string {
		global $wpdb;
		$token = wp_generate_password( 12, false );
		$value = time() . '|' . $token;
		// Two tries: the second covers a row that vanished between the insert and the read.
		for ( $try = 0; $try < 2; $try++ ) {
			$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO %i (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $wpdb->options, $this->name, $value ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- atomic claim, see the class comment.
			if ( 1 === $inserted ) {
				$this->forget_cache();
				return $token;
			}
			$held = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, $this->name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- read around the object cache on purpose: the claim must see the latest value.
			if ( null === $held ) {
				continue;
			}
			if ( ! self::is_stale( (string) $held, $this->ttl ) ) {
				return null;
			}
			// Stale: its holder is gone. Of the requests that race to replace it, only one UPDATE matches the old value.
			$won = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $wpdb->options, $value, $this->name, (string) $held ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- compare-and-swap, see the class comment.
			$this->forget_cache();
			return 1 === $won ? $token : null;
		}
		return null;
	}

	/**
	 * Is a held value abandoned? It is when it is not "time|token", when its time is more than a few
	 * seconds ahead (a planted row would otherwise block the lock for good), or when it is older than the limit.
	 *
	 * @param string $held Value read from the row.
	 * @param int    $ttl  Seconds a lock is honoured.
	 */
	private static function is_stale( string $held, int $ttl ): bool {
		if ( 1 !== preg_match( '/^(\d{1,12})\|[A-Za-z0-9]+$/', $held, $m ) ) {
			return true;
		}
		$time = (int) $m[1];
		$now  = time();
		return $time > $now + self::FUTURE_ALLOWANCE || $time <= $now - $ttl;
	}

	/**
	 * Release the lock, only if the token still owns it.
	 *
	 * @param string $token Token from claim().
	 */
	public function release( string $token ): void {
		global $wpdb;
		$held = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, $this->name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- must see the latest value.
		if ( null === $held || substr( (string) $held, -strlen( $token ) - 1 ) !== '|' . $token ) {
			return;
		}
		// Conditional on the exact value: if another request took the lock meanwhile, nothing matches.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE option_name = %s AND option_value = %s', $wpdb->options, $this->name, (string) $held ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- conditional delete, see the class comment.
		$this->forget_cache();
	}

	/** Drop cached copies of the lock option so get_option() stays coherent after a direct write. */
	private function forget_cache(): void {
		wp_cache_delete( $this->name, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}
}
