<?php
/**
 * Where the settings fingerprint lives: three options and one transient.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

use WPBouncer\Storage\OptionLock;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress repository. None of the options is autoloaded: every add and update passes false
 * explicitly, because an omitted argument becomes "auto" on WordPress 6.6 and later.
 */
final class FingerprintStore {

	/** The sealed record (a JSON string). */
	public const RECORD_OPTION = 'wp_bouncer_fp';

	/** Time of the first baseline. */
	public const MARKER_OPTION = 'wp_bouncer_fp_since';

	/** Lock row. */
	public const LOCK_OPTION = 'wp_bouncer_fp_lock';

	/** Throttle transient of the admin check. */
	public const THROTTLE_TRANSIENT = 'wp_bouncer_fp_check';

	/** Seconds a lock is honoured if its holder never released it. */
	public const LOCK_SECONDS = 60;

	/**
	 * Token of the lock this request holds.
	 *
	 * @var string|null
	 */
	private ?string $token = null;

	/**
	 * The raw stored record as text. Never read through get_option(), which would unserialize
	 * whatever a database writer planted in the row.
	 *
	 * @return string|false A string, or false when missing.
	 */
	public function load(): string|false {
		return $this->load_fresh();
	}

	/**
	 * The record as the database holds it now, around every cache.
	 *
	 * @return string|false The stored text, or false when the row is missing.
	 */
	public function load_fresh(): string|false {
		global $wpdb;
		$value = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, self::RECORD_OPTION ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- read around the object cache on purpose: it must show what a racing request has written.
		return null === $value ? false : (string) $value;
	}

	/**
	 * Store a record.
	 *
	 * @param FingerprintRecord $record Record.
	 * @return bool True when the stored text is now the record.
	 */
	public function save( FingerprintRecord $record ): bool {
		$json = $record->to_json();
		$this->scrub( self::RECORD_OPTION, '{' );
		// update_option() compares with the cached old value and skips the write when they are equal.
		wp_cache_delete( self::RECORD_OPTION, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
		update_option( self::RECORD_OPTION, $json, false );
		return $this->load_fresh() === $json;
	}

	/**
	 * Time of the first baseline.
	 *
	 * @return int|null Null when none was ever set.
	 */
	public function marker(): ?int {
		global $wpdb;
		$value = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, self::MARKER_OPTION ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- raw text on purpose, see load().
		return is_string( $value ) && 1 === preg_match( '/^\d{1,12}$/', $value ) ? (int) $value : null;
	}

	/**
	 * Remember that a baseline was set.
	 *
	 * @param int $time Time of the baseline.
	 */
	public function set_marker( int $time ): void {
		$this->scrub( self::MARKER_OPTION, '' );
		wp_cache_delete( self::MARKER_OPTION, 'options' );
		update_option( self::MARKER_OPTION, $time, false );
	}

	/**
	 * Delete a row whose text is not what this class writes, so update_option() never reads (and
	 * unserializes) a planted value as the "old" one.
	 *
	 * @param string $name   Option name.
	 * @param string $prefix First character a good value starts with ('' = digits).
	 */
	private function scrub( string $name, string $prefix ): void {
		global $wpdb;
		$value = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, $name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- raw text on purpose, see load().
		if ( null === $value ) {
			return;
		}
		$good = '' === $prefix ? 1 === preg_match( '/^\d{1,12}$/', (string) $value ) : 0 === strpos( (string) $value, $prefix );
		if ( ! $good ) {
			delete_option( $name );
			wp_cache_delete( $name, 'options' );
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( 'notoptions', 'options' );
		}
	}

	/**
	 * Try to take the lock. Never waits.
	 *
	 * @return bool True when this request now holds it.
	 */
	public function claim_lock(): bool {
		if ( null !== $this->token ) {
			return false;
		}
		$this->token = $this->lock()->claim();
		return null !== $this->token;
	}

	/** Release the lock if this request holds it. */
	public function release_lock(): void {
		if ( null !== $this->token ) {
			$this->lock()->release( $this->token );
			$this->token = null;
		}
	}

	/**
	 * Is the admin check due? The transient holds the time it was set; a value that is not a time, lies
	 * ahead or is older than an hour counts as open, whatever timeout the row has (a planted row with a
	 * far-off timeout would otherwise switch the check off).
	 */
	public function throttle_open(): bool {
		$set = get_transient( self::THROTTLE_TRANSIENT );
		$now = time();
		// A scalar read back from the database is text, from the object cache an int.
		$set = is_string( $set ) && ctype_digit( $set ) ? (int) $set : $set;
		return ! is_int( $set ) || $set > $now || $set < $now - HOUR_IN_SECONDS;
	}

	/** Close the admin check for an hour. */
	public function close_throttle(): void {
		set_transient( self::THROTTLE_TRANSIENT, time(), HOUR_IN_SECONDS );
	}

	/** The lock. */
	private function lock(): OptionLock {
		return new OptionLock( self::LOCK_OPTION, self::LOCK_SECONDS );
	}
}
