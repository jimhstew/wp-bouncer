<?php
/**
 * Schema version 3 data migration: redact what older versions stored.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Storage;

use WPBouncer\Support\UrlRedactor;

defined( 'ABSPATH' ) || exit;

/**
 * Redacts rows written before 1.1.3 (S4 redacts new rows only):
 * - uri in {prefix}bouncer_log,
 * - uri and referrer in {prefix}bouncer_traffic,
 * - the username in lockout reasons ("(last username "x")") when no such account exists.
 *
 * Safe on large tables:
 * - Batched by primary key (keyset, "id > last ORDER BY id LIMIT n"), so each query is an
 *   index range and the cost doesn't grow with the position.
 * - Time-boxed: run() returns when its budget is spent, and the next call continues from the
 *   saved cursor. Plugin runs a slice at upgrade and the rest from a one-minute cron event.
 * - Resumable: the cursors live in an option, written after every batch.
 * - Idempotent: only rows whose redacted value differs are updated, and redacting twice
 *   gives the same text, so a repeated or overlapping run changes nothing.
 * - Rows written while it runs are already redacted, so the cursor passing them is harmless.
 */
final class RedactionMigration {

	/** Option holding the cursors. Absent once the migration has finished. */
	public const STATE_OPTION = 'wp_bouncer_migration_3';

	/** Option used as a short lock between overlapping runs. */
	public const LOCK_OPTION = 'wp_bouncer_migration_3_lock';

	/** Cron hook that continues an unfinished migration. */
	public const HOOK = 'wp_bouncer_migrate_data';

	/** Rows read per batch. */
	public const BATCH = 500;

	/** Seconds after which a lock is considered abandoned. */
	private const LOCK_SECONDS = 120;

	/** The three jobs, in order. */
	private const JOBS = array( 'log', 'traffic', 'reasons' );

	/** Reason text that keeps no username (matches LoginGuard::failure_reason()). */
	private const UNKNOWN = '(last: unknown username)';

	/**
	 * Returns the account's canonical user_login for a typed name, or null.
	 *
	 * @var callable
	 */
	private $user_exists;

	/**
	 * Set up the migration.
	 *
	 * @param callable $user_exists Takes a name, returns the user_login of that account or null.
	 */
	public function __construct( callable $user_exists ) {
		$this->user_exists = $user_exists;
	}

	/** Start (or keep) a migration: the cursors begin at zero. */
	public static function begin(): void {
		if ( false === get_option( self::STATE_OPTION ) ) {
			add_option( self::STATE_OPTION, array_fill_keys( self::JOBS, 0 ), '', false );
		}
	}

	/** Is there unfinished work? */
	public static function pending(): bool {
		return false !== get_option( self::STATE_OPTION );
	}

	/**
	 * Schedule the cron continuation if work is pending and nothing is scheduled.
	 */
	public static function schedule(): void {
		if ( self::pending() && ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::HOOK );
		}
	}

	/**
	 * Work for up to $seconds, then stop. Saves progress after every batch.
	 *
	 * @param float $seconds Time budget; at least one batch always runs.
	 * @return bool True when everything is done.
	 */
	public function run( float $seconds ): bool {
		$state = get_option( self::STATE_OPTION );
		if ( ! is_array( $state ) ) {
			return true;
		}
		if ( ! $this->claim() ) {
			return false;
		}
		$deadline = microtime( true ) + $seconds;

		foreach ( self::JOBS as $job ) {
			$last = (int) ( $state[ $job ] ?? 0 );
			if ( $last < 0 ) {
				continue;
			}
			do {
				$last = $this->batch( $job, $last );
				// A negative cursor marks the job as finished.
				$state[ $job ] = $last;
				update_option( self::STATE_OPTION, $state, false );
				if ( $last >= 0 && microtime( true ) >= $deadline ) {
					$this->release();
					return false;
				}
			} while ( $last >= 0 );
		}

		delete_option( self::STATE_OPTION );
		$this->release();
		wp_clear_scheduled_hook( self::HOOK );
		return true;
	}

	/**
	 * Cron callback: a longer slice than the upgrade request gets.
	 *
	 * @param callable $user_exists Account lookup, see the constructor.
	 */
	public static function cron( callable $user_exists ): void {
		$migration = new self( $user_exists );
		if ( ! $migration->run( 20.0 ) ) {
			self::schedule();
		}
	}

	/**
	 * One batch of one job.
	 *
	 * @param string $job  log | traffic | reasons.
	 * @param int    $last Highest id handled so far.
	 * @return int The new cursor, or -1 when the job has no more rows.
	 */
	private function batch( string $job, int $last ): int {
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- one-off migration of the plugin's own tables; nothing to cache.
		switch ( $job ) {
			case 'log':
				$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, uri FROM %i WHERE id > %d ORDER BY id ASC LIMIT %d', $wpdb->prefix . 'bouncer_log', $last, self::BATCH ), ARRAY_A );
				$cols = array( 'uri' );
				$tbl  = $wpdb->prefix . 'bouncer_log';
				break;
			case 'traffic':
				$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, uri, referrer FROM %i WHERE id > %d ORDER BY id ASC LIMIT %d', $wpdb->prefix . 'bouncer_traffic', $last, self::BATCH ), ARRAY_A );
				$cols = array( 'uri', 'referrer' );
				$tbl  = $wpdb->prefix . 'bouncer_traffic';
				break;
			default:
				$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, reason FROM %i WHERE rule = %s AND id > %d AND reason LIKE %s ORDER BY id ASC LIMIT %d', $wpdb->prefix . 'bouncer_log', 'login_lockout', $last, '%' . $wpdb->esc_like( '(last username "' ) . '%', self::BATCH ), ARRAY_A );
				$cols = array( 'reason' );
				$tbl  = $wpdb->prefix . 'bouncer_log';
		}
		if ( ! is_array( $rows ) || array() === $rows ) {
			return -1;
		}

		$names = array();
		foreach ( $rows as $row ) {
			$changes = array();
			foreach ( $cols as $col ) {
				$old = (string) $row[ $col ];
				$new = 'reason' === $col ? $this->redact_reason( $old, $names ) : UrlRedactor::redact( $old );
				if ( $new !== $old ) {
					$changes[ $col ] = $new;
				}
			}
			if ( array() !== $changes ) {
				$wpdb->update( $tbl, $changes, array( 'id' => (int) $row['id'] ) );
			}
			$last = (int) $row['id'];
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		return count( $rows ) < self::BATCH ? -1 : $last;
	}

	/**
	 * Drop the username from a lockout reason when no such account exists.
	 *
	 * @param string              $reason Stored reason.
	 * @param array<string, bool> $names  Lookup cache for this batch (name => exists).
	 */
	private function redact_reason( string $reason, array &$names ): string {
		// The name runs up to the known suffix; if the 255-char column cut the reason short, up to its end,
		// so no part of a typed password is left behind. Byte-wise (no /u): stored text may not be valid UTF-8.
		if ( 1 !== preg_match( '/\(last username "(.*?)(?:"\)(?= \xe2\x80\x93 locked out for \d+ min\z)|\z)/s', $reason, $m ) ) {
			return $reason;
		}
		$name = $m[1];
		if ( ! isset( $names[ $name ] ) ) {
			$login          = ( $this->user_exists )( $name );
			$names[ $name ] = is_string( $login ) && '' !== $login;
		}
		return $names[ $name ] ? $reason : str_replace( $m[0], self::UNKNOWN, $reason );
	}

	/** Take the short lock. False when another run holds it. */
	private function claim(): bool {
		$now = time();
		if ( add_option( self::LOCK_OPTION, $now, '', false ) ) {
			return true;
		}
		if ( $now - (int) get_option( self::LOCK_OPTION, 0 ) > self::LOCK_SECONDS ) {
			update_option( self::LOCK_OPTION, $now, false );
			return true;
		}
		return false;
	}

	/** Drop the lock. */
	private function release(): void {
		delete_option( self::LOCK_OPTION );
	}
}
