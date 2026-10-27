<?php
/**
 * Stores each administrator's location history in per-site user options.
 *
 * @package WPBouncer
 */

namespace WPBouncer\AdminLogins;

defined( 'ABSPATH' ) || exit;

/**
 * Storage adapter. The stored key is "{blog prefix}wpb_login_seen", so the
 * history is per site, like the Activity Log rows.
 */
final class LoginHistoryRepository {

	public const META = 'wpb_login_seen';

	/** Autoload-off option holding the umeta_id the next prune run continues after. */
	public const CURSOR_OPTION = 'wp_bouncer_login_prune_cursor';

	/** Batches per prune run. */
	private const MAX_BATCHES = 5;

	/**
	 * A user's history.
	 *
	 * @param int $user_id User ID.
	 * @return LocationHistory|null Null when none was recorded or the data is unreadable.
	 */
	public function load( int $user_id ): ?LocationHistory {
		return LocationHistory::from_meta( get_user_option( self::META, $user_id ) );
	}

	/**
	 * Save a user's history.
	 *
	 * @param int             $user_id User ID.
	 * @param LocationHistory $history History.
	 */
	public function save( int $user_id, LocationHistory $history ): void {
		update_user_option( $user_id, self::META, $history->to_meta() );
	}

	/**
	 * Delete a user's history.
	 *
	 * @param int $user_id User ID.
	 */
	public function delete( int $user_id ): void {
		delete_user_option( $user_id, self::META );
	}

	/**
	 * Delete a user's history on one site (the user left that site).
	 *
	 * @param int $user_id User ID.
	 * @param int $blog_id Site ID.
	 */
	public function delete_for_blog( int $user_id, int $blog_id ): void {
		global $wpdb;
		delete_user_meta( $user_id, $wpdb->get_blog_prefix( $blog_id ) . self::META );
	}

	/**
	 * Replace a user's history on one site with a tombstone, if they had one (the user left that site
	 * or was deleted from it, and may be added back).
	 *
	 * @param int $user_id User ID.
	 * @param int $blog_id Site ID.
	 * @param int $now     Unix time.
	 */
	public function tombstone_for_blog( int $user_id, int $blog_id, int $now ): void {
		global $wpdb;
		$key = $wpdb->get_blog_prefix( $blog_id ) . self::META;
		if ( null !== LocationHistory::from_meta( get_user_meta( $user_id, $key, true ) ) ) {
			update_user_meta( $user_id, $key, LocationHistory::start( $now )->to_meta() );
		}
	}

	/**
	 * Replace a user's history with an empty one that starts now (a tombstone).
	 *
	 * Unlike delete(), the account is not "never recorded" afterwards: the next login
	 * from any range is a new location and alerts. Used by the privacy eraser.
	 *
	 * @param int $user_id User ID.
	 * @param int $now     Unix time.
	 */
	public function reset( int $user_id, int $now ): void {
		$this->save( $user_id, LocationHistory::start( $now ) );
	}

	/**
	 * Drop expired entries from stored histories, a few hundred users at a time.
	 *
	 * Continues from a persisted cursor, so a site with many administrators is
	 * covered over several runs. Only tidiness: every login also prunes its own
	 * user and an expired entry never matches.
	 *
	 * @param int $window Seconds an entry is kept.
	 * @param int $batch  Users per query.
	 */
	public function prune_expired( int $window, int $batch = 200 ): void {
		global $wpdb;
		$batch  = max( 1, $batch );
		$key    = $wpdb->get_blog_prefix() . self::META;
		$cursor = max( 0, (int) get_option( self::CURSOR_OPTION, 0 ) );
		$now    = time();

		for ( $i = 0; $i < self::MAX_BATCHES; $i++ ) {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- cursor-paged maintenance scan.
				$wpdb->prepare( 'SELECT umeta_id, user_id FROM %i WHERE meta_key = %s AND umeta_id > %d ORDER BY umeta_id LIMIT %d', $wpdb->usermeta, $key, $cursor, $batch ),
				ARRAY_A
			);
			$rows = is_array( $rows ) ? $rows : array();
			foreach ( $rows as $row ) {
				$cursor  = (int) $row['umeta_id'];
				$user_id = (int) $row['user_id'];
				$history = $this->load( $user_id );
				if ( null === $history ) {
					continue;
				}
				$pruned = $history->pruned( $now, $window );
				if ( count( $pruned->entries() ) !== count( $history->entries() ) ) {
					$this->save( $user_id, $pruned );
				}
			}
			if ( count( $rows ) < $batch ) {
				$cursor = 0;
				break;
			}
		}
		update_option( self::CURSOR_OPTION, $cursor, false );
	}
}
