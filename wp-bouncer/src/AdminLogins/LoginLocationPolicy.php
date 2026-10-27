<?php
/**
 * Decides whether a login came from a new location.
 *
 * @package WPBouncer
 */

namespace WPBouncer\AdminLogins;

use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP: no WordPress calls.
 */
final class LoginLocationPolicy {

	/**
	 * Seconds a history entry is kept.
	 *
	 * @var int
	 */
	private int $window;
	/**
	 * Most entries kept.
	 *
	 * @var int
	 */
	private int $max_entries;

	/**
	 * Set up the LoginLocationPolicy.
	 *
	 * @param int $window_seconds Seconds an entry is kept (default 90 days).
	 * @param int $max_entries    Most entries kept.
	 */
	public function __construct( int $window_seconds = 7776000, int $max_entries = 20 ) {
		$this->window      = $window_seconds;
		$this->max_entries = $max_entries;
	}

	/**
	 * Network range of an address: a.b.c.0/24 or the /64 network.
	 *
	 * @param string $ip Client IP.
	 * @return string The range, or '' for an invalid address.
	 */
	public static function range_of( string $ip ): string {
		if ( ! IpUtils::is_valid( $ip ) ) {
			return '';
		}
		$canonical = IpUtils::canonical( $ip );
		$packed    = inet_pton( $canonical );
		if ( false === $packed ) {
			return '';
		}
		if ( 4 === strlen( $packed ) ) {
			return substr( $canonical, 0, (int) strrpos( $canonical, '.' ) ) . '.0/24';
		}
		return inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) ) . '/64';
	}

	/**
	 * Compare a login with the history.
	 *
	 * @param LocationHistory|null $h       History, or null when none was recorded.
	 * @param string               $range   Range of the login.
	 * @param string               $country Country code or ''.
	 * @param int                  $now     Unix time.
	 */
	public function assess( ?LocationHistory $h, string $range, string $country, int $now ): LoginAssessment {
		if ( null === $h ) {
			return new LoginAssessment( true, false, false, LocationHistory::start( $now )->with_login( $range, $country, $now, $this->window, $this->max_entries ) );
		}
		$pruned    = $h->pruned( $now, $this->window );
		$known     = $pruned->known_countries();
		$new_range = '' !== $range && ! $pruned->has_range( $range );
		$new_ctry  = '' !== $country && array() !== $known && ! in_array( $country, $known, true );
		return new LoginAssessment( false, $new_range, $new_ctry, $pruned->with_login( $range, $country, $now, $this->window, $this->max_entries ) );
	}
}
