<?php
/**
 * Result of comparing a login with the account's history.
 *
 * @package WPBouncer
 */

namespace WPBouncer\AdminLogins;

defined( 'ABSPATH' ) || exit;

/**
 * Read-only value. Pure PHP.
 */
final class LoginAssessment {

	/**
	 * No history existed (the first recorded login).
	 *
	 * @var bool
	 */
	public readonly bool $first;
	/**
	 * The network range is not in the history.
	 *
	 * @var bool
	 */
	public readonly bool $new_range;
	/**
	 * The country is not among the countries in the history.
	 *
	 * @var bool
	 */
	public readonly bool $new_country;
	/**
	 * The updated history to save.
	 *
	 * @var LocationHistory
	 */
	public readonly LocationHistory $history;

	/**
	 * Set up the LoginAssessment.
	 *
	 * @param bool            $first       No history existed.
	 * @param bool            $new_range   New network range.
	 * @param bool            $new_country New country.
	 * @param LocationHistory $history     Updated history.
	 */
	public function __construct( bool $first, bool $new_range, bool $new_country, LocationHistory $history ) {
		$this->first       = $first;
		$this->new_range   = $new_range;
		$this->new_country = $new_country;
		$this->history     = $history;
	}

	/** A known account logging in from somewhere it has not been in the window. */
	public function is_new_location(): bool {
		return ! $this->first && ( $this->new_range || $this->new_country );
	}
}
