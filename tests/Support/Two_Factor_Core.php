<?php
/**
 * Stand-in for the Two Factor plugin's core class (global namespace, like the real one).
 *
 * Only what WP Bouncer asks. Load it with require_once from the test that needs it;
 * by default no user is "using two factor", so other tests are unaffected.
 *
 * @package WPBouncer\Tests
 */

// phpcs:disable

class Two_Factor_Core {

	/** @var int[] IDs of users that use two-factor. */
	public static array $users = array();

	/** The real one runs at wp_login priority 10 and exits; tests hook this where they need it. */
	public static function wp_login( $user_login = '', $user = null ) {
	}

	public static function is_user_using_two_factor( $user_id = null ) {
		return in_array( (int) $user_id, self::$users, true );
	}
}
