<?php
/**
 * Refuses locked-out IPs at the login door.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Login\LoginGuard;

defined( 'ABSPATH' ) || exit;

/**
 * Turns away locked-out IPs from wp-login.php and xmlrpc.php before WordPress
 * does any authentication work. The counting is done by LoginGuard.
 *
 * Settings: see LoginGuard. This rule only reads "enabled".
 */
final class LoginLockoutRule extends AbstractRule {

	public const ID = LoginGuard::RULE_ID;

	/**
	 * Login failure tracker.
	 *
	 * @var LoginGuard
	 */
	private LoginGuard $guard;

	/**
	 * Set up the LoginLockoutRule.
	 *
	 * @param array<string, mixed> $settings Login lockout settings.
	 * @param LoginGuard           $guard    Failure tracker.
	 */
	public function __construct( array $settings, LoginGuard $guard ) {
		parent::__construct( $settings );
		$this->guard = $guard;
	}

	/** {@inheritDoc} */
	public function id(): string {
		return self::ID;
	}

	/**
	 * Inspect the request.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function inspect( Request $request ): ?Verdict {
		if ( ! ( $request->is_login() || $request->is_xmlrpc() ) ) {
			return null;
		}
		// Viewing the login page is harmless. Only refuse attempts to submit credentials.
		if ( $request->is_login() && 'POST' !== $request->method() ) {
			return null;
		}

		// No lockout is ever kept for loopback, proxy or shared (fallback) addresses.
		if ( ! $request->can_be_banned() ) {
			return null;
		}

		$remaining = $this->guard->lockout_remaining( $request->key_ip() );
		if ( $remaining > 0 ) {
			return $this->deny( 'IP is locked out after failed logins', 403, $remaining );
		}
		return null;
	}
}
