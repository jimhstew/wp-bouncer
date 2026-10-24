<?php
/**
 * Tracks failed logins per IP and places temporary lockouts.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Login;

use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Brute-force protection state machine.
 *
 * Settings (settings['rules']['login_lockout']):
 * - enabled (bool)
 * - max_attempts (int): failures allowed inside the window.
 * - window_minutes (int): how long failures are remembered.
 * - lockout_minutes (int): how long a locked-out IP stays locked out.
 * - banned_usernames (string[]): trying any of these locks the IP out at once.
 * - generic_errors (bool): hide whether the username or the password was wrong.
 *
 * Plugin.php connects this class to WordPress (wp_login_failed and
 * authenticate). LoginLockoutRule uses it to refuse locked-out IPs at the door.
 */
final class LoginGuard {

	public const RULE_ID = 'login_lockout';

	/**
	 * Settings for this component.
	 *
	 * @var array<string, mixed>
	 */
	private array $settings;
	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface
	 */
	private CounterStoreInterface $store;
	/**
	 * Block log.
	 *
	 * @var BlockLogInterface
	 */
	private BlockLogInterface $log;
	/**
	 * Time source.
	 *
	 * @var Clock
	 */
	private Clock $clock;

	/**
	 * Set up the LoginGuard.
	 *
	 * @param array<string, mixed>  $settings Login lockout settings.
	 * @param CounterStoreInterface $store    Where counters and lockouts live.
	 * @param BlockLogInterface     $log      Where lockout events are recorded.
	 * @param Clock|null            $clock    Time source.
	 */
	public function __construct( array $settings, CounterStoreInterface $store, BlockLogInterface $log, ?Clock $clock = null ) {
		$this->settings = $settings;
		$this->store    = $store;
		$this->log      = $log;
		$this->clock    = $clock ?? new Clock();
	}

	/** Is brute-force protection switched on? */
	public function is_enabled(): bool {
		return ! empty( $this->settings['enabled'] );
	}

	/**
	 * Is the IP currently locked out?
	 *
	 * @param string $ip Client IP.
	 */
	public function is_locked_out( string $ip ): bool {
		return $this->lockout_remaining( $ip ) > 0;
	}

	/**
	 * Seconds left on the IP's lockout (0 if not locked out).
	 *
	 * @param string $ip Client IP.
	 */
	public function lockout_remaining( string $ip ): int {
		$until = $this->store->get( self::lockout_key( $ip ) );
		return null === $until ? 0 : max( 0, (int) $until - $this->clock->now() );
	}

	/**
	 * Record a failed login. Locks the IP out once the limit is reached.
	 *
	 * @param string               $ip       Client IP.
	 * @param string               $username Username that was tried.
	 * @param array<string,string> $context  Extra log fields (method, uri, user_agent, country).
	 * @return bool True if this failure caused a lockout.
	 */
	public function record_failure( string $ip, string $username, array $context = array() ): bool {
		if ( ! $this->is_enabled() || '' === $ip || $this->is_locked_out( $ip ) ) {
			return false;
		}

		if ( $this->is_banned_username( $username ) ) {
			$this->lock( $ip, sprintf( 'Tried banned username "%s"', $username ), $context );
			return true;
		}

		$window   = max( 1, (int) ( $this->settings['window_minutes'] ?? 15 ) ) * 60;
		$failures = $this->store->increment( self::failures_key( $ip ), $window );
		$max      = max( 1, (int) ( $this->settings['max_attempts'] ?? 5 ) );

		if ( $failures >= $max ) {
			$this->lock( $ip, sprintf( '%d failed logins (last username "%s")', $failures, $username ), $context );
			return true;
		}
		return false;
	}

	/**
	 * Lift a lockout and forget failures (used by the admin "unlock IP" tool).
	 *
	 * @param string $ip Client IP.
	 */
	public function clear( string $ip ): void {
		$this->store->delete( self::lockout_key( $ip ) );
		$this->store->delete( self::failures_key( $ip ) );
	}

	/**
	 * Is the username on the instant-lockout list? Case-insensitive.
	 *
	 * @param string $username Username.
	 */
	public function is_banned_username( string $username ): bool {
		$username = strtolower( trim( $username ) );
		if ( '' === $username ) {
			return false;
		}
		$banned = array_map( 'strtolower', (array) ( $this->settings['banned_usernames'] ?? array() ) );
		return in_array( $username, $banned, true );
	}

	/** Should login error messages be made generic? */
	public function wants_generic_errors(): bool {
		return $this->is_enabled() && ! empty( $this->settings['generic_errors'] );
	}

	/**
	 * Place a lockout and log it.
	 *
	 * @param string               $ip      Client IP.
	 * @param string               $reason  Log reason.
	 * @param array<string,string> $context Extra log fields.
	 */
	private function lock( string $ip, string $reason, array $context ): void {
		$duration = max( 1, (int) ( $this->settings['lockout_minutes'] ?? 60 ) ) * 60;
		$this->store->set( self::lockout_key( $ip ), $this->clock->now() + $duration, $duration );
		$this->store->delete( self::failures_key( $ip ) );

		$this->log->record(
			array_merge(
				array(
					'method'     => '',
					'uri'        => '',
					'user_agent' => '',
					'country'    => '',
				),
				$context,
				array(
					'ip'     => (string) ( $context['ip'] ?? $ip ),
					'rule'   => self::RULE_ID,
					'action' => BlockLogInterface::ACTION_LOCKOUT,
					'reason' => $reason . sprintf( ' – locked out for %d min', $duration / 60 ),
				)
			)
		);
	}

	/**
	 * Store key for an IP's lockout.
	 *
	 * @param string $ip Client IP.
	 */
	public static function lockout_key( string $ip ): string {
		return 'login_lock:' . $ip;
	}

	/**
	 * Store key for an IP's failure counter.
	 *
	 * @param string $ip Client IP.
	 */
	public static function failures_key( string $ip ): string {
		return 'login_fail:' . $ip;
	}
}
