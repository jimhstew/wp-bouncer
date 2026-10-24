<?php
/**
 * Tracks failed logins per IP and places temporary lockouts.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Login;

use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Storage\AtomicCounterInterface;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\Clock;
use WPBouncer\Support\CounterSubject;

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
 * Counting and lockouts are keyed by CounterSubject (IPv4 address, or the IPv6 /64).
 * With an AtomicCounterInterface, an attempt is reserved before the password is checked
 * (reserve()), so parallel guesses can't all pass the check (RT-08). Without one, failures
 * are counted after the fact in the CounterStoreInterface, as in 1.1.3.
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
	 * Tells whether a username belongs to a real account. Null means unknown.
	 *
	 * @var callable|null
	 */
	private $user_exists;
	/**
	 * Atomic attempt counter. Null means failures are counted in the store.
	 *
	 * @var AtomicCounterInterface|null
	 */
	private ?AtomicCounterInterface $counter;
	/**
	 * Attempt number reserved by this request (0 = none).
	 *
	 * @var int
	 */
	private int $reserved = 0;
	/**
	 * Attempt number in the surrounding IPv6 /48 reserved by this request (0 = none).
	 *
	 * @var int
	 */
	private int $reserved_wide = 0;

	/**
	 * Set up the LoginGuard.
	 *
	 * @param array<string, mixed>        $settings Login lockout settings.
	 * @param CounterStoreInterface       $store    Where counters and lockouts live.
	 * @param BlockLogInterface           $log      Where lockout events are recorded.
	 * @param Clock|null                  $clock    Time source.
	 * @param callable|null               $user_exists Takes a typed name and returns the account's canonical user_login, or null if there is no such account. Null callable means unknown.
	 * @param AtomicCounterInterface|null $counter Atomic attempt counter; null to count failures in $store.
	 */
	public function __construct( array $settings, CounterStoreInterface $store, BlockLogInterface $log, ?Clock $clock = null, ?callable $user_exists = null, ?AtomicCounterInterface $counter = null ) {
		$this->settings    = $settings;
		$this->store       = $store;
		$this->log         = $log;
		$this->clock       = $clock ?? new Clock();
		$this->user_exists = $user_exists;
		$this->counter     = $counter;
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
	 * Failed logins currently counted for the IP.
	 *
	 * @param string $ip Client IP.
	 */
	public function failures( string $ip ): int {
		if ( null !== $this->counter ) {
			return $this->counter->get( self::attempts_key( $ip ) );
		}
		return (int) $this->store->get( self::failures_key( $ip ) );
	}

	/**
	 * Attempts allowed from one IPv6 /48 inside the window (the /64 limit times a multiplier).
	 * Setting: wide_multiplier (default 8; Plugin passes the wp_bouncer_ipv6_wide_multiplier filter).
	 */
	public function wide_limit(): int {
		return $this->max_attempts() * max( 1, (int) ( $this->settings['wide_multiplier'] ?? 8 ) );
	}

	/** Does this request hold a reserved attempt? */
	public function has_reservation(): bool {
		return $this->reserved > 0;
	}

	/** Window in seconds that failures are remembered for. */
	private function window(): int {
		return max( 1, (int) ( $this->settings['window_minutes'] ?? 15 ) ) * 60;
	}

	/**
	 * Reserve one login attempt before the password is checked.
	 *
	 * Call at the start of authentication, then settle with release() (the login
	 * succeeded) or record_failure() (it didn't). Does nothing without an atomic
	 * counter, or for an address that isn't counted (loopback).
	 *
	 * @param string $ip Client IP.
	 * @return int The attempt number (1 = first in the window), 0 when nothing was reserved.
	 */
	public function reserve( string $ip ): int {
		$this->reserved      = 0;
		$this->reserved_wide = 0;
		// A client that is already locked out is refused anyway: counting it would only inflate the /48.
		if ( null === $this->counter || ! $this->is_enabled() || '' === CounterSubject::of( $ip ) || $this->is_locked_out( $ip ) ) {
			return 0;
		}
		$this->reserved = $this->counter->add_or_increment( self::attempts_key( $ip ), $this->window() );
		if ( null !== self::wide_key( $ip ) ) {
			// A second, coarser count for the whole /48. When it is over its limit, /64s that are
			// already failing get a tighter limit (limit_for()). It never refuses a /64 by itself.
			$this->reserved_wide = $this->counter->add_or_increment( (string) self::wide_key( $ip ), $this->window() );
		}
		return $this->reserved;
	}

	/**
	 * Give back this request's reservation (the login succeeded).
	 *
	 * @param string $ip Client IP.
	 */
	public function release( string $ip ): void {
		if ( null !== $this->counter && $this->reserved > 0 ) {
			$this->counter->decrement( self::attempts_key( $ip ) );
			if ( $this->reserved_wide > 0 ) {
				$this->counter->decrement( (string) self::wide_key( $ip ) );
			}
		}
		$this->reserved      = 0;
		$this->reserved_wide = 0;
	}

	/**
	 * Seconds to refuse this authentication for, 0 to let it proceed.
	 *
	 * Refuses during a lockout, and when this request's reserved attempt is past
	 * the maximum, whatever the password check said (so extra guesses learn nothing).
	 * Without a reservation it refuses once the stored failures are at the maximum.
	 *
	 * @param string $ip Client IP.
	 */
	public function refusal_seconds( string $ip ): int {
		$remaining = $this->lockout_remaining( $ip );
		if ( $remaining > 0 ) {
			return $remaining;
		}
		$over = $this->reserved > 0 ? $this->reserved > $this->limit_for( $this->reserved_wide ) : $this->failures( $ip ) >= $this->max_attempts();
		return $over ? 60 : 0;
	}

	/**
	 * Attempts one /64 may use in the window.
	 *
	 * Normally max_attempts. While its surrounding /48 is over wide_limit() the limit drops to 2
	 * (never above max_attempts), so a /64 that already has a failure is locked at its second.
	 * A /64 with no failures of its own still passes its first attempts, so innocent neighbours in
	 * a shared /48 (carrier, ISP, VPS block) are never locked just because someone else floods it.
	 *
	 * @param int $wide Attempts counted in the /48 including this one (0 = none).
	 */
	private function limit_for( int $wide ): int {
		$max = $this->max_attempts();
		return $wide > $this->wide_limit() ? min( $max, 2 ) : $max;
	}

	/** Failures allowed inside the window. */
	public function max_attempts(): int {
		return max( 1, (int) ( $this->settings['max_attempts'] ?? 5 ) );
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
		$reserved            = $this->reserved;
		$reserved_wide       = $this->reserved_wide;
		$this->reserved      = 0;
		$this->reserved_wide = 0;
		if ( ! $this->is_enabled() || '' === CounterSubject::of( $ip ) || $this->is_locked_out( $ip ) ) {
			return false;
		}

		if ( $this->is_banned_username( $username ) ) {
			$this->lock( $ip, sprintf( 'Tried banned username "%s"', $username ), $context );
			return true;
		}

		if ( null !== $this->counter ) {
			// The attempt was counted when it was reserved; count it now only if it wasn't.
			if ( 0 === $reserved ) {
				$reserved            = $this->reserve( $ip );
				$reserved_wide       = $this->reserved_wide;
				$this->reserved      = 0;
				$this->reserved_wide = 0;
			}
			$failures = $reserved;
		} else {
			$failures = $this->store->increment( self::failures_key( $ip ), $this->window() );
		}

		if ( $failures >= $this->limit_for( $reserved_wide ) ) {
			$this->lock( $ip, $this->failure_reason( $failures, $username ), $context );
			return true;
		}
		return false;
	}

	/**
	 * Log reason for a lockout caused by repeated failures. The username is
	 * kept only for an existing account, because a mistyped one is often a
	 * password or an email address.
	 *
	 * @param int    $failures Failures counted.
	 * @param string $username Username that was tried.
	 */
	private function failure_reason( int $failures, string $username ): string {
		$login = $this->known_login( $username );
		if ( null !== $login ) {
			return sprintf( '%d failed logins (last username "%s")', $failures, $login );
		}
		return sprintf( '%d failed logins (last: unknown username)', $failures );
	}

	/**
	 * Canonical login of an existing account, or null.
	 *
	 * @param string $username Typed name.
	 */
	private function known_login( string $username ): ?string {
		$login = '' !== $username && null !== $this->user_exists ? ( $this->user_exists )( $username ) : null;
		return is_string( $login ) && '' !== $login ? $login : null;
	}

	/**
	 * Lift a lockout and forget failures (used by the admin "unlock IP" tool).
	 *
	 * @param string $ip Client IP.
	 */
	public function clear( string $ip ): void {
		$this->forget( $ip );
		// Bans and counts placed before IPv6 subjects existed are keyed by the exact string.
		$typed = trim( $ip );
		$this->store->delete( 'login_lock:' . $typed );
		$this->store->delete( 'login_fail:' . $typed );
	}

	/**
	 * Delete the lockout and the counters under the subject's keys.
	 *
	 * @param string $ip Client IP.
	 */
	private function forget( string $ip ): void {
		$this->store->delete( self::lockout_key( $ip ) );
		$this->store->delete( self::failures_key( $ip ) );
		if ( null !== $this->counter ) {
			$this->counter->delete( self::attempts_key( $ip ) );
			if ( null !== self::wide_key( $ip ) ) {
				$this->counter->delete( (string) self::wide_key( $ip ) );
			}
		}
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
		if ( null !== $this->counter ) {
			$this->counter->delete( self::attempts_key( $ip ) );
		}

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
	 * Subject the keys are built from: the IPv4 address or the IPv6 network.
	 * An address that isn't counted gives the string itself, so a key is always valid.
	 *
	 * @param string $ip Client IP.
	 */
	private static function subject( string $ip ): string {
		$ip      = trim( $ip );
		$subject = CounterSubject::of( $ip );
		return '' === $subject ? $ip : $subject;
	}

	/**
	 * Store key for an IP's lockout.
	 *
	 * @param string $ip Client IP.
	 */
	public static function lockout_key( string $ip ): string {
		return 'login_lock:' . self::subject( $ip );
	}

	/**
	 * Store key for an IP's failure counter.
	 *
	 * @param string $ip Client IP.
	 */
	public static function failures_key( string $ip ): string {
		return 'login_fail:' . self::subject( $ip );
	}

	/**
	 * Key of the coarse counter for the IPv6 /48 around the address; null for IPv4 and other keys.
	 *
	 * @param string $ip Client IP.
	 */
	public static function wide_key( string $ip ): ?string {
		$subject = CounterSubject::of( trim( $ip ), CounterSubject::MIN_PREFIX );
		return str_contains( $subject, '/' ) && str_contains( $subject, ':' ) ? 'login_n48:' . $subject : null;
	}

	/**
	 * Key of the atomic attempt counter.
	 *
	 * @param string $ip Client IP.
	 */
	public static function attempts_key( string $ip ): string {
		return 'login_n:' . self::subject( $ip );
	}
}
