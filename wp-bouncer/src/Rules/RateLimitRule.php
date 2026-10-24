<?php
/**
 * Throttles IPs that make too many requests.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Settings;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\CounterSubject;

defined( 'ABSPATH' ) || exit;

/**
 * Fixed-window rate limiter with a temporary ban.
 *
 * Settings:
 * - enabled (bool)
 * - max_requests (int): requests allowed per window.
 * - window_seconds (int): window length.
 * - ban_minutes (int): how long an IP that goes over the limit is refused.
 *
 * Only PHP requests are counted. Static files served directly by the web
 * server never reach WordPress. Administrators are not throttled.
 */
final class RateLimitRule extends AbstractRule {

	public const ID = 'rate_limit';

	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface
	 */
	private CounterStoreInterface $store;

	/**
	 * Set up the RateLimitRule.
	 *
	 * @param array<string, mixed>  $settings Rule settings.
	 * @param CounterStoreInterface $store    Counter storage.
	 */
	public function __construct( array $settings, CounterStoreInterface $store ) {
		parent::__construct( $settings );
		$this->store = $store;
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
		$ip = $request->key_ip();
		// Nothing is counted or banned for loopback, proxy or shared (fallback) addresses.
		if ( '' === $ip || '' === CounterSubject::of( $ip ) || $request->is_trusted() || ! $request->can_be_banned() ) {
			return null;
		}

		$ban_seconds = min( Settings::MAX_BAN_MINUTES, max( 1, (int) $this->setting( 'ban_minutes', 10 ) ) ) * 60;

		if ( null !== $this->store->get( self::ban_key( $ip ) ) ) {
			return $this->deny( 'Temporarily banned for exceeding the rate limit', 429, $ban_seconds );
		}

		$window = max( 1, (int) $this->setting( 'window_seconds', 60 ) );
		$max    = max( 1, (int) $this->setting( 'max_requests', 120 ) );
		$count  = $this->store->increment( self::counter_key( $ip ), $window );

		if ( $count > $max ) {
			$this->store->set( self::ban_key( $ip ), 1, $ban_seconds );
			$this->store->delete( self::counter_key( $ip ) );
			return $this->deny( sprintf( 'Exceeded %d requests in %d seconds', $max, $window ), 429, $ban_seconds );
		}
		return null;
	}

	/**
	 * Store key for an IP's request counter (by counter subject: the IPv4 address or the IPv6 network).
	 *
	 * @param string $ip Client IP.
	 */
	public static function counter_key( string $ip ): string {
		return 'rl_count:' . CounterSubject::key( $ip );
	}

	/**
	 * Store key for an IP's ban (by counter subject, so one read covers the whole IPv6 network).
	 *
	 * @param string $ip Client IP.
	 */
	public static function ban_key( string $ip ): string {
		return 'rl_ban:' . CounterSubject::key( $ip );
	}

	/**
	 * Every key to clear when unlocking an address: subject keys and the exact-string keys of earlier versions.
	 *
	 * @param string $ip Client IP as typed.
	 * @return string[]
	 */
	public static function keys_for( string $ip ): array {
		$keys = array();
		foreach ( CounterSubject::keys( $ip ) as $part ) {
			$keys[] = 'rl_ban:' . $part;
			$keys[] = 'rl_count:' . $part;
		}
		return $keys;
	}
}
