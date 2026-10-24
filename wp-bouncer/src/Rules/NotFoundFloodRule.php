<?php
/**
 * Bans IPs that rack up "not found" pages: vulnerability scanners.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Settings;
use WPBouncer\Storage\AtomicCounterInterface;
use WPBouncer\Storage\CounterStoreInterface;

defined( 'ABSPATH' ) || exit;

/**
 * Scanners try hundreds of URLs for known-vulnerable plugins and themes, and
 * almost all of them are 404s. Real visitors rarely see more than one or two.
 *
 * Two halves, like the login lockout:
 * - record() is called after WordPress has decided a page is a 404, and
 *   counts it. Going over the limit places a ban.
 * - inspect() refuses banned IPs at the door on later requests.
 *
 * Not counted: logged-in administrators, missing images/CSS/JS/fonts (a page
 * with broken images must not ban its reader), and, if ignore_crawlers is on,
 * visitors whose User-Agent says they are a major search engine.
 *
 * Settings:
 * - enabled (bool)
 * - max_404 (int): 404s allowed per window.
 * - window_seconds (int)
 * - ban_minutes (int)
 * - ignore_crawlers (bool)
 */
final class NotFoundFloodRule extends AbstractRule {

	public const ID = 'not_found';

	/** Missing static files are not counted. */
	private const ASSET = '#\.(jpe?g|png|gif|webp|avif|svg|ico|bmp|tiff?|css|js|mjs|map|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf)$#';

	/** Search engine crawlers (by User-Agent, which can be faked). */
	private const CRAWLERS = '/googlebot|bingbot|duckduckbot|baiduspider|yandex|applebot|slurp|petalbot|seznambot|qwantify/i';

	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface
	 */
	private CounterStoreInterface $store;

	/**
	 * Atomic counter for the 404 counts (falls back to the store's counter).
	 *
	 * @var AtomicCounterInterface|null
	 */
	private ?AtomicCounterInterface $counter;

	/**
	 * Set up the NotFoundFloodRule.
	 *
	 * @param array<string, mixed>        $settings Rule settings (cross_site_multiplier: how many times the limit applies to 404s another site's page caused, default 5).
	 * @param CounterStoreInterface       $store    Counter storage.
	 * @param AtomicCounterInterface|null $counter  Atomic counter for the 404 counts.
	 */
	public function __construct( array $settings, CounterStoreInterface $store, ?AtomicCounterInterface $counter = null ) {
		parent::__construct( $settings );
		$this->store   = $store;
		$this->counter = $counter;
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
		if ( '' === $ip || $request->is_trusted() || ! $request->can_be_banned() ) {
			return null;
		}
		if ( null !== $this->store->get( self::ban_key( $ip ) ) ) {
			return $this->deny( 'Temporarily banned for too many "not found" requests', 403, $this->ban_seconds() );
		}
		// Foreign 404s past their limit only close the door to further foreign requests (never the whole site),
		// so a hostile page can't lock its visitor out. Link clicks and the visitor's own requests pass.
		if ( $request->is_foreign_fetch() && null !== $this->store->get( self::foreign_ban_key( $ip ) ) ) {
			return $this->deny( 'Requests from another site refused after repeated "not found" requests', 403, $this->ban_seconds() );
		}
		return null;
	}

	/**
	 * Count a 404 for this request.
	 *
	 * @param Request $request The request that produced the 404.
	 * @return string|null A reason if this 404 placed a ban, otherwise null.
	 */
	public function record( Request $request ): ?string {
		if ( ! $this->counts( $request ) ) {
			return null;
		}
		$ip      = $request->key_ip();
		$window  = max( 1, (int) $this->setting( 'window_seconds', 60 ) );
		$max     = max( 1, (int) $this->setting( 'max_404', 20 ) );
		$foreign = $request->is_foreign_fetch();
		if ( $foreign ) {
			// Another site's page can cause these, so they have their own counter and a higher limit.
			$max *= max( 1, (int) $this->setting( 'cross_site_multiplier', 5 ) );
		}
		$key   = $foreign ? self::foreign_counter_key( $ip ) : self::counter_key( $ip );
		$count = null !== $this->counter ? $this->counter->add_or_increment( $key, $window ) : $this->store->increment( $key, $window );
		if ( $count <= $max ) {
			return null;
		}
		$this->store->set( $foreign ? self::foreign_ban_key( $ip ) : self::ban_key( $ip ), 1, $this->ban_seconds() );
		null !== $this->counter ? $this->counter->delete( $key ) : $this->store->delete( $key );
		return sprintf(
			$foreign ? 'Requests from another site refused for %d minutes after more than %d "not found" requests in %d seconds' : 'Banned for %d minutes after more than %d "not found" requests in %d seconds',
			(int) ( $this->ban_seconds() / 60 ),
			$max,
			$window
		);
	}

	/**
	 * Does this 404 count towards a ban?
	 *
	 * @param Request $request Request.
	 */
	public function counts( Request $request ): bool {
		if ( ! $this->is_enabled() || '' === $request->ip() || $request->is_trusted() || ! $request->can_be_banned() ) {
			return false;
		}
		if ( preg_match( self::ASSET, $request->path() ) || $request->is_exempt_subresource() ) {
			return false;
		}
		if ( $this->setting( 'ignore_crawlers', true ) && preg_match( self::CRAWLERS, $request->user_agent() ) ) {
			return false;
		}
		return true;
	}

	/** Ban length in seconds. */
	private function ban_seconds(): int {
		return min( Settings::MAX_BAN_MINUTES, max( 1, (int) $this->setting( 'ban_minutes', 60 ) ) ) * 60;
	}

	/**
	 * Store key for an IP's 404 counter.
	 *
	 * @param string $ip Client IP.
	 */
	public static function counter_key( string $ip ): string {
		return 'nf_count:' . $ip;
	}

	/**
	 * Store key for an IP's counter of 404s that another site's page caused.
	 *
	 * @param string $ip Client IP.
	 */
	public static function foreign_counter_key( string $ip ): string {
		return 'nf_count_x:' . $ip;
	}

	/**
	 * Store key for the refusal of foreign requests from an IP.
	 *
	 * @param string $ip Client IP.
	 */
	public static function foreign_ban_key( string $ip ): string {
		return 'nf_xban:' . $ip;
	}

	/**
	 * Store key for an IP's ban.
	 *
	 * @param string $ip Client IP.
	 */
	public static function ban_key( string $ip ): string {
		return 'nf_ban:' . $ip;
	}
}
