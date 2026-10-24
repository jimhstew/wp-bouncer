<?php
/**
 * Works out the real client IP, taking reverse proxies into account.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves the client IP from $_SERVER according to the configured source.
 *
 * Proxy headers are trivially forged by clients, so a header is only honoured
 * when REMOTE_ADDR is one of the trusted proxies. With a header source and no
 * trusted proxies the header is ignored and REMOTE_ADDR is used (the
 * "fallback", see fallback_active()). A value taken from a header must also
 * be a public address: loopback, private and unspecified values are refused.
 */
final class IpResolver {

	/** Map of setting value => $_SERVER key. */
	public const SOURCES = array(
		'remote_addr'      => 'REMOTE_ADDR',
		'x_forwarded_for'  => 'HTTP_X_FORWARDED_FOR',
		'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP',
		'x_real_ip'        => 'HTTP_X_REAL_IP',
	);

	/** Forwarding headers whose presence means a proxy sits in front of the site. */
	public const FORWARDING_HEADERS = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_FORWARDED' );

	/**
	 * IP source key.
	 *
	 * @var string
	 */
	private string $source;
	/**
	 * Proxies allowed to set the IP header (over-broad entries removed).
	 *
	 * @var string[]
	 */
	private array $trusted_proxies;
	/**
	 * Accept private addresses from a trusted proxy.
	 *
	 * @var bool
	 */
	private bool $allow_private;

	/**
	 * Set up the IpResolver.
	 *
	 * @param string   $source          One of the SOURCES keys.
	 * @param string[] $trusted_proxies IPs / CIDRs of proxies allowed to set the header.
	 *                                  Entries that are too broad (see IpUtils::is_broad_range()) are ignored.
	 * @param bool     $allow_private   Accept private (not loopback) header values. Off by default.
	 */
	public function __construct( string $source = 'remote_addr', array $trusted_proxies = array(), bool $allow_private = false ) {
		$this->source          = isset( self::SOURCES[ $source ] ) ? $source : 'remote_addr';
		$this->trusted_proxies = IpUtils::without_broad( $trusted_proxies );
		$this->allow_private   = $allow_private;
	}

	/**
	 * The trusted proxies actually in force (over-broad entries removed).
	 *
	 * @return string[]
	 */
	public function proxies(): array {
		return $this->trusted_proxies;
	}

	/**
	 * Is a header source configured with no usable trusted proxy?
	 *
	 * In that state the header is ignored and the address is REMOTE_ADDR,
	 * which may be a proxy shared by many visitors.
	 */
	public function fallback_active(): bool {
		return 'remote_addr' !== $this->source && empty( $this->trusted_proxies );
	}

	/**
	 * Must bans, lockouts and counters be suspended for this request?
	 *
	 * True during the fallback (header source, no proxies), and also when a
	 * forwarding header arrives from an unlisted peer that is not public (a
	 * same-host or LAN proxy that is not on the list yet). An unlisted public
	 * peer (for example a CDN edge not yet listed) stays bannable: see the
	 * peer_not_in_proxies notice.
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 */
	public function suspends_bans( array $server ): bool {
		if ( $this->fallback_active() ) {
			return true;
		}
		if ( 'remote_addr' === $this->source ) {
			return false;
		}
		$remote = trim( (string) ( $server['REMOTE_ADDR'] ?? '' ) );
		if ( '' !== $remote && IpUtils::matches_any( $remote, $this->trusted_proxies ) ) {
			return false;
		}
		// A public peer is keyed on its own address and stays bannable: otherwise anyone
		// reaching the origin directly could add a header and switch every ban off.
		// Only a non-public peer (same host or LAN, which outsiders can't be) is a proxy
		// whose address stands for many visitors.
		if ( '' !== $remote && IpUtils::is_public( $remote ) ) {
			return false;
		}
		foreach ( self::FORWARDING_HEADERS as $header ) {
			if ( isset( $server[ $header ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Counter subject for a request whose forwarding header was refused.
	 *
	 * A trusted proxy sent the configured header but its value was unusable
	 * (loopback, private, junk), so the request resolves to the proxy itself,
	 * which is never banned. Without a subject of its own, such a request could
	 * repeat without limit. "rejected:<proxy>" matches only requests that carry
	 * a rejected header, so it is safe to count and ban.
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 * @return string The subject, or '' when this is not such a request.
	 */
	public function rejected_subject( array $server ): string {
		if ( 'remote_addr' === $this->source || $this->fallback_active() ) {
			return '';
		}
		$remote = trim( (string) ( $server['REMOTE_ADDR'] ?? '' ) );
		if ( '' === $remote || ! IpUtils::is_valid( $remote ) || ! IpUtils::matches_any( $remote, $this->trusted_proxies ) ) {
			return '';
		}
		if ( '' === trim( (string) ( $server[ self::SOURCES[ $this->source ] ] ?? '' ) ) ) {
			return '';
		}
		return $this->resolve( $server ) === $remote ? 'rejected:' . $remote : '';
	}

	/**
	 * Is this a request from the server itself (WP-Cron, health checks)?
	 *
	 * True when REMOTE_ADDR is loopback and no forwarding header is present.
	 * With a forwarding header the loopback peer is a same-host proxy, and the
	 * request came from outside.
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 */
	public function is_local_request( array $server ): bool {
		$remote = trim( (string) ( $server['REMOTE_ADDR'] ?? '' ) );
		if ( ! IpUtils::is_valid( $remote ) || ! IpUtils::is_loopback( $remote ) ) {
			return false;
		}
		foreach ( self::FORWARDING_HEADERS as $header ) {
			if ( isset( $server[ $header ] ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Resolve the client IP.
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 * @return string A valid IP, or '' if none could be determined.
	 */
	public function resolve( array $server ): string {
		$remote = trim( (string) ( $server['REMOTE_ADDR'] ?? '' ) );
		$remote = IpUtils::is_valid( $remote ) ? $remote : '';

		if ( 'remote_addr' === $this->source || $this->fallback_active() ) {
			return $remote;
		}

		if ( '' === $remote || ! IpUtils::matches_any( $remote, $this->trusted_proxies ) ) {
			return $remote;
		}

		$header = (string) ( $server[ self::SOURCES[ $this->source ] ] ?? '' );
		if ( '' === $header ) {
			return $remote;
		}

		if ( 'x_forwarded_for' === $this->source ) {
			$candidate = $this->from_forwarded_chain( $header );
		} else {
			$candidate = trim( $header );
		}

		return $this->acceptable( $candidate ) ? $candidate : $remote;
	}

	/**
	 * May this header value be used as the client address?
	 *
	 * @param string $candidate Value taken from the header.
	 */
	private function acceptable( string $candidate ): bool {
		if ( ! IpUtils::is_valid( $candidate ) ) {
			return false;
		}
		if ( $this->allow_private ) {
			return ! IpUtils::is_loopback( $candidate ) && ! IpUtils::is_unspecified( $candidate );
		}
		return IpUtils::is_public( $candidate );
	}

	/**
	 * Pick the client from an X-Forwarded-For chain.
	 *
	 * Each proxy appends the address it received the request from, so walk the
	 * list right-to-left and return the first address that is not one of our
	 * trusted proxies. Anything further left could have been forged by the client.
	 *
	 * @param string $header Raw header value: "client, proxy1, proxy2".
	 */
	private function from_forwarded_chain( string $header ): string {
		$hops = array_reverse( array_filter( array_map( 'trim', explode( ',', $header ) ) ) );
		foreach ( $hops as $hop ) {
			if ( ! IpUtils::is_valid( $hop ) ) {
				return '';
			}
			if ( ! IpUtils::matches_any( $hop, $this->trusted_proxies ) ) {
				return $hop;
			}
		}
		return '';
	}
}
