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
 * Proxy headers are trivially forged by clients. They are only honoured when
 * REMOTE_ADDR is one of the trusted proxies, or when no trusted proxies are
 * configured (the admin screen warns about the second case).
 */
final class IpResolver {

	/** Map of setting value => $_SERVER key. */
	public const SOURCES = array(
		'remote_addr'      => 'REMOTE_ADDR',
		'x_forwarded_for'  => 'HTTP_X_FORWARDED_FOR',
		'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP',
		'x_real_ip'        => 'HTTP_X_REAL_IP',
	);

	private string $source;
	/** @var string[] */
	private array $trusted_proxies;

	/**
	 * @param string   $source          One of the SOURCES keys.
	 * @param string[] $trusted_proxies IPs / CIDRs of proxies allowed to set the header.
	 */
	public function __construct( string $source = 'remote_addr', array $trusted_proxies = array() ) {
		$this->source          = isset( self::SOURCES[ $source ] ) ? $source : 'remote_addr';
		$this->trusted_proxies = $trusted_proxies;
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

		if ( 'remote_addr' === $this->source ) {
			return $remote;
		}

		$proxy_is_trusted = empty( $this->trusted_proxies ) || ( '' !== $remote && IpUtils::matches_any( $remote, $this->trusted_proxies ) );
		if ( ! $proxy_is_trusted ) {
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

		return IpUtils::is_valid( $candidate ) ? $candidate : $remote;
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
			if ( empty( $this->trusted_proxies ) || ! IpUtils::matches_any( $hop, $this->trusted_proxies ) ) {
				return $hop;
			}
		}
		return '';
	}
}
