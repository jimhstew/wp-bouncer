<?php
/**
 * Contract for IP-to-country lookup.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Geo;

defined( 'ABSPATH' ) || exit;

/**
 * Country lookup. Every implementation is local; no third-party API is called.
 */
interface GeoProviderInterface {

	/**
	 * Find the country for an IP.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return string|null Upper-case ISO 3166-1 alpha-2 code, or null if unknown.
	 */
	public function lookup( string $ip ): ?string;
}
