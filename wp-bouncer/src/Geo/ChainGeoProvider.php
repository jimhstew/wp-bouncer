<?php
/**
 * Asks several providers in turn and caches answers for the request.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Geo;

defined( 'ABSPATH' ) || exit;

/**
 * Returns the first non-null answer from its providers. Results are cached
 * for the request, so the country rule and the logger share one lookup.
 */
final class ChainGeoProvider implements GeoProviderInterface {

	/**
	 * Providers in priority order.
	 *
	 * @var GeoProviderInterface[]
	 */
	private array $providers;

	/**
	 * Lookup results by IP.
	 *
	 * @var array<string, string|null>
	 */
	private array $cache = array();

	/**
	 * Set up the ChainGeoProvider.
	 *
	 * @param GeoProviderInterface[] $providers In priority order.
	 */
	public function __construct( array $providers ) {
		$this->providers = $providers;
	}

	/**
	 * Find the country for an IP.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return string|null Upper-case ISO 3166-1 alpha-2 code, or null if unknown.
	 */
	public function lookup( string $ip ): ?string {
		if ( array_key_exists( $ip, $this->cache ) ) {
			return $this->cache[ $ip ];
		}
		$result = null;
		foreach ( $this->providers as $provider ) {
			$result = $provider->lookup( $ip );
			if ( null !== $result ) {
				break;
			}
		}
		$this->cache[ $ip ] = $result;
		return $result;
	}
}
