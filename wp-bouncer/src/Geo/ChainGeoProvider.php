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

	/** @var GeoProviderInterface[] */
	private array $providers;

	/** @var array<string, string|null> */
	private array $cache = array();

	/**
	 * @param GeoProviderInterface[] $providers In priority order.
	 */
	public function __construct( array $providers ) {
		$this->providers = $providers;
	}

	/** {@inheritDoc} */
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
