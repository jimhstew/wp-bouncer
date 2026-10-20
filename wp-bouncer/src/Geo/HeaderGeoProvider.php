<?php
/**
 * Reads the country from a header or server variable set by your proxy or web server.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Geo;

defined( 'ABSPATH' ) || exit;

/**
 * Uses a country code that something in front of WordPress already worked out:
 * Cloudflare's CF-IPCountry header, nginx/Apache GeoIP modules
 * (GEOIP_COUNTRY_CODE, MM_COUNTRY_CODE), or a load balancer header.
 *
 * It only knows about the current request, so it answers only for that
 * request's IP. Only enable it when the header can't be set by clients,
 * for example when traffic can reach the site only through Cloudflare.
 */
final class HeaderGeoProvider implements GeoProviderInterface {

	private string $request_ip;
	private string $value;

	/**
	 * @param array<string, mixed> $server     $_SERVER.
	 * @param string               $name       Header or server variable name.
	 * @param string               $request_ip IP of the current request.
	 */
	public function __construct( array $server, string $name, string $request_ip ) {
		$this->request_ip = $request_ip;

		$key         = 'HTTP_' . strtoupper( str_replace( '-', '_', $name ) );
		$this->value = strtoupper( trim( (string) ( $server[ $key ] ?? $server[ $name ] ?? '' ) ) );
	}

	/** {@inheritDoc} */
	public function lookup( string $ip ): ?string {
		if ( $ip !== $this->request_ip ) {
			return null;
		}
		// "XX" (unknown) is Cloudflare's placeholder. "T1" (Tor) is kept so Tor can be blocked.
		if ( ! preg_match( '/^[A-Z][A-Z0-9]$/', $this->value ) || 'XX' === $this->value ) {
			return null;
		}
		return $this->value;
	}
}
