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

	/** The name is an HTTP request header, which a client can forge. */
	public const KIND_HEADER = 'header';
	/** The name is a server variable set by a web server module (not client-controlled). */
	public const KIND_SERVER_VAR = 'server_var';

	/**
	 * Well-known country headers whose names have no hyphen (normalised form).
	 */
	private const KNOWN_HEADERS = array(
		'CF_IPCOUNTRY',
		'CLOUDFRONT_VIEWER_COUNTRY',
		'X_COUNTRY_CODE',
		'X_GEO_COUNTRY',
		'X_APPENGINE_COUNTRY',
		'FASTLY_GEO_COUNTRY',
	);

	/**
	 * IP of the current request.
	 *
	 * @var string
	 */
	private string $request_ip;
	/**
	 * Header value.
	 *
	 * @var string
	 */
	private string $value;

	/**
	 * Set up the HeaderGeoProvider.
	 *
	 * @param array<string, mixed> $server     $_SERVER.
	 * @param string               $name       Header or server variable name.
	 * @param string               $request_ip IP of the current request.
	 * @param bool                 $trust_headers Whether request headers may be read (the peer is a trusted proxy). Server variables are always read.
	 */
	public function __construct( array $server, string $name, string $request_ip, bool $trust_headers = true ) {
		$this->request_ip = $request_ip;

		$value = '';
		if ( self::KIND_HEADER === self::kind( $name ) ) {
			if ( $trust_headers ) {
				$value = $server[ 'HTTP_' . self::normalise( $name ) ] ?? '';
			}
		} else {
			// Never HTTP_*: a client can send a header with the same name as the variable.
			$value = $server[ $name ] ?? '';
		}
		$this->value = strtoupper( trim( is_scalar( $value ) ? (string) $value : '' ) );
	}

	/**
	 * Upper-case a name, turn - into _ and drop a leading HTTP_.
	 *
	 * @param string $name Configured name.
	 */
	private static function normalise( string $name ): string {
		$normal = strtoupper( str_replace( '-', '_', trim( $name ) ) );
		return 0 === strpos( $normal, 'HTTP_' ) ? substr( $normal, 5 ) : $normal;
	}

	/**
	 * Is a configured name an HTTP header or a server variable?
	 *
	 * A header: a name with a hyphen, one starting with HTTP_ (any case),
	 * one on the well-known list, or one that cannot be a server variable
	 * (anything that is not upper-case letters, digits and underscores).
	 * That last rule makes a mistyped name fail visibly: it is gated like a
	 * header instead of silently reading nothing. Other upper-case names
	 * (GEOIP_COUNTRY_CODE, MM_COUNTRY_CODE) are server variables.
	 *
	 * @param string $name Configured name.
	 * @return string KIND_HEADER or KIND_SERVER_VAR.
	 */
	public static function kind( string $name ): string {
		$name = trim( $name );
		if ( false !== strpos( $name, '-' ) || 0 === stripos( $name, 'HTTP_' ) || 1 !== preg_match( '/^[A-Z][A-Z0-9_]*$/', $name ) ) {
			return self::KIND_HEADER;
		}
		return in_array( self::normalise( $name ), self::KNOWN_HEADERS, true ) ? self::KIND_HEADER : self::KIND_SERVER_VAR;
	}

	/**
	 * Find the country for an IP.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return string|null Upper-case ISO 3166-1 alpha-2 code, or null if unknown.
	 */
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
