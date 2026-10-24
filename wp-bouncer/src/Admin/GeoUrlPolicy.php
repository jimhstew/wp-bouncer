<?php
/**
 * Which URLs the geo database importer may fetch.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Pure check, made before any request: https only, and the host must be
 * exactly on the list. A DNS-rebinding host can't be told apart from a good
 * one after validation, so the list (not the lookup) is the defence (RT-12).
 */
final class GeoUrlPolicy {

	/** Hosts that publish the free country databases. */
	public const DEFAULT_HOSTS = array( 'download.db-ip.com', 'download.ip2location.com' );

	/**
	 * May this URL be fetched?
	 *
	 * @param string   $url        URL.
	 * @param string[] $hosts      Allowed host names.
	 * @param bool     $allow_http Also accept http (for local test servers).
	 */
	public static function allowed( string $url, array $hosts, bool $allow_http = false ): bool {
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- this class is pure PHP (no WordPress calls) so it can be unit-tested; the result is checked field by field.
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return false;
		}
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return false;
		}
		$scheme = strtolower( (string) $parts['scheme'] );
		if ( 'https' !== $scheme && ! ( $allow_http && 'http' === $scheme ) ) {
			return false;
		}
		$host  = strtolower( rtrim( (string) $parts['host'], '.' ) );
		$hosts = array_map( 'strtolower', $hosts );
		return in_array( $host, $hosts, true );
	}

	/**
	 * Resolve a redirect's Location against the URL that issued it, and say
	 * whether following it is allowed: same rules as the first request, and
	 * never https to http (unless http is allowed at all).
	 *
	 * @param string   $current    URL that answered with the redirect.
	 * @param string   $location   Location header value (absolute, scheme-relative, or relative).
	 * @param string[] $hosts      Allowed host names.
	 * @param bool     $allow_http Also accept http.
	 * @return string|null The absolute target, or null if it must not be followed.
	 */
	public static function redirect_target( string $current, string $location, array $hosts, bool $allow_http = false ): ?string {
		$location = trim( $location );
		$base     = parse_url( $current ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- pure PHP class, see allowed().
		if ( '' === $location || ! is_array( $base ) || empty( $base['scheme'] ) || empty( $base['host'] ) ) {
			return null;
		}
		$origin = strtolower( (string) $base['scheme'] ) . '://' . (string) $base['host'] . ( isset( $base['port'] ) ? ':' . (int) $base['port'] : '' );
		if ( 1 === preg_match( '#^[a-z][a-z0-9+.-]*:#i', $location ) ) {
			$target = $location;
		} elseif ( 0 === strpos( $location, '//' ) ) {
			$target = strtolower( (string) $base['scheme'] ) . ':' . $location;
		} elseif ( 0 === strpos( $location, '/' ) ) {
			$target = $origin . $location;
		} else {
			$dir    = isset( $base['path'] ) ? substr( (string) $base['path'], 0, (int) strrpos( (string) $base['path'], '/' ) + 1 ) : '/';
			$target = $origin . ( '' === $dir ? '/' : $dir ) . $location;
		}
		$was_https = 'https' === strtolower( (string) $base['scheme'] );
		$now_http  = 0 === stripos( $target, 'http:' );
		if ( $was_https && $now_http && ! $allow_http ) {
			return null;
		}
		return self::allowed( $target, $hosts, $allow_http ) ? $target : null;
	}
}
