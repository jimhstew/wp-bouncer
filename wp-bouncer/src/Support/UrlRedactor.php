<?php
/**
 * Removes secrets from URLs before they are stored or emailed.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP, no WordPress calls.
 */
final class UrlRedactor {

	/** What a secret value is replaced with. */
	public const REDACTED = '[removed]';

	/** Query parameters whose values are replaced. */
	private const SECRET_PARAMS = array( 'key', 'pwd', 'pass', 'pass1', 'pass2', 'password', 'token', 'access_token', 'refresh_token', 'id_token', 'auth', 'code', 'secret', 'client_secret', 'api_key', 'apikey', 'signature', 'sig', 'nonce', '_wpnonce', 'session', 'sid', 'otp', 'jwt', 'email', 'e-mail', 'mail', 'user_email' );

	/** Also replaced: any parameter whose name contains one of these. */
	private const SECRET_PARTS = array( 'token', 'secret', 'email', 'nonce', 'apikey', 'api_key', 'api-key', 'license_key', 'licence_key', '_key', '-key', 'auth_', 'credential' );

	/** Login form fields: always replaced, whatever the value. */
	private const LOGIN_PARAMS = array( 'log', 'pwd', 'user_login', 'username', 'user' );

	/** Longest chain of URLs inside URLs that is looked into. */
	private const MAX_DEPTH = 2;

	/**
	 * Replace the values of secret query parameters (reset keys, tokens,
	 * passwords, nonces, email addresses, and any value that looks like an
	 * email address), the user info of a full URL, and secret-looking
	 * key=value pairs in a fragment, with "[removed]".
	 *
	 * @param string $url URL or request URI.
	 */
	public static function redact( string $url ): string {
		return self::redact_at_depth( $url, 0 );
	}

	/**
	 * Redact, looking into URLs held in parameter values down to a set depth.
	 *
	 * @param string $url   URL or request URI.
	 * @param int    $depth Current nesting level.
	 */
	private static function redact_at_depth( string $url, int $depth ): string {
		if ( '' === $url ) {
			return '';
		}
		if ( false !== strpos( $url, '://' ) ) {
			$url = self::strip_user_info( $url );
		}
		$url = (string) preg_replace( '/wp-personal-data-file-[A-Za-z0-9]+/', 'wp-personal-data-file-' . self::REDACTED, $url );
		$url = (string) preg_replace( '/;jsessionid=[^?#&\/;]*/i', ';jsessionid=' . self::REDACTED, $url );
		$q   = strpos( $url, '?' );
		$h   = strpos( $url, '#' );
		if ( false === $q && false === $h ) {
			return $url;
		}
		if ( false !== $h && ( false === $q || $h < $q ) ) {
			// A "?" after a "#" belongs to the fragment.
			return substr( $url, 0, $h + 1 ) . self::redact_pairs( substr( $url, $h + 1 ), $depth );
		}
		$h     = strpos( $url, '#', $q );
		$query = false === $h ? substr( $url, $q + 1 ) : substr( $url, $q + 1, $h - $q - 1 );
		$tail  = false === $h ? '' : '#' . self::redact_pairs( substr( $url, $h + 1 ), $depth );
		return substr( $url, 0, $q + 1 ) . self::redact_pairs( $query, $depth ) . $tail;
	}

	/**
	 * A short, safe description of a source URL: the host plus the last path
	 * segment. No user info, query or fragment. A value that isn't a URL
	 * (such as an uploaded file name) loses any query or fragment and is
	 * otherwise returned as it is.
	 *
	 * @param string $url URL or file name.
	 */
	public static function label( string $url ): string {
		$url = trim( $url );
		if ( 1 !== preg_match( '#^[a-z][a-z0-9+.\-]*://([^/?\#]*)([^?\#]*)#i', $url, $m ) ) {
			$cut = strcspn( $url, '?#' );
			return substr( $url, 0, $cut );
		}
		$host = $m[1];
		$at   = strrpos( $host, '@' );
		if ( false !== $at ) {
			$host = substr( $host, $at + 1 );
		}
		$path    = trim( $m[2], '/' );
		$segment = '' === $path ? '' : substr( $path, (int) strrpos( '/' . $path, '/' ) );
		if ( '' !== $segment && false === strpos( $segment, '.' ) ) {
			$segment = self::REDACTED; // No file extension: likely a licence key or token.
		}
		return '' === $segment ? $host : $host . '/…/' . $segment;
	}

	/**
	 * Remove "user:password@" from a full URL.
	 *
	 * @param string $url URL.
	 */
	private static function strip_user_info( string $url ): string {
		if ( 1 !== preg_match( '#^([a-z][a-z0-9+.\-]*://)([^/?\#]*)@#i', $url, $m ) ) {
			return $url;
		}
		return $m[1] . self::REDACTED . '@' . substr( $url, strlen( $m[0] ) );
	}

	/**
	 * Redact the values in an "a=b&c=d" string.
	 *
	 * @param string $pairs Query string or fragment, without the leading mark.
	 * @param int    $depth Current nesting level.
	 */
	private static function redact_pairs( string $pairs, int $depth ): string {
		if ( '' === $pairs ) {
			return '';
		}
		$parts = explode( '&', $pairs );
		foreach ( $parts as $i => $part ) {
			$eq = strpos( $part, '=' );
			if ( false === $eq ) {
				continue;
			}
			$value = substr( $part, $eq + 1 );
			if ( '' === $value ) {
				continue;
			}
			$raw   = strtolower( rawurldecode( str_replace( '+', ' ', substr( $part, 0, $eq ) ) ) );
			$full  = trim( (string) preg_replace( '/[\[\].\s]+/', '_', $raw ), '_' );
			$base  = (string) preg_replace( '/\[.*$/', '', $raw );
			$clean = self::value_to_store( $value, $depth );
			if ( self::is_secret( $full ) || self::is_secret( $base ) || self::looks_like_email( $value ) ) {
				$parts[ $i ] = substr( $part, 0, $eq + 1 ) . self::REDACTED;
			} elseif ( $clean !== $value ) {
				$parts[ $i ] = substr( $part, 0, $eq + 1 ) . $clean;
			}
		}
		return implode( '&', $parts );
	}

	/**
	 * A value that is itself a URL with a query string gets that query redacted.
	 *
	 * @param string $value Raw (still encoded) value.
	 * @param int    $depth Current nesting level.
	 */
	private static function value_to_store( string $value, int $depth ): string {
		if ( $depth >= self::MAX_DEPTH || strlen( $value ) > 8192 ) {
			return $value;
		}
		$decoded = rawurldecode( $value );
		if ( false === strpos( $decoded, '?' ) || 1 !== preg_match( '#^(?:[a-z][a-z0-9+.\-]*:)?//|^/#i', $decoded ) ) {
			return $value;
		}
		$redacted = self::redact_at_depth( $decoded, $depth + 1 );
		if ( $redacted === $decoded ) {
			return $value;
		}
		return str_replace( rawurlencode( self::REDACTED ), self::REDACTED, rawurlencode( $redacted ) );
	}

	/**
	 * Is the (possibly encoded) value an email address?
	 *
	 * @param string $value Raw value.
	 */
	private static function looks_like_email( string $value ): bool {
		if ( strlen( $value ) > 320 * 3 ) {
			return false;
		}
		$value = rawurldecode( str_replace( '+', ' ', $value ) );
		return 1 === preg_match( '/^[^\s@\/]{1,64}@[^\s@\/]+\.[^\s@\/]+$/', trim( $value ) );
	}

	/**
	 * Is the parameter name a secret?
	 *
	 * @param string $name Lowercased, decoded parameter name.
	 */
	private static function is_secret( string $name ): bool {
		if ( in_array( $name, self::SECRET_PARAMS, true ) || in_array( $name, self::LOGIN_PARAMS, true ) ) {
			return true;
		}
		if ( 1 === preg_match( '/(^|[_\-.])pass/', $name ) ) {
			return true;
		}
		foreach ( self::SECRET_PARTS as $part ) {
			if ( false !== strpos( $name, $part ) ) {
				return true;
			}
		}
		return false;
	}
}
