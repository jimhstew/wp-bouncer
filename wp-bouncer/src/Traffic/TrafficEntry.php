<?php
/**
 * Builds one traffic log row.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Traffic;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP, unit-tested. Turns what was known at the end of a request into a
 * row that fits the {prefix}bouncer_traffic columns, with secrets taken out
 * of URLs first.
 */
final class TrafficEntry {

	/** Column length limits (match the schema in Installer). */
	private const LIMITS = array(
		'ip'         => 45,
		'method'     => 10,
		'uri'        => 2048,
		'referrer'   => 2048,
		'user_agent' => 512,
		'client'     => 16,
	);

	/** Query parameters whose values are replaced before saving. */
	private const SECRET_PARAMS = array( 'key', 'pwd', 'pass', 'pass1', 'pass2', 'password', 'token', 'access_token', 'refresh_token', 'id_token', 'auth', 'code', 'secret', 'client_secret', 'api_key', 'apikey', 'signature', 'sig', 'nonce', '_wpnonce', 'session', 'sid', 'otp', 'jwt' );

	/** Also replaced: any parameter whose name contains one of these. */
	private const SECRET_PARTS = array( 'pass', 'token', 'secret' );

	/** What a secret value is replaced with. */
	public const REDACTED = '[removed]';

	/**
	 * Build a row.
	 *
	 * @param array<string, mixed> $data ip, method, uri, status, referrer, user_agent, user_id.
	 * @return array<string, string|int>
	 */
	public static function build( array $data ): array {
		$ua  = self::text( $data['user_agent'] ?? '' );
		$row = array(
			'ip'         => self::text( $data['ip'] ?? '' ),
			'method'     => strtoupper( self::text( $data['method'] ?? '' ) ),
			'uri'        => self::redact_url( self::text( $data['uri'] ?? '' ) ),
			'referrer'   => self::redact_url( self::text( $data['referrer'] ?? '' ) ),
			'user_agent' => $ua,
			'client'     => ClientClassifier::classify( $ua ),
		);
		foreach ( self::LIMITS as $column => $limit ) {
			$row[ $column ] = function_exists( 'mb_substr' ) ? mb_substr( $row[ $column ], 0, $limit ) : substr( $row[ $column ], 0, $limit );
		}
		$status         = (int) ( $data['status'] ?? 0 );
		$row['status']  = $status >= 100 && $status <= 599 ? $status : 0;
		$row['user_id'] = max( 0, (int) ( $data['user_id'] ?? 0 ) );
		return $row;
	}

	/**
	 * Replace the values of secret query parameters, such as the key in a
	 * password-reset link or an access token, with "[removed]".
	 *
	 * @param string $url URL or request URI.
	 */
	public static function redact_url( string $url ): string {
		$q = strpos( $url, '?' );
		if ( false === $q ) {
			return $url;
		}
		$hash  = strpos( $url, '#', $q );
		$query = false === $hash ? substr( $url, $q + 1 ) : substr( $url, $q + 1, $hash - $q - 1 );
		$tail  = false === $hash ? '' : substr( $url, $hash );
		$parts = explode( '&', $query );
		foreach ( $parts as $i => $part ) {
			$eq = strpos( $part, '=' );
			if ( false === $eq ) {
				continue;
			}
			$name = strtolower( rawurldecode( substr( $part, 0, $eq ) ) );
			$name = (string) preg_replace( '/\[.*$/', '', $name ); // pass[0] => pass.
			if ( self::is_secret( $name ) && '' !== substr( $part, $eq + 1 ) ) {
				$parts[ $i ] = substr( $part, 0, $eq + 1 ) . self::REDACTED;
			}
		}
		return substr( $url, 0, $q + 1 ) . implode( '&', $parts ) . $tail;
	}

	/**
	 * Is secret.
	 *
	 * @param string $name Lowercased parameter name.
	 */
	private static function is_secret( string $name ): bool {
		if ( in_array( $name, self::SECRET_PARAMS, true ) ) {
			return true;
		}
		foreach ( self::SECRET_PARTS as $part ) {
			if ( false !== strpos( $name, $part ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Scalar to one line of text.
	 *
	 * @param mixed $value Value.
	 */
	private static function text( $value ): string {
		return is_scalar( $value ) ? trim( (string) preg_replace( '/[\x00-\x1F\x7F]/', '', (string) $value ) ) : '';
	}

	/**
	 * The status class a filter value stands for.
	 *
	 * @param string $filter '2xx', '3xx', '4xx' or '5xx'.
	 * @return array{0: int, 1: int}|null Lowest and highest code, or null if not a class.
	 */
	public static function status_range( string $filter ): ?array {
		if ( ! preg_match( '/^([1-5])xx$/', $filter, $m ) ) {
			return null;
		}
		$low = (int) $m[1] * 100;
		return array( $low, $low + 99 );
	}
}
