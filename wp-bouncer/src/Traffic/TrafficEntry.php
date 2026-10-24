<?php
/**
 * Builds one traffic log row.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Traffic;

use WPBouncer\Support\UrlRedactor;

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

	/** What a secret value is replaced with. */
	public const REDACTED = UrlRedactor::REDACTED;

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
	 * Kept for callers of the old name; see UrlRedactor::redact().
	 *
	 * @param string $url URL or request URI.
	 */
	public static function redact_url( string $url ): string {
		return UrlRedactor::redact( $url );
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
