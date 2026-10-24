<?php
/**
 * Works out whether a request was started by this site's own pages.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP, no WordPress calls.
 *
 * Browsers describe where a request came from in the Sec-Fetch-Site header.
 * Older ones don't send it, so the Origin header (sent with POSTs) is compared
 * with the site's own hosts instead. Without either, the answer is "unknown",
 * which callers treat as before (bots, curl and old browsers behave as today).
 *
 * These headers can be forged by a non-browser client. A forged "cross-site"
 * only ever makes a request count for less, and login posts that claim it are
 * refused, so a forged header buys nothing.
 */
final class FetchContext {

	public const CROSS_SITE  = 'cross-site';
	public const SAME_SITE   = 'same-site';
	public const SAME_ORIGIN = 'same-origin';
	public const NONE        = 'none';
	public const UNKNOWN     = 'unknown';

	/**
	 * Sec-Fetch-Dest values for things a page loads by itself, with the file extensions each one may fetch.
	 * A request for "/.env" with a destination of "image" is not a real image load, so the extension must fit.
	 */
	private const SUBRESOURCES = array(
		'image'  => 'jpe?g|png|gif|webp|avif|svg|ico|bmp|tiff?',
		'font'   => 'woff2?|ttf|otf|eot',
		'style'  => 'css',
		'script' => 'js|mjs',
		'audio'  => 'mp3|wav|ogg|m4a|flac|aac',
		'video'  => 'mp4|webm|ogv|mov|m4v',
		'track'  => 'vtt|srt',
	);

	/**
	 * Classify a request.
	 *
	 * - Sec-Fetch-Site is used when present. For cross-site and same-site it is overruled by an
	 *   Origin header naming this site: a page cannot forge Origin, so that is a request from our own pages
	 *   (sibling subdomains and other sites on the allowed list are told apart that way).
	 * - Without Sec-Fetch-Site, Origin is compared with the site's origins. On a POST an Origin of "null"
	 *   (a sandboxed or redirected context) counts as cross-site.
	 * - Without either, a GET falls back to the Referer.
	 * - Otherwise "unknown" (old browsers, bots, curl), which callers treat as before.
	 *
	 * An origin is scheme, host and port, and all three must match. The Host header is not used: only
	 * the given origins count. An entry without a scheme matches that host over http and https.
	 *
	 * @param array<string, mixed> $server      $_SERVER (REQUEST_METHOD is read from it).
	 * @param string[]             $own_origins Origins (or bare host names) that count as this site.
	 * @return string One of the class constants.
	 */
	public static function from_server( array $server, array $own_origins ): string {
		$own = array();
		foreach ( $own_origins as $entry ) {
			foreach ( self::origins_of( (string) $entry ) as $canonical ) {
				$own[ $canonical ] = true;
			}
		}

		$post   = 'POST' === strtoupper( (string) ( $server['REQUEST_METHOD'] ?? '' ) );
		$origin = trim( (string) ( $server['HTTP_ORIGIN'] ?? '' ) );
		$null   = 'null' === strtolower( $origin );
		$mine   = '' !== $origin && ! $null && self::is_own( $origin, $own );

		$site = strtolower( trim( (string) ( $server['HTTP_SEC_FETCH_SITE'] ?? '' ) ) );
		if ( in_array( $site, array( self::CROSS_SITE, self::SAME_SITE ), true ) ) {
			return $mine ? self::SAME_ORIGIN : $site;
		}
		if ( in_array( $site, array( self::SAME_ORIGIN, self::NONE ), true ) ) {
			return $site;
		}

		if ( $null ) {
			return $post ? self::CROSS_SITE : self::UNKNOWN;
		}
		if ( '' !== $origin ) {
			return '' === self::origin_of( $origin ) ? self::UNKNOWN : ( $mine ? self::SAME_ORIGIN : self::CROSS_SITE );
		}
		if ( ! $post ) {
			$referer = trim( (string) ( $server['HTTP_REFERER'] ?? '' ) );
			if ( '' !== self::origin_of( $referer ) ) {
				return self::is_own( $referer, $own ) ? self::SAME_ORIGIN : self::CROSS_SITE;
			}
		}
		return self::UNKNOWN;
	}

	/**
	 * Is the request a visitor's own top-level navigation (a link click or typed address)?
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 */
	public static function is_navigation( array $server ): bool {
		return 'navigate' === strtolower( trim( (string) ( $server['HTTP_SEC_FETCH_MODE'] ?? '' ) ) )
			&& 'document' === strtolower( trim( (string) ( $server['HTTP_SEC_FETCH_DEST'] ?? '' ) ) );
	}

	/**
	 * Is the URL's origin one of the given canonical origins?
	 *
	 * @param string              $url Origin or URL.
	 * @param array<string, true> $own Canonical origins.
	 */
	private static function is_own( string $url, array $own ): bool {
		$origin = self::origin_of( $url );
		return '' !== $origin && isset( $own[ $origin ] );
	}

	/**
	 * The canonical origin of a URL: "scheme://host" plus ":port" unless it is the scheme's default.
	 * Empty when the value has no scheme and host.
	 *
	 * @param string $url Origin or URL.
	 */
	public static function origin_of( string $url ): string {
		$parts = self::split( $url );
		return null === $parts || '' === $parts[0] ? '' : self::canonical( $parts[0], $parts[1], $parts[2] );
	}

	/**
	 * Canonical origins for a configured entry: a URL or origin gives one, a bare host gives http and https.
	 *
	 * @param string $entry Entry.
	 * @return string[]
	 */
	private static function origins_of( string $entry ): array {
		$entry = trim( $entry );
		if ( '' === $entry ) {
			return array();
		}
		if ( false !== strpos( $entry, '//' ) ) {
			$origin = self::origin_of( $entry );
			return '' === $origin ? array() : array( $origin );
		}
		$parts = self::split( '//' . $entry );
		if ( null === $parts ) {
			return array();
		}
		return array( self::canonical( 'http', $parts[1], $parts[2] ), self::canonical( 'https', $parts[1], $parts[2] ) );
	}

	/**
	 * Split a URL into scheme, host and port.
	 *
	 * @param string $url URL.
	 * @return array{0: string, 1: string, 2: int|null}|null
	 */
	private static function split( string $url ): ?array {
		$url = trim( $url );
		if ( '' === $url ) {
			return null;
		}
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- pure-PHP class unit-tested without WordPress; only scheme, host and port are read.
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return null;
		}
		return array(
			strtolower( (string) ( $parts['scheme'] ?? '' ) ),
			strtolower( trim( (string) $parts['host'], '[]' ) ),
			isset( $parts['port'] ) ? (int) $parts['port'] : null,
		);
	}

	/**
	 * Build "scheme://host[:port]", leaving out the scheme's default port.
	 *
	 * @param string   $scheme http or https.
	 * @param string   $host   Lowercase host.
	 * @param int|null $port   Port, or null.
	 */
	private static function canonical( string $scheme, string $host, ?int $port ): string {
		$default = 'https' === $scheme ? 443 : 80;
		return $scheme . '://' . $host . ( null === $port || $default === $port ? '' : ':' . $port );
	}

	/**
	 * Does the request announce itself as a page's own image, script, stylesheet, font or media load?
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 */
	public static function is_subresource_load( array $server ): bool {
		return isset( self::SUBRESOURCES[ strtolower( trim( (string) ( $server['HTTP_SEC_FETCH_DEST'] ?? '' ) ) ) ] );
	}

	/**
	 * Is it such a load AND does the path have an extension that fits the destination?
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 * @param string               $path   Normalised request path.
	 */
	public static function is_subresource( array $server, string $path ): bool {
		$dest = strtolower( trim( (string) ( $server['HTTP_SEC_FETCH_DEST'] ?? '' ) ) );
		return isset( self::SUBRESOURCES[ $dest ] ) && 1 === preg_match( '/\.(' . self::SUBRESOURCES[ $dest ] . ')$/i', $path );
	}
}
