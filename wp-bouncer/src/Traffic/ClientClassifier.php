<?php
/**
 * Sorts visitors into client types by their User-Agent.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Traffic;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP. The User-Agent is whatever the client says it is, so this is a
 * label for reading the log, never a basis for trusting a request.
 *
 * Checked in order; the first match wins.
 */
final class ClientClassifier {

	public const UNKNOWN       = 'unknown';
	public const SCANNER       = 'scanner';
	public const SEARCH_ENGINE = 'search_engine';
	public const MONITOR       = 'monitor';
	public const FEED          = 'feed';
	public const BOT           = 'bot';
	public const WORDPRESS     = 'wordpress';
	public const TOOL          = 'tool';
	public const MOBILE        = 'mobile';
	public const BROWSER       = 'browser';
	public const OTHER         = 'other';

	/** Type => pattern. */
	private const PATTERNS = array(
		self::SCANNER       => '/sqlmap|nikto|wpscan|nuclei|masscan|zgrab|nmap|acunetix|netsparker|dirbuster|gobuster|ffuf|wfuzz|whatweb|openvas|nessus|jorgee|zmeu/i',
		self::SEARCH_ENGINE => '/googlebot|google-inspectiontool|bingbot|duckduckbot|baiduspider|yandexbot|yandex\.com\/bots|applebot|slurp|petalbot|seznambot|qwantify|sogou|exabot/i',
		self::MONITOR       => '/uptimerobot|pingdom|statuscake|site24x7|newrelicpinger|betteruptime|uptime-kuma|uptimekuma|freshping|hetrixtools|jetpack|monitis|checkly/i',
		self::FEED          => '/feedly|inoreader|newsblur|feedbin|feedburner|feedfetcher|tiny tiny rss|netnewswire|feedvalidator|\brss\b/i',
		self::BOT           => '/bot\b|bot\/|crawl|spider|scrape|facebookexternalhit|embedly|preview|ahrefs|semrush|mj12|dotbot|gptbot|chatgpt|claude|anthropic|bytespider|ccbot|perplexity|amazonbot|meta-externalagent|archive\.org/i',
		self::WORDPRESS     => '/^WordPress\//i',
		self::TOOL          => '/^curl\/|wget|python|go-http-client|^java\/|okhttp|libwww|httpclient|axios|node-fetch|undici|guzzle|postman|powershell|ruby|^php\/|httpie|aiohttp|requests\//i',
	);

	/**
	 * Client type for a User-Agent.
	 *
	 * @param string $user_agent User-Agent header.
	 * @return string One of the constants.
	 */
	public static function classify( string $user_agent ): string {
		$ua = trim( $user_agent );
		if ( '' === $ua ) {
			return self::UNKNOWN;
		}
		foreach ( self::PATTERNS as $type => $pattern ) {
			if ( preg_match( $pattern, $ua ) ) {
				return $type;
			}
		}
		if ( preg_match( '/^(Mozilla|Opera)\//', $ua ) ) {
			return preg_match( '/Mobile|Android|iPhone|iPad|iPod|Windows Phone/', $ua ) ? self::MOBILE : self::BROWSER;
		}
		return self::OTHER;
	}

	/**
	 * List the client types.
	 *
	 * @return string[] Every type, in display order.
	 */
	public static function types(): array {
		return array( self::BROWSER, self::MOBILE, self::SEARCH_ENGINE, self::BOT, self::MONITOR, self::FEED, self::WORDPRESS, self::TOOL, self::SCANNER, self::UNKNOWN, self::OTHER );
	}
}
