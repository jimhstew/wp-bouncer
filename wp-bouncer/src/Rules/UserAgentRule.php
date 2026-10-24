<?php
/**
 * Blocks requests by User-Agent string.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;

defined( 'ABSPATH' ) || exit;

/**
 * Settings:
 * - enabled (bool)
 * - block_empty (bool): refuse requests with no User-Agent header at all.
 * - patterns (string[]): one per entry. "/regex/flags" is a PCRE pattern;
 *   anything else is a case-insensitive substring.
 */
final class UserAgentRule extends AbstractRule {

	public const ID = 'user_agent';

	/**
	 * Default patterns: well-known vulnerability scanners and attack tools.
	 * Kept short so legitimate crawlers and monitoring tools aren't caught.
	 */
	public const DEFAULT_PATTERNS = array(
		'sqlmap',
		'nikto',
		'wpscan',
		'masscan',
		'zgrab',
		'nmap scripting engine',
		'acunetix',
		'netsparker',
		'dirbuster',
		'gobuster',
		'nuclei',
		'havij',
		'fimap',
		'w3af',
		'jorgee',
	);

	/** {@inheritDoc} */
	public function id(): string {
		return self::ID;
	}

	/**
	 * Inspect the request.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function inspect( Request $request ): ?Verdict {
		$ua = trim( $request->user_agent() );

		if ( '' === $ua ) {
			return $this->setting( 'block_empty', false ) ? $this->deny( 'Empty User-Agent' ) : null;
		}

		foreach ( (array) $this->setting( 'patterns', array() ) as $pattern ) {
			$pattern = (string) $pattern;
			if ( '' !== $pattern && self::matches( $ua, $pattern ) ) {
				return $this->deny( sprintf( 'User-Agent matches "%s"', $pattern ) );
			}
		}
		return null;
	}

	/**
	 * Is the pattern written as a regex ("/.../flags")?
	 *
	 * @param string $pattern Pattern.
	 */
	public static function is_regex( string $pattern ): bool {
		return (bool) preg_match( '#^/.+/[imsxuU]*$#s', $pattern );
	}

	/**
	 * Match a User-Agent against one pattern.
	 *
	 * @param string $ua      User-Agent.
	 * @param string $pattern Substring or /regex/.
	 */
	public static function matches( string $ua, string $pattern ): bool {
		if ( self::is_regex( $pattern ) ) {
			return 1 === @preg_match( $pattern, $ua ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- invalid patterns are filtered on save.
		}
		return false !== stripos( $ua, $pattern );
	}
}
