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

	/** Patterns beyond this many are ignored at runtime. */
	public const MAX_PATTERNS = 100;

	/** Regex patterns only see this many bytes of the User-Agent. */
	private const MAX_REGEX_SUBJECT = 1024;

	/**
	 * PCRE failures seen while matching: pattern => preg_last_error() code.
	 *
	 * @var array<string, int>
	 */
	private static $errors = array();

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

		foreach ( array_slice( array_values( (array) $this->setting( 'patterns', array() ) ), 0, self::MAX_PATTERNS ) as $pattern ) {
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
	 * A regex that fails (backtrack limit, bad pattern) is treated as no
	 * match, not as a block: these patterns are written by an administrator,
	 * and failing closed on a bad one would refuse every visitor. The failure
	 * is available from last_errors().
	 *
	 * @param string $ua      User-Agent.
	 * @param string $pattern Substring or /regex/.
	 */
	public static function matches( string $ua, string $pattern ): bool {
		if ( self::is_regex( $pattern ) ) {
			$result = @preg_match( $pattern, substr( $ua, 0, self::MAX_REGEX_SUBJECT ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- a pattern that does not compile warns; it is recorded below.
			if ( false === $result ) {
				self::$errors[ $pattern ] = preg_last_error();
			}
			return 1 === $result;
		}
		return false !== stripos( $ua, $pattern );
	}

	/**
	 * Regex patterns that failed since the last reset.
	 *
	 * @return array<string, int> Pattern => preg_last_error() code.
	 */
	public static function last_errors(): array {
		return self::$errors;
	}

	/** Forget recorded PCRE failures. */
	public static function reset_errors(): void {
		self::$errors = array();
	}
}
