<?php
/**
 * Lightweight web application firewall: pattern rules for common attack payloads.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;

defined( 'ABSPATH' ) || exit;

/**
 * Scans the path, query string and POST body for SQL injection, XSS, path
 * traversal and PHP/code injection payloads.
 *
 * Settings:
 * - enabled (bool)
 * - sqli, xss, traversal, code_injection (bool): which categories are on.
 * - excluded_params (string[]): parameter names never inspected (e.g. a page
 *   builder field that legitimately carries HTML).
 *
 * Administrators are not inspected, because they legitimately post HTML and
 * scripts through the editor.
 *
 * This is a signature filter and won't catch everything. It stops the
 * automated, noisy attacks that make up most real-world traffic. Keeping
 * WordPress and plugins updated is still the main defence.
 */
final class WafRule extends AbstractRule {

	public const ID = 'waf';

	/** Values longer than this are truncated before matching, to bound regex cost. */
	private const MAX_VALUE_LENGTH = 8192;

	/**
	 * Signatures by category. Keys are short names written to the log.
	 *
	 * @var array<string, array<string, string>>
	 */
	public const SIGNATURES = array(
		'sqli'           => array(
			'union select'        => '/\bunion\b[\s\/\*\(\)]+(all\b[\s\/\*\(\)]+)?select\b/i',
			'tautology'           => '/[\'"`]\s*(or|and|\|\||&&)\s*[\'"`]?\s*\d+\s*[\'"`]?\s*=\s*[\'"`]?\s*\d+/i',
			'time-based'          => '/\b(sleep|benchmark|pg_sleep)\s*\(\s*\d/i',
			'waitfor delay'       => '/\bwaitfor\s+delay\s+[\'"]/i',
			'information_schema'  => '/\binformation_schema\b/i',
			'file read/write'     => '/\b(load_file\s*\(|into\s+(out|dump)file\b)/i',
			'stacked destructive' => '/;\s*(drop|truncate|alter)\s+table\b/i',
			'comment terminator'  => '/[\'"]\s*(--|#|\/\*)\s*$/',
		),
		'xss'            => array(
			'script tag'     => '/<\s*script\b/i',
			'javascript uri' => '/\bjavascript\s*:/i',
			'event handler'  => '/<[a-z][^>]*[\s\/]on[a-z]{3,}\s*=/i',
			'embed tag'      => '/<\s*(iframe|object|embed|applet|base|meta)\b/i',
			'cookie access'  => '/\bdocument\s*\.\s*(cookie|domain)\b/i',
		),
		'traversal'      => array(
			'dot-dot-slash'   => '/(\.\.[\/\\\\]){2,}/',
			'system file'     => '/\/etc\/(passwd|shadow|group|hosts)\b/i',
			'wp-config probe' => '/(^|=|\.\.[\/\\\\])wp-config\.php/i',
			'php wrapper'     => '/\b(php|phar|expect|zip|glob):\/\//i',
		),
		'code_injection' => array(
			'php open tag'  => '/<\?(php|=)/i',
			'php exec call' => '/\b(eval|assert|shell_exec|passthru|proc_open|base64_decode)\s*\(/i',
			'backtick exec' => '/`\s*(wget|curl|bash|sh|nc)\s/i',
			'jndi lookup'   => '/\$\{\s*jndi\s*:/i',
			'shell chain'   => '/[;&|]\s*(wget|curl)\s+https?:\/\//i',
		),
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
		if ( $request->is_trusted() ) {
			return null;
		}

		$categories = $this->active_categories();
		if ( empty( $categories ) ) {
			return null;
		}

		// The path is only checked for traversal; normal URLs can contain words such as "select".
		if ( isset( $categories['traversal'] ) ) {
			$hit = self::match_value( rawurldecode( $request->uri() ), array( 'traversal' => $categories['traversal'] ) );
			if ( null !== $hit ) {
				return $this->deny( sprintf( 'WAF %s (%s) in URL', $hit[0], $hit[1] ) );
			}
		}

		$excluded = array_map( 'strtolower', (array) $this->setting( 'excluded_params', array() ) );

		foreach ( array(
			'query' => $request->query(),
			'body'  => $request->post(),
		) as $source => $params ) {
			foreach ( self::flatten( $params ) as $name => $value ) {
				if ( in_array( strtolower( self::root_name( $name ) ), $excluded, true ) ) {
					continue;
				}
				$hit = self::match_value( $name . '=' . $value, $categories );
				if ( null !== $hit ) {
					return $this->deny( sprintf( 'WAF %s (%s) in %s parameter "%s"', $hit[0], $hit[1], $source, self::root_name( $name ) ) );
				}
			}
		}
		return null;
	}

	/**
	 * Signature groups switched on in settings.
	 *
	 * @return array<string, array<string, string>>
	 */
	private function active_categories(): array {
		$active = array();
		foreach ( self::SIGNATURES as $category => $signatures ) {
			if ( $this->setting( $category, true ) ) {
				$active[ $category ] = $signatures;
			}
		}
		return $active;
	}

	/**
	 * Test one value against the given signature groups.
	 *
	 * The value is also checked after one more round of URL decoding, which
	 * catches double-encoded payloads such as %253Cscript%253E.
	 *
	 * @param string                               $value      Value.
	 * @param array<string, array<string, string>> $categories Signature groups.
	 * @return array{0: string, 1: string}|null [category, signature name] on match.
	 */
	public static function match_value( string $value, array $categories ): ?array {
		$value    = substr( $value, 0, self::MAX_VALUE_LENGTH );
		$variants = array( $value );
		if ( false !== strpos( $value, '%' ) ) {
			$variants[] = rawurldecode( $value );
		}

		foreach ( $variants as $candidate ) {
			foreach ( $categories as $category => $signatures ) {
				foreach ( $signatures as $name => $regex ) {
					if ( 1 === preg_match( $regex, $candidate ) ) {
						return array( $category, $name );
					}
				}
			}
		}
		return null;
	}

	/**
	 * Flatten nested parameters: [ 'a' => [ 'b' => 'x' ] ] becomes [ 'a[b]' => 'x' ].
	 *
	 * @param array<mixed> $params Parameters.
	 * @param string       $prefix Key prefix for recursion.
	 * @return array<string, string>
	 */
	public static function flatten( array $params, string $prefix = '' ): array {
		$out = array();
		foreach ( $params as $key => $value ) {
			$name = '' === $prefix ? (string) $key : $prefix . '[' . $key . ']';
			if ( is_array( $value ) ) {
				$out += self::flatten( $value, $name );
			} elseif ( is_scalar( $value ) ) {
				$out[ $name ] = (string) $value;
			}
		}
		return $out;
	}

	/**
	 * Top-level parameter name: "meta[foo][bar]" becomes "meta".
	 *
	 * @param string $name Flattened name.
	 */
	private static function root_name( string $name ): string {
		$pos = strpos( $name, '[' );
		return false === $pos ? $name : substr( $name, 0, $pos );
	}
}
