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

	/** Characters or words without which no built-in signature can match (used to skip big, plain values). */
	private const GATE = '/[<\'"`;(%:|&=#$\/\\\\_{]|union|into|document|wp-config/i';

	/** Size of one scan window. */
	private const WINDOW = 8192;

	/** Windows overlap by this much, so a signature can't hide on a boundary. */
	private const OVERLAP = 1024;

	/** Values up to this size are scanned in full; longer ones get the first part plus the last window. */
	private const MAX_VALUE_LENGTH = 65536;

	/**
	 * The most recent PCRE failure: signature name and preg_last_error() code.
	 *
	 * @var array{0: string, 1: int}|null
	 */
	private static $last_error = null;

	/**
	 * Signatures by category. Keys are short names written to the log.
	 *
	 * @var array<string, array<string, string>>
	 */
	public const SIGNATURES = array(
		'sqli'           => array(
			'union select'        => '/\bunion\b[\s\/\*\(\)]{1,200}(all\b[\s\/\*\(\)]{1,200})?select\b/i',
			'tautology'           => '/[\'"`]\s{0,64}(or|and|\|\||&&)\s{0,64}[\'"`]?\s{0,64}\d{1,32}\s{0,64}[\'"`]?\s{0,64}=\s{0,64}[\'"`]?\s{0,64}\d/i',
			'time-based'          => '/\b(sleep|benchmark|pg_sleep)\s{0,64}\(\s{0,64}\d/i',
			'waitfor delay'       => '/\bwaitfor\s{1,64}delay\s{1,64}[\'"]/i',
			'information_schema'  => '/\binformation_schema\b/i',
			'file read/write'     => '/\b(load_file\s{0,64}\(|into\s{1,64}(out|dump)file\b)/i',
			'stacked destructive' => '/;\s{0,64}(drop|truncate|alter)\s{1,64}table\b/i',
			'comment terminator'  => '/[\'"]\s{0,64}(--|#|\/\*)\s{0,64}$/',
		),
		'xss'            => array(
			'script tag'     => '/<\s{0,64}script\b/i',
			'javascript uri' => '/\bjavascript\s{0,64}:/i',
			'event handler'  => '/<[a-z][^>]{0,800}[\s\/]on[a-z]{3,20}\s{0,16}=/i',
			'embed tag'      => '/<\s{0,64}(iframe|object|embed|applet|base|meta)\b/i',
			'cookie access'  => '/\bdocument\s{0,64}\.\s{0,64}(cookie|domain)\b/i',
		),
		'traversal'      => array(
			'dot-dot-slash'   => '/(\.\.[\/\\\\]){2}/',
			'system file'     => '/\/etc\/(passwd|shadow|group|hosts)\b/i',
			'wp-config probe' => '/(^|=|\.\.[\/\\\\])wp-config\.php/i',
			'php wrapper'     => '/\b(php|phar|expect|zip|glob):\/\//i',
		),
		'code_injection' => array(
			'php open tag'  => '/<\?(php|=)/i',
			'php exec call' => '/\b(eval|assert|shell_exec|passthru|proc_open|base64_decode)\s{0,64}\(/i',
			'backtick exec' => '/`\s{0,64}(wget|curl|bash|sh|nc)\s/i',
			'jndi lookup'   => '/\$\{\s{0,64}jndi\s{0,64}:/i',
			'shell chain'   => '/[;&|]\s{0,64}(wget|curl)\s{1,64}https?:\/\//i',
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

		self::$last_error = null;

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
	 * Values up to 64 KB are scanned in 8 KB windows that overlap by 1 KB;
	 * longer values also get their last 8 KB scanned. Every quantifier in the
	 * signatures is bounded so that no match is longer than the overlap, which
	 * means a payload cannot hide on a window boundary. Each window is scanned
	 * with one byte of left context, so "\b" and "^" do not fire at an artificial
	 * edge, and "$" only counts in the window that ends the value. Each window is
	 * also checked after one more round of URL decoding.
	 *
	 * A PCRE failure (backtrack limit, JIT stack) counts as a match, with the
	 * signature name "pattern error (<name>)", so an attacker can't switch the
	 * WAF off by tripping the engine. The failure is available from last_error().
	 *
	 * Signatures must not use the /u modifier: invalid UTF-8 would then be a
	 * PCRE error, and so a block, for every binary value.
	 *
	 * @param string                               $value      Value.
	 * @param array<string, array<string, string>> $categories Signature groups.
	 * @return array{0: string, 1: string}|null [category, signature name] on match.
	 */
	public static function match_value( string $value, array $categories ): ?array {
		$large = strlen( $value ) > self::WINDOW;
		foreach ( self::windows( $value ) as $window ) {
			// Cheap gate for big values: every signature needs one of these characters or words.
			if ( $large && 1 !== preg_match( self::GATE, $window['text'] ) ) {
				continue;
			}

			$subjects = array( array( $window['context'] . $window['text'], strlen( $window['context'] ) ) );
			if ( false !== strpos( $window['text'], '%' ) ) {
				$decoded = rawurldecode( $window['text'] );
				if ( $decoded !== $window['text'] ) {
					$subjects[] = array( $window['context'] . $decoded, strlen( $window['context'] ) );
				}
			}

			foreach ( $subjects as $subject ) {
				foreach ( $categories as $category => $signatures ) {
					foreach ( $signatures as $name => $regex ) {
						// "$" would match at the end of a window that is not the end of the value.
						if ( ! $window['last'] && 1 === preg_match( '/\$\/[a-z]*$/', $regex ) ) {
							continue;
						}
						$result = preg_match( $regex, $subject[0], $unused, 0, $subject[1] );
						if ( 1 === $result ) {
							return array( $category, $name );
						}
						if ( false === $result ) {
							self::$last_error = array( $name, preg_last_error() );
							return array( $category, 'pattern error (' . $name . ')' );
						}
					}
				}
			}
		}
		return null;
	}

	/**
	 * Split a value into the windows that are scanned.
	 *
	 * @param string $value Value.
	 * @return array<int, array{text: string, context: string, last: bool}> Window text, the byte before it, and whether it ends the value.
	 */
	private static function windows( string $value ): array {
		$length = strlen( $value );
		if ( $length <= self::WINDOW ) {
			return array(
				array(
					'text'    => $value,
					'context' => '',
					'last'    => true,
				),
			);
		}

		$limit   = min( $length, self::MAX_VALUE_LENGTH );
		$step    = self::WINDOW - self::OVERLAP;
		$windows = array();
		for ( $start = 0; $start < $limit; $start += $step ) {
			$windows[] = self::window_at( $value, $start );
			if ( $start + self::WINDOW >= $limit ) {
				break;
			}
		}
		if ( $length > self::MAX_VALUE_LENGTH ) {
			$windows[] = self::window_at( $value, $length - self::WINDOW );
		}
		return $windows;
	}

	/**
	 * One window plus its left-context byte.
	 *
	 * If the window starts inside a %XX escape the context is a neutral letter,
	 * so decoding the window cannot misalign it.
	 *
	 * @param string $value Whole value.
	 * @param int    $start Window start.
	 * @return array{text: string, context: string, last: bool}
	 */
	private static function window_at( string $value, int $start ): array {
		$context = '';
		if ( $start > 0 ) {
			$context = $value[ $start - 1 ];
			if ( '%' === $context || ( $start > 1 && '%' === $value[ $start - 2 ] ) ) {
				$context = 'a';
			}
		}
		return array(
			'text'    => substr( $value, $start, self::WINDOW ),
			'context' => $context,
			'last'    => $start + self::WINDOW >= strlen( $value ),
		);
	}

	/**
	 * The most recent PCRE failure seen by match_value(), if any.
	 *
	 * @return array{0: string, 1: int}|null [signature name, preg_last_error() code].
	 */
	public static function last_error(): ?array {
		return self::$last_error;
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
