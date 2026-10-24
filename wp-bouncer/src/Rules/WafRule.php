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

	/** Name of the event-handler signature, which is checked in code (see event_handler_hit()). */
	private const EVENT_HANDLER = 'event handler';

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
			'event handler'  => '/[\s\/"\']on[a-z]{3,20}\s{0,16}=/i',
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
	 * The value is first normalised: runs of whitespace and complete SQL/C
	 * comments collapse to one space, so padding (the word "union", 300 spaces or
	 * empty comments, then "select") cannot push a signature out of reach of its
	 * bounded quantifiers. If it holds "%", a URL-decoded copy is normalised and
	 * checked too (one extra decode level, R-04).
	 *
	 * Each copy up to 64 KB is scanned in 8 KB windows that overlap by 1 KB;
	 * longer ones also get their last 8 KB scanned. Every quantifier in the
	 * signatures is bounded so that no match is longer than the overlap, which
	 * means a payload cannot hide on a window boundary. Each window is scanned
	 * with one byte of left context, so "\b" and "^" do not fire at an artificial
	 * edge, and "$" only counts in the window that ends the value.
	 *
	 * The event-handler signature has no distance bound: it finds " onxxx=" and
	 * then checks in code that an unclosed "<tag" comes before it.
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
		$variants = array( self::normalise( $value ) );
		if ( false !== strpos( $value, '%' ) ) {
			$decoded = self::normalise( rawurldecode( $value ) );
			if ( $decoded !== $variants[0] ) {
				$variants[] = $decoded;
			}
		}

		foreach ( $variants as $variant ) {
			$hit = self::scan_variant( $variant, $categories );
			if ( null !== $hit ) {
				return $hit;
			}
		}
		return null;
	}

	/**
	 * Collapse whitespace runs and complete C-style comments to one space.
	 *
	 * MySQL executes the inside of a comment that opens with slash, star, exclamation
	 * mark (optionally followed by a five-digit version), so those comments are unwrapped
	 * first: the markers go and the inner text stays, so a split word is joined again. An unterminated one is unwrapped to the end of the text. Nested forms
	 * are unwrapped one level per pass, at most four passes. Every pattern is linear.
	 *
	 * @param string $value Value.
	 */
	private static function normalise( string $value ): string {
		for ( $pass = 0; $pass < 4; $pass++ ) {
			if ( false === strpos( $value, '/*!' ) ) {
				break;
			}
			$unwrapped = preg_replace( '~/\*!\d*+((?:[^*]++|\*(?!/))*+)(?:\*/|$)~', '$1 ', $value );
			if ( null === $unwrapped || $unwrapped === $value ) {
				break;
			}
			$value = $unwrapped;
		}
		// No comment can end after the last closing marker, so only look for comments before it.
		// An opener with no closer would otherwise be scanned to the end once per opener, which is quadratic.
		$cut  = strrpos( $value, '*/' );
		$head = false === $cut ? '' : substr( $value, 0, $cut + 2 );
		$tail = false === $cut ? $value : (string) substr( $value, $cut + 2 );
		$head = '' === $head ? '' : preg_replace( '~(?:\s++|/\*(?:[^*]++|\*(?!/))*+\*/)++~', ' ', $head );
		$tail = preg_replace( '~\s++~', ' ', $tail );
		return null === $head || null === $tail ? $value : $head . $tail;
	}

	/**
	 * Run the signatures over one normalised copy of a value.
	 *
	 * @param string                               $text       Normalised text.
	 * @param array<string, array<string, string>> $categories Signature groups.
	 * @return array{0: string, 1: string}|null
	 */
	private static function scan_variant( string $text, array $categories ): ?array {
		$large = strlen( $text ) > self::WINDOW;
		foreach ( self::windows( $text ) as $window ) {
			// Cheap gate for big values: every signature needs one of these characters or words.
			if ( $large && 1 !== preg_match( self::GATE, $window['text'] ) ) {
				continue;
			}

			$subject = $window['context'] . $window['text'];
			$offset  = strlen( $window['context'] );
			foreach ( $categories as $category => $signatures ) {
				foreach ( $signatures as $name => $regex ) {
					if ( self::EVENT_HANDLER === $name ) {
						continue; // Handled below, without a distance bound.
					}
					// "$" would match at the end of a window that is not the end of the value.
					if ( ! $window['last'] && 1 === preg_match( '/\$\/[a-z]*$/', $regex ) ) {
						continue;
					}
					$result = preg_match( $regex, $subject, $unused, 0, $offset );
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

		foreach ( $categories as $category => $signatures ) {
			if ( isset( $signatures[ self::EVENT_HANDLER ] ) ) {
				$hit = self::event_handler_hit( $text, $signatures[ self::EVENT_HANDLER ] );
				if ( null !== $hit ) {
					return array( $category, $hit );
				}
			}
		}
		return null;
	}

	/**
	 * Find an event-handler attribute (" onerror=") inside an unclosed tag, whatever the distance from "<tag".
	 *
	 * Scans the first 64 KB and, for longer text, the last 8 KB.
	 *
	 * @param string $text  Normalised text.
	 * @param string $regex The handler signature.
	 * @return string|null The signature name, "pattern error (...)", or null.
	 */
	private static function event_handler_hit( string $text, string $regex ): ?string {
		$length   = strlen( $text );
		$segments = array( substr( $text, 0, self::MAX_VALUE_LENGTH ) );
		if ( $length > self::MAX_VALUE_LENGTH ) {
			$segments[] = substr( $text, -self::WINDOW );
		}
		foreach ( $segments as $segment ) {
			$found = preg_match_all( $regex, $segment, $all, PREG_OFFSET_CAPTURE );
			if ( false === $found ) {
				self::$last_error = array( self::EVENT_HANDLER, preg_last_error() );
				return 'pattern error (' . self::EVENT_HANDLER . ')';
			}
			if ( 0 === $found ) {
				continue;
			}
			// Position of the attribute name (one past the leading space, slash or quote).
			$candidates = array();
			foreach ( $all[0] as $match ) {
				$candidates[] = (int) $match[1] + 1;
			}
			if ( self::candidate_inside_tag( $segment, $candidates ) ) {
				return self::EVENT_HANDLER;
			}
		}
		return null;
	}

	/**
	 * Is any of the (sorted) positions inside an open tag, outside a quoted attribute value?
	 *
	 * One pass over the text. A tag opens at "<" plus a letter and closes at ">".
	 * A quote only starts a value straight after "=", as in HTML, so a stray quote
	 * inside an unquoted value (src=x"onerror=...) does not hide anything, and a
	 * ">" inside a quoted value does not close the tag.
	 *
	 * @param string $text       Text.
	 * @param int[]  $candidates Ascending positions to test.
	 */
	private static function candidate_inside_tag( string $text, array $candidates ): bool {
		$length = strlen( $text );
		$count  = count( $candidates );
		$state  = 'out';
		$quote  = '';
		$i      = 0;
		$ci     = 0;
		while ( $ci < $count ) {
			$end  = $length;
			$next = $length;
			$m    = array();
			if ( 'out' === $state ) {
				if ( 1 === preg_match( '/<[a-z]/i', $text, $m, PREG_OFFSET_CAPTURE, $i ) ) {
					$end  = (int) $m[0][1];
					$next = $end + 2;
				}
			} elseif ( 'tag' === $state ) {
				if ( 1 === preg_match( '/>|=\s*(["\'])/', $text, $m, PREG_OFFSET_CAPTURE, $i ) ) {
					$end  = (int) $m[0][1];
					$next = $end + strlen( $m[0][0] );
				}
			} else {
				$pos = strpos( $text, $quote, $i );
				if ( false !== $pos ) {
					$end  = $pos;
					$next = $pos + 1;
				}
			}

			// Candidates in the stretch [i, end) are in the current state.
			while ( $ci < $count && $candidates[ $ci ] < $end ) {
				if ( 'tag' === $state && $candidates[ $ci ] >= $i ) {
					return true;
				}
				++$ci;
			}
			if ( $end >= $length ) {
				break;
			}

			if ( 'out' === $state ) {
				$state = 'tag';
			} elseif ( 'tag' === $state ) {
				if ( '>' === $m[0][0] ) {
					$state = 'out';
				} else {
					$state = 'quote';
					$quote = $m[1][0];
				}
			} else {
				$state = 'tag';
			}
			$i = $next;
		}
		return false;
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
	 * @param string $value Whole value.
	 * @param int    $start Window start.
	 * @return array{text: string, context: string, last: bool}
	 */
	private static function window_at( string $value, int $start ): array {
		return array(
			'text'    => substr( $value, $start, self::WINDOW ),
			'context' => $start > 0 ? $value[ $start - 1 ] : '',
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
