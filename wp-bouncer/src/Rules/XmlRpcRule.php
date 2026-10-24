<?php
/**
 * Blocks XML-RPC, either completely or just the methods attackers abuse.
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
 * - mode ("block_all"|"block_abuse"):
 *     block_all   refuses every request to xmlrpc.php.
 *     block_abuse lets XML-RPC clients (e.g. the Jetpack and mobile apps) work, but refuses
 *                 system.multicall (used to try hundreds of passwords in one request)
 *                 and pingback.ping (used for DDoS reflection).
 *
 * Plugin.php also switches XML-RPC off through the xmlrpc_enabled filter and
 * removes the X-Pingback header while this rule is on.
 */
final class XmlRpcRule extends AbstractRule {

	public const ID = 'xmlrpc';

	/** IXR refuses messages with more elements than this. */
	private const MAX_ELEMENTS = 30000;

	/** Methods refused in block_abuse mode. */
	public const ABUSED_METHODS = array( 'system.multicall', 'pingback.ping', 'pingback.extensions.getpingbacks' );

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
		if ( ! $request->is_xmlrpc() ) {
			return null;
		}

		if ( 'block_abuse' !== $this->setting( 'mode', 'block_all' ) ) {
			return $this->deny( 'XML-RPC is disabled' );
		}

		$stream = $request->body_stream();
		if ( null === $stream ) {
			return $this->deny( 'XML-RPC request could not be inspected' );
		}
		$methods = self::method_names_from_stream( $stream );
		fclose( $stream ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- request body stream.
		if ( null === $methods ) {
			return $this->deny( 'XML-RPC request could not be inspected' );
		}
		foreach ( $methods as $method ) {
			if ( in_array( strtolower( $method ), self::ABUSED_METHODS, true ) ) {
				return $this->deny( sprintf( 'XML-RPC method %s is disabled', $method ) );
			}
		}
		return null;
	}

	/**
	 * Every <methodName> in an XML-RPC payload, read the way WordPress's IXR library reads it.
	 *
	 * @see self::method_names_from_stream()
	 *
	 * @param string $body Raw request body.
	 * @return string[]|null Null when the request must be refused.
	 */
	public static function method_names( string $body ): ?array {
		$stream = fopen( 'php://memory', 'w+b' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- in-memory stream, not a file.
		if ( false === $stream ) {
			return null;
		}
		fwrite( $stream, $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- in-memory stream.
		rewind( $stream );
		$names = self::method_names_from_stream( $stream );
		fclose( $stream ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- in-memory stream.
		return $names;
	}

	/**
	 * Every <methodName> in an XML-RPC payload read from a stream, in chunks.
	 *
	 * IXR strips the XML declaration from the first 100 bytes, trims the
	 * message, parses it with ext/xml, resets its text buffer on every tag and
	 * keeps the last methodName. This does the same, and returns every name.
	 * The body is never held in memory whole, so a large upload (a
	 * wp.uploadFile / metaWeblog.newMediaObject call) is parsed like any other
	 * request. Text is kept up to a small cap, per tag, as IXR does.
	 *
	 * Returns null when the request must be refused: it holds a DOCTYPE or
	 * ENTITY declaration, or it does not parse (IXR would reject it too, so
	 * refusing costs no legitimate client anything). An empty body gives an
	 * empty list. If ext/xml is missing, the old regex is used on the first 1 MB.
	 *
	 * @param resource $stream Readable stream positioned at the start of the body.
	 * @return string[]|null
	 */
	public static function method_names_from_stream( $stream ): ?array {
		// Same normalisation as IXR_Message::parse(): strip the declaration from the first 100 bytes, trim.
		$first = '';
		$have  = 0;
		while ( $have < 100 && ! feof( $stream ) ) {
			$read = fread( $stream, 8192 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads a request body stream.
			if ( false === $read || '' === $read ) {
				break;
			}
			$first .= $read;
			$have  += strlen( $read );
		}
		$header = preg_replace( '/<\?xml.*?\?' . '>/s', '', substr( $first, 0, 100 ), 1 );
		$first  = ltrim( (string) $header . (string) substr( $first, 100 ) );
		while ( '' === $first && ! feof( $stream ) ) {
			$read  = fread( $stream, 8192 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads a request body stream.
			$first = false === $read ? '' : ltrim( $read );
		}
		if ( '' === $first ) {
			return array();
		}

		$have_xml     = function_exists( 'xml_parser_create' );
		$state        = new \stdClass();
		$state->names = array();
		$state->text  = '';
		$state->count = 0;
		$parser       = null;
		if ( $have_xml ) {
			$parser = xml_parser_create();
			xml_parser_set_option( $parser, XML_OPTION_CASE_FOLDING, false );
			// Exactly as IXR: the text buffer is reset on every opening and closing tag,
			// and the name is whatever text sits directly before a closing methodName tag.
			xml_set_element_handler(
				$parser,
				static function () use ( $state ) {
					$state->text = '';
					++$state->count;
				},
				static function ( $p, $tag ) use ( $state ) {
					if ( 'methodName' === $tag ) {
						$state->names[] = trim( $state->text );
					}
					$state->text = '';
				}
			);
			xml_set_character_data_handler(
				$parser,
				static function ( $p, $data ) use ( $state ) {
					// Leading space is dropped and the length capped, so a huge base64 value costs no memory.
					// A name longer than the cap cannot be one of the refused methods.
					if ( strlen( $state->text ) < 1024 ) {
						$state->text .= '' === $state->text ? ltrim( $data ) : $data;
					}
				}
			);
		}

		$chunk = $first;
		$carry = '';
		$sniff = '';
		do {
			// A DOCTYPE or ENTITY declaration may straddle two chunks.
			$scan = $carry . $chunk;
			if ( 1 === preg_match( '/<!DOCTYPE|<!ENTITY/i', $scan ) ) {
				return null;
			}
			$carry = substr( $scan, -16 );
			if ( null === $parser && strlen( $sniff ) < 1048576 ) {
				$sniff .= $chunk;
			}
			if ( null !== $parser && ( 1 !== xml_parse( $parser, $chunk, false ) || $state->count > self::MAX_ELEMENTS ) ) {
				return null; // Does not parse, or more elements than IXR accepts.
			}
			$chunk = '';
			if ( ! feof( $stream ) ) {
				$read  = fread( $stream, 65536 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads a request body stream.
				$chunk = false === $read ? '' : $read;
			}
		} while ( '' !== $chunk || ! feof( $stream ) );

		if ( null === $parser ) {
			$method = self::method_name( $sniff );
			return null === $method ? array() : array( $method );
		}
		if ( 1 !== xml_parse( $parser, '', true ) || $state->count > self::MAX_ELEMENTS ) {
			return null;
		}
		return array_values(
			array_filter(
				$state->names,
				static function ( string $name ): bool {
					return '' !== $name;
				}
			)
		);
	}

	/**
	 * Pull <methodName> out of an XML-RPC payload with a regex (fallback).
	 *
	 * @param string $body Raw request body.
	 */
	public static function method_name( string $body ): ?string {
		if ( preg_match( '#<methodName>\s*([^<\s]+)\s*</methodName>#i', $body, $m ) ) {
			return $m[1];
		}
		return null;
	}
}
