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

		$methods = self::method_names( $request->body() );
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
	 * IXR strips the XML declaration from the first 100 bytes, trims the
	 * message, parses it with ext/xml, resets its text buffer on every tag and
	 * keeps the last methodName. This does the same, and returns every name.
	 *
	 * Returns null when the request must be refused: it holds a DOCTYPE or
	 * ENTITY declaration, or it does not parse (IXR would reject it too, so
	 * refusing costs no legitimate client anything). An empty body gives an
	 * empty list. If ext/xml is missing, the old regex is used.
	 *
	 * @param string $body Raw request body.
	 * @return string[]|null
	 */
	public static function method_names( string $body ): ?array {
		// Same normalisation as IXR_Message::parse().
		$header = preg_replace( '/<\?xml.*?\?' . '>/s', '', substr( $body, 0, 100 ), 1 );
		$body   = trim( (string) substr_replace( $body, (string) $header, 0, 100 ) );
		if ( '' === $body ) {
			return array();
		}
		if ( 1 === preg_match( '/<!DOCTYPE|<!ENTITY/i', $body ) ) {
			return null;
		}
		if ( ! function_exists( 'xml_parser_create' ) ) {
			$method = self::method_name( $body );
			return null === $method ? array() : array( $method );
		}

		$state        = new \stdClass();
		$state->names = array();
		$state->text  = '';
		$parser       = xml_parser_create();
		xml_parser_set_option( $parser, XML_OPTION_CASE_FOLDING, false );
		xml_set_element_handler(
			$parser,
			static function () use ( $state ) {
				$state->text = '';
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
				$state->text .= $data;
			}
		);
		if ( 1 !== xml_parse( $parser, $body, true ) ) {
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
