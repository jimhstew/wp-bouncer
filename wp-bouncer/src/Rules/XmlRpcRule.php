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

		$method = self::method_name( $request->body() );
		if ( null !== $method && in_array( strtolower( $method ), self::ABUSED_METHODS, true ) ) {
			return $this->deny( sprintf( 'XML-RPC method %s is disabled', $method ) );
		}
		return null;
	}

	/**
	 * Pull <methodName> out of an XML-RPC payload without a full XML parse.
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
