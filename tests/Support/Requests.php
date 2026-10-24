<?php
/**
 * Concise Request builder for tests.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Firewall\Request;

/**
 * Requests::make( [ 'uri' => '/wp-login.php', 'method' => 'POST' ] ).
 */
final class Requests {

	/**
	 * Build a request with sensible defaults.
	 *
	 * @param array<string, mixed> $args {
	 *     @type string $ip, $method, $uri, $ua, $body
	 *     @type array  $query, $post, $server
	 *     @type bool   $logged_in, $trusted, $local, $bannable
	 * }
	 */
	public static function make( array $args = array() ): Request {
		$server = $args['server'] ?? array();
		if ( array_key_exists( 'ua', $args ) ) {
			$server['HTTP_USER_AGENT'] = $args['ua'];
		} elseif ( ! isset( $server['HTTP_USER_AGENT'] ) ) {
			$server['HTTP_USER_AGENT'] = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0';
		}

		$logged_in = (bool) ( $args['logged_in'] ?? false );
		$trusted   = (bool) ( $args['trusted'] ?? false );
		$body      = (string) ( $args['body'] ?? '' );

		return new Request(
			array(
				'ip'        => $args['ip'] ?? '203.0.113.10',
				'method'    => $args['method'] ?? 'GET',
				'uri'       => $args['uri'] ?? '/',
				'query'     => $args['query'] ?? array(),
				'post'      => $args['post'] ?? array(),
				'server'    => $server,
				'logged_in' => static function () use ( $logged_in ) {
					return $logged_in;
				},
				'trusted'   => static function () use ( $trusted ) {
					return $trusted;
				},
				'local'     => (bool) ( $args['local'] ?? false ),
				'bannable'  => (bool) ( $args['bannable'] ?? true ),
				'subject'   => (string) ( $args['subject'] ?? '' ),
				'body'      => static function () use ( $body ) {
					return $body;
				},
			)
		);
	}
}
