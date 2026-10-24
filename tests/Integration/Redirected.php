<?php
/**
 * Thrown by the wp_redirect filter so handlers that redirect and exit can be tested.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

/** A redirect that would have happened. */
final class Redirected extends \RuntimeException {

	/** @var string */
	public $location;

	/**
	 * @param string $location Target URL.
	 * @param int    $status   HTTP status.
	 */
	public function __construct( string $location, int $status = 302 ) {
		parent::__construct( 'Redirected to ' . $location, $status );
		$this->location = $location;
	}

	/** Decoded wpb_msg query argument, '' if none. */
	public function message(): string {
		$query = (string) wp_parse_url( $this->location, PHP_URL_QUERY );
		parse_str( $query, $args );
		return isset( $args['wpb_msg'] ) ? rawurldecode( (string) $args['wpb_msg'] ) : '';
	}

	/** Did the redirect carry the error flag? */
	public function is_error(): bool {
		return false !== strpos( $this->location, 'wpb_err=1' );
	}
}
