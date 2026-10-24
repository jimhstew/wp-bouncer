<?php
/**
 * Thrown by the wp_redirect filter so handlers that redirect and exit can be tested.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

use WPBouncer\Admin\MessageCodes;

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

	/** The message code in the redirect, '' if none. */
	public function code(): string {
		return MessageCodes::from_query( $this->query() )[0];
	}

	/**
	 * The message text the admin would see for this redirect ('' if none).
	 *
	 * Consumes the server-side flash detail, so call it once per redirect and keep the result.
	 */
	public function message(): string {
		list( $code, $args ) = MessageCodes::from_query( $this->query() );
		if ( MessageCodes::uses_detail( $code ) ) {
			$args['detail'] = MessageCodes::take_flash();
		}
		return (string) MessageCodes::text( $code, $args );
	}

	/** @return array<string, mixed> */
	private function query(): array {
		parse_str( (string) wp_parse_url( $this->location, PHP_URL_QUERY ), $args );
		return $args;
	}

	/** Did the redirect carry the error flag? */
	public function is_error(): bool {
		return false !== strpos( $this->location, 'wpb_err=1' );
	}
}
