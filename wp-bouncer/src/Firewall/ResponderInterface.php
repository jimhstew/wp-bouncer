<?php
/**
 * Contract for turning a Verdict into an HTTP response.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Sends the "you're not getting in" response.
 */
interface ResponderInterface {

	/**
	 * Refuse the request. Production implementations end the request.
	 *
	 * @param Verdict $verdict   Why the request is refused.
	 * @param string  $message   Message shown to the visitor.
	 * @param int     $reference Log row id shown as a support reference (0 = none).
	 */
	public function deny( Verdict $verdict, string $message, int $reference ): void;
}
