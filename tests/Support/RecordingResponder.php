<?php
/**
 * Responder that records instead of exiting.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Firewall\ResponderInterface;
use WPBouncer\Firewall\Verdict;

/**
 * Remembers every deny() call.
 */
final class RecordingResponder implements ResponderInterface {

	/** @var array<int, array{verdict: Verdict, message: string, reference: int}> */
	public array $denials = array();

	/** {@inheritDoc} */
	public function deny( Verdict $verdict, string $message, int $reference ): void {
		$this->denials[] = compact( 'verdict', 'message', 'reference' );
	}
}
