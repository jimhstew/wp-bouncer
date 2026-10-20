<?php
/**
 * The decision a rule returns when it wants a request turned away.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Immutable value object describing why a request should be refused.
 */
final class Verdict {

	private string $rule;
	private string $reason;
	private int $status;
	private int $retry_after;

	/**
	 * @param string $rule        Rule id that produced the verdict (e.g. "waf").
	 * @param string $reason      Short human-readable explanation for the log.
	 * @param int    $status      HTTP status to send (403 by default, 429 for throttling).
	 * @param int    $retry_after Seconds until the client may retry (0 = no header).
	 */
	public function __construct( string $rule, string $reason, int $status = 403, int $retry_after = 0 ) {
		$this->rule        = $rule;
		$this->reason      = $reason;
		$this->status      = $status;
		$this->retry_after = max( 0, $retry_after );
	}

	/** Rule id. */
	public function rule(): string {
		return $this->rule;
	}

	/** Human-readable reason. */
	public function reason(): string {
		return $this->reason;
	}

	/** HTTP status code. */
	public function status(): int {
		return $this->status;
	}

	/** Retry-After seconds (0 when not applicable). */
	public function retry_after(): int {
		return $this->retry_after;
	}
}
