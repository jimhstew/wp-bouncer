<?php
/**
 * Contract every blocking rule implements.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;

defined( 'ABSPATH' ) || exit;

/**
 * A rule inspects a request and either objects (returns a Verdict) or stays quiet (returns null).
 *
 * Rules must not read superglobals or call WordPress functions directly.
 * Everything they need comes from Request or from collaborators passed to
 * their constructor. That keeps them unit-testable.
 */
interface RuleInterface {

	/** Stable machine id, used as the settings key and in the log (e.g. "user_agent"). */
	public function id(): string;

	/** Whether the admin has switched this rule on. */
	public function is_enabled(): bool;

	/**
	 * Inspect the request.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function inspect( Request $request ): ?Verdict;
}
