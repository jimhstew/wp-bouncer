<?php
/**
 * Contract for recording what the bouncer turned away.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Log;

defined( 'ABSPATH' ) || exit;

/**
 * Write side of the block log. BlockLog stores to the database; the tests use
 * an in-memory implementation.
 */
interface BlockLogInterface {

	/** Request was refused. */
	public const ACTION_BLOCKED = 'blocked';

	/** Request matched a rule but monitor mode let it through. */
	public const ACTION_MONITORED = 'monitored';

	/** A temporary ban or lockout was placed on the IP. */
	public const ACTION_LOCKOUT = 'lockout';

	/** Not a block: an email alert about a site change (new administrator, plugin change). */
	public const ACTION_ALERT = 'alert';

	/** Not a block: a successful administrator login (rule admin_login). */
	public const ACTION_LOGIN = 'login';

	/** Summary row: events dropped because the per-minute write budget ran out. */
	public const ACTION_SUPPRESSED = 'suppressed';

	/**
	 * Record one event.
	 *
	 * @param array<string, string> $entry {
	 *     Event fields.
	 *
	 *     @type string $ip         Client IP.
	 *     @type string $country    ISO 3166 alpha-2 code or ''.
	 *     @type string $rule       Rule id.
	 *     @type string $action     One of the ACTION_* constants.
	 *     @type string $reason     Explanation.
	 *     @type string $method     HTTP method.
	 *     @type string $uri        Request URI.
	 *     @type string $user_agent User-Agent header.
	 * }
	 * @return int Inserted row id (0 when not stored).
	 */
	public function record( array $entry ): int;
}
