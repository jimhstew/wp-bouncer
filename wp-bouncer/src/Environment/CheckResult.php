<?php
/**
 * The outcome of one environment check.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * `value` is a safe summary ("On", "set (3 paths)", "inside web root: yes"),
 * never a raw path or setting list.
 */
final readonly class CheckResult {

	public const GROUP_VERSIONS  = 'versions';
	public const GROUP_PHP       = 'php';
	public const GROUP_WORDPRESS = 'wordpress';

	/**
	 * Set up the CheckResult.
	 *
	 * @param string   $id             Check id.
	 * @param string   $group          versions|php|WordPress.
	 * @param Severity $severity       Severity.
	 * @param string   $title          Short title.
	 * @param string   $value          Safe summary of the current value.
	 * @param string   $why            Why it matters (may contain basic HTML).
	 * @param string   $fix            How to fix it (may contain basic HTML).
	 * @param bool     $is_private     Leave the value out of "Copy site info".
	 * @param bool     $dashboard_only Show on the Dashboard tab only (core reports it in Site Health).
	 */
	public function __construct(
		public string $id,
		public string $group,
		public Severity $severity,
		public string $title,
		public string $value,
		public string $why = '',
		public string $fix = '',
		public bool $is_private = false,
		public bool $dashboard_only = false
	) {
	}
}
