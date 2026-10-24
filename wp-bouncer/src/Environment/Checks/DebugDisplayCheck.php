<?php
/**
 * Does WordPress print PHP errors into pages?
 *
 * @package WPBouncer\Environment
 */

namespace WPBouncer\Environment\Checks;

use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\EnvironmentInterface;
use WPBouncer\Environment\Severity;

defined( 'ABSPATH' ) || exit;

/**
 * Dashboard tab only: WordPress core already reports this in Site Health.
 */
final class DebugDisplayCheck implements CheckInterface {

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_debug_display';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title = 'WP_DEBUG_DISPLAY';
		// As core's wp_debug_mode(): WP_DEBUG on, and WP_DEBUG_DISPLAY undefined (default true) or truthy.
		$debug   = (bool) $env->constant( 'WP_DEBUG' );
		$display = $env->constant( 'WP_DEBUG_DISPLAY' );
		$shown   = $debug && ( null === $display || (bool) $display );
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_WORDPRESS,
			$shown ? Severity::Warning : Severity::Ok,
			$title,
			$shown ? __( 'PHP errors are printed into pages', 'wp-bouncer' ) : __( 'PHP errors are not printed into pages', 'wp-bouncer' ),
			__( 'Error messages shown to visitors reveal file paths and details that help an attacker.', 'wp-bouncer' ),
			__( 'Turn WP_DEBUG off on a live site, or add <code>define( \'WP_DEBUG_DISPLAY\', false );</code> to wp-config.php.', 'wp-bouncer' ),
			false,
			true
		);
	}
}
