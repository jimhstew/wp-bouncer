<?php
/**
 * Can administrators edit plugin and theme code from the dashboard?
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
 * DISALLOW_FILE_EDIT (or DISALLOW_FILE_MODS, which also stops editing).
 */
final class FileEditCheck implements CheckInterface {

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_file_edit';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title = 'DISALLOW_FILE_EDIT';
		// Truthy, as in core's wp-includes/default-constants.php and the editor screens.
		$off = (bool) $env->constant( 'DISALLOW_FILE_EDIT' ) || (bool) $env->constant( 'DISALLOW_FILE_MODS' );
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_WORDPRESS,
			$off ? Severity::Ok : Severity::Warning,
			$title,
			$off ? __( 'Code editing is switched off', 'wp-bouncer' ) : __( 'Administrators can edit plugin and theme code in the dashboard', 'wp-bouncer' ),
			__( 'If an administrator account is taken over, the built-in code editor turns that into running any PHP code on the server.', 'wp-bouncer' ),
			__( 'Add <code>define( \'DISALLOW_FILE_EDIT\', true );</code> to wp-config.php.', 'wp-bouncer' )
		);
	}
}
