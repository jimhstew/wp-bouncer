<?php
/**
 * Are the program-running functions switched off?
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment\Checks;

use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\EnvironmentInterface;
use WPBouncer\Environment\Severity;

defined( 'ABSPATH' ) || exit;

/**
 * Info only. Lists the exec-family functions that are NOT disabled, nothing else from the setting.
 */
final class DisableFunctionsCheck implements CheckInterface {

	private const EXEC_FAMILY = array( 'exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen' );

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_disable_functions';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title = 'disable_functions';
		$why   = __( 'If an attacker gets PHP code running, functions that start programs let them take over the whole server. Few sites need them.', 'wp-bouncer' );
		$fix   = __( 'Add the functions listed to disable_functions if nothing on the site needs them. Some plugins do; test first.', 'wp-bouncer' );
		$raw   = $env->ini( 'disable_functions' );
		if ( false === $raw ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Unknown, $title, __( 'Unknown', 'wp-bouncer' ), $why, $fix, true );
		}
		$disabled = array_map( 'strtolower', array_map( 'trim', explode( ',', $raw ) ) );
		$missing  = array_values( array_diff( self::EXEC_FAMILY, $disabled ) );
		if ( array() === $missing ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Ok, $title, __( 'The exec family is disabled', 'wp-bouncer' ), $why, $fix, true );
		}
		/* translators: %s: function names. */
		$value = sprintf( __( 'Not disabled: %s', 'wp-bouncer' ), implode( ', ', $missing ) );
		return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Info, $title, $value, $why, $fix, true );
	}
}
