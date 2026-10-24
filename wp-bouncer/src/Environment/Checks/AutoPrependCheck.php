<?php
/**
 * Is a file run before or after every script?
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
 * Info only: normal for some firewalls, a known malware trick otherwise. Never shows the path.
 */
final class AutoPrependCheck implements CheckInterface {

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_auto_prepend';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title = 'auto_prepend_file / auto_append_file';
		$why   = __( 'A file run before or after every PHP script is normal for some security tools, but malware uses it to hide.', 'wp-bouncer' );
		$fix   = __( 'If you do not recognise it, check the .user.ini and php.ini files with your host.', 'wp-bouncer' );
		$set   = false;
		foreach ( array( 'auto_prepend_file', 'auto_append_file' ) as $name ) {
			$raw = $env->ini( $name );
			if ( is_string( $raw ) && '' !== trim( $raw ) ) {
				$set = true;
			}
		}
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_PHP,
			$set ? Severity::Info : Severity::Ok,
			$title,
			$set ? __( 'Set; normal for some firewalls, otherwise investigate', 'wp-bouncer' ) : __( 'Not set', 'wp-bouncer' ),
			$why,
			$fix,
			true
		);
	}
}
