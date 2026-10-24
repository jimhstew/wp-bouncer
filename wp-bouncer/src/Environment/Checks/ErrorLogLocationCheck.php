<?php
/**
 * Is PHP's error log somewhere the web server can serve?
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
 * Only "inside the WordPress folder: yes/no" is shown, never the path.
 */
final class ErrorLogLocationCheck implements CheckInterface {

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_error_log_location';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title = __( 'PHP error log location', 'wp-bouncer' );
		$why   = __( 'An error log inside the WordPress folder can often be downloaded by anyone, and it contains file paths and data from errors.', 'wp-bouncer' );
		$fix   = __( 'Set error_log to a file outside the WordPress folder, or deny access to it in the web server.', 'wp-bouncer' );
		$path  = $env->ini( 'error_log' );
		if ( false === $path || '' === trim( $path ) ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Ok, $title, __( 'Not set (the server default is used)', 'wp-bouncer' ), $why, $fix, true );
		}
		if ( 'syslog' === strtolower( trim( $path ) ) ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Ok, $title, __( 'Sent to the system log', 'wp-bouncer' ), $why, $fix, true );
		}
		// A relative path depends on the working directory of each request, so where it points cannot be told.
		if ( 1 !== preg_match( '#^(/|[A-Za-z]:[\\\\/]|\\\\\\\\)#', trim( $path ) ) ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Unknown, $title, __( 'Set to a relative path; could not tell where', 'wp-bouncer' ), $why, $fix, true );
		}
		$inside = $env->inside_web_root( $path );
		if ( null === $inside ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Unknown, $title, __( 'Set; could not tell where', 'wp-bouncer' ), $why, $fix, true );
		}
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_PHP,
			$inside ? Severity::Warning : Severity::Ok,
			$title,
			$inside ? __( 'Inside the WordPress folder: yes', 'wp-bouncer' ) : __( 'Inside the WordPress folder: no', 'wp-bouncer' ),
			$why,
			$fix,
			true
		);
	}
}
