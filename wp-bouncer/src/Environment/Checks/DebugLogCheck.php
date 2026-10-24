<?php
/**
 * Is the WordPress debug log in a web-readable place?
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
 * Decided from constants and paths only (no request is made to fetch the file).
 */
final class DebugLogCheck implements CheckInterface {

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_debug_log';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title   = 'WP_DEBUG_LOG';
		$why     = __( 'wp-content/debug.log is inside the WordPress folder and can often be downloaded by anyone. It holds file paths, queries and sometimes personal data.', 'wp-bouncer' );
		$fix     = __( 'Turn WP_DEBUG_LOG off, or set it to a file path outside the WordPress folder, or deny access to debug.log in the web server.', 'wp-bouncer' );
		$content = (string) ( $env->constant( 'WP_CONTENT_DIR' ) ?? '' );
		$debug   = (bool) $env->constant( 'WP_DEBUG' );
		$log     = $env->constant( 'WP_DEBUG_LOG' );
		$path    = '';
		// As core's wp_debug_mode(): "true" or "1" mean wp-content/debug.log; any other string is the path.
		if ( $debug && $log ) {
			$path = is_string( $log ) && ! in_array( strtolower( $log ), array( 'true', '1' ), true ) ? $log : $content . '/debug.log';
		}

		if ( '' === $path ) {
			// Logging is off, but an old log may still be sitting in wp-content.
			$old = $content . '/debug.log';
			if ( '' !== $content && (int) $env->file_size( $old ) > 0 && true === $env->inside_web_root( $content ) ) {
				return new CheckResult( $this->id(), CheckResult::GROUP_WORDPRESS, Severity::Warning, $title, __( 'Not logging now, but an old debug.log is still in wp-content', 'wp-bouncer' ), $why, __( 'Delete wp-content/debug.log, and deny access to it in the web server.', 'wp-bouncer' ), true );
			}
			return new CheckResult( $this->id(), CheckResult::GROUP_WORDPRESS, Severity::Ok, $title, __( 'Not logging to a file', 'wp-bouncer' ), $why, $fix, true );
		}

		$inside = $env->inside_web_root( $path );
		if ( null === $inside ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_WORDPRESS, Severity::Unknown, $title, __( 'Logging to a file; could not tell where', 'wp-bouncer' ), $why, $fix, true );
		}
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_WORDPRESS,
			$inside ? Severity::Warning : Severity::Ok,
			$title,
			$inside ? __( 'Logging inside the WordPress folder: yes', 'wp-bouncer' ) : __( 'Logging inside the WordPress folder: no', 'wp-bouncer' ),
			$why,
			$fix,
			true
		);
	}
}
