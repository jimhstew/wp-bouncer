<?php
/**
 * Upload and input limits, for context.
 *
 * @package WPBouncer\Environment
 */

namespace WPBouncer\Environment\Checks;

use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\EnvironmentInterface;
use WPBouncer\Environment\IniValue;
use WPBouncer\Environment\Severity;

defined( 'ABSPATH' ) || exit;

/**
 * Info only: file_uploads, upload_max_filesize, post_max_size and max_input_vars.
 */
final class UploadLimitsCheck implements CheckInterface {

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_upload_limits';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title   = __( 'Upload and input limits', 'wp-bouncer' );
		$uploads = IniValue::flag( $env->ini( 'file_uploads' ) );
		$upload  = IniValue::bytes( $env->ini( 'upload_max_filesize' ) );
		$post    = IniValue::bytes( $env->ini( 'post_max_size' ) );
		$vars    = IniValue::int( $env->ini( 'max_input_vars' ) );
		if ( null === $uploads && null === $upload && null === $post && null === $vars ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Unknown, $title, __( 'Unknown', 'wp-bouncer' ) );
		}
		$parts   = array();
		$parts[] = null === $uploads ? 'file_uploads: ?' : 'file_uploads: ' . ( $uploads ? 'on' : 'off' );
		$parts[] = 'upload_max_filesize: ' . self::size( $upload );
		$parts[] = 'post_max_size: ' . self::size( $post );
		$parts[] = 'max_input_vars: ' . ( null === $vars ? '?' : (string) $vars );
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_PHP,
			Severity::Info,
			$title,
			implode( ', ', $parts ),
			__( 'Large upload limits make it easier to fill the disk or exhaust memory; very small ones break legitimate uploads. This is context, not a finding.', 'wp-bouncer' ),
			__( 'Set them to what the site actually needs.', 'wp-bouncer' )
		);
	}

	/**
	 * Show a size; -1 and 0 mean no limit.
	 *
	 * @param int|null $bytes Bytes.
	 */
	private static function size( ?int $bytes ): string {
		if ( null === $bytes ) {
			return '?';
		}
		return $bytes <= 0 ? __( 'unlimited', 'wp-bouncer' ) : (string) size_format( $bytes );
	}
}
