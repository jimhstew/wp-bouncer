<?php
/**
 * Is open_basedir set?
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
 * Info only; hosts often set (or cannot set) it. The paths are never shown.
 */
final class OpenBasedirCheck implements CheckInterface {

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_open_basedir';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title = 'open_basedir';
		$why   = __( 'open_basedir limits which folders PHP may read, which contains the damage if one site on a shared server is compromised.', 'wp-bouncer' );
		$fix   = __( 'On shared hosting, ask your host. On your own server, set open_basedir for the site.', 'wp-bouncer' );
		$raw   = $env->ini( 'open_basedir' );
		if ( false === $raw ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Unknown, $title, __( 'Unknown', 'wp-bouncer' ), $why, $fix, true );
		}
		$paths = array_filter( array_map( 'trim', explode( PATH_SEPARATOR, $raw ) ), static fn( string $path ): bool => '' !== $path );
		if ( array() === $paths ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Info, $title, __( 'Not set', 'wp-bouncer' ), $why, $fix, true );
		}
		/* translators: %d: number of paths. */
		$value = sprintf( _n( 'Set (%d path)', 'Set (%d paths)', count( $paths ), 'wp-bouncer' ), count( $paths ) );
		return new CheckResult( $this->id(), CheckResult::GROUP_PHP, Severity::Ok, $title, $value, $why, $fix, true );
	}
}
