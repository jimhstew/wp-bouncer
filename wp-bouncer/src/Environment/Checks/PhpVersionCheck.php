<?php
/**
 * Is the PHP version still getting security fixes?
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment\Checks;

use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\EnvironmentInterface;
use WPBouncer\Environment\Severity;
use WPBouncer\Environment\SupportPolicy;
use WPBouncer\Environment\VersionParser;
use WPBouncer\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * By WP Bouncer's bundled support policy. Distributions sometimes backport fixes.
 */
final class PhpVersionCheck implements CheckInterface {

	/**
	 * Policy.
	 *
	 * @var SupportPolicy
	 */
	private SupportPolicy $policy;
	/**
	 * Time source.
	 *
	 * @var Clock
	 */
	private Clock $clock;

	/**
	 * Set up the check.
	 *
	 * @param SupportPolicy $policy Policy.
	 * @param Clock         $clock  Time source.
	 */
	public function __construct( SupportPolicy $policy, Clock $clock ) {
		$this->policy = $policy;
		$this->clock  = $clock;
	}

	/** {@inheritDoc} */
	public function id(): string {
		return 'wpb_php_version';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$branch = VersionParser::php( $env->php_version() );
		$title  = __( 'PHP version', 'wp-bouncer' );
		if ( null === $branch ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_VERSIONS, Severity::Unknown, $title, __( 'Unknown (could not read the version)', 'wp-bouncer' ) );
		}
		$severity = $this->policy->status( 'php', $branch, $this->clock->now() );
		$value    = 'PHP ' . $branch;
		if ( Severity::Unknown === $severity ) {
			/* translators: %s: PHP branch such as 8.3. */
			$value = sprintf( __( 'PHP %s (not in the bundled policy, or the policy is out of date)', 'wp-bouncer' ), $branch );
		}
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_VERSIONS,
			$severity,
			$title,
			$value,
			__( 'A PHP version that no longer receives security fixes gets no patches for newly found holes. Some hosts and distributions backport security fixes; check with your host.', 'wp-bouncer' ),
			__( 'Ask your host to move the site to a supported PHP version.', 'wp-bouncer' )
		);
	}
}
