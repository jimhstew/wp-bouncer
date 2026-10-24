<?php
/**
 * Is the database server still getting security fixes?
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
 * MySQL and MariaDB by branch. Managed or unrecognised servers are "unknown", not a warning.
 */
final class DatabaseVersionCheck implements CheckInterface {

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
		return 'wpb_db_version';
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$db    = VersionParser::database( $env->db_server_info() );
		$title = __( 'Database version', 'wp-bouncer' );
		if ( null === $db ) {
			return new CheckResult( $this->id(), CheckResult::GROUP_VERSIONS, Severity::Unknown, $title, __( 'Unknown (not in the bundled policy)', 'wp-bouncer' ) );
		}
		$severity = $this->policy->status( $db['product'], $db['branch'], $this->clock->now() );
		$name     = 'mariadb' === $db['product'] ? 'MariaDB' : 'MySQL';
		$value    = $name . ' ' . $db['branch'];
		if ( Severity::Unknown === $severity ) {
			/* translators: 1: product, 2: branch. */
			$value = sprintf( __( '%1$s %2$s (not in the bundled policy, or the policy is out of date)', 'wp-bouncer' ), $name, $db['branch'] );
		}
		return new CheckResult(
			$this->id(),
			CheckResult::GROUP_VERSIONS,
			$severity,
			$title,
			$value,
			__( 'A database version that no longer receives security fixes gets no patches for newly found holes. Some hosts and distributions backport security fixes; check with your host.', 'wp-bouncer' ),
			__( 'Ask your host to upgrade the database server to a supported version.', 'wp-bouncer' )
		);
	}
}
