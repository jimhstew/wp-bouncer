<?php
/**
 * A yes/no php.ini directive.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment\Checks;

use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\EnvironmentInterface;
use WPBouncer\Environment\IniValue;
use WPBouncer\Environment\Severity;

defined( 'ABSPATH' ) || exit;

/**
 * Data-driven: one instance per directive. The check reports the current
 * (runtime) value; it never changes anything.
 */
final class IniFlagCheck implements CheckInterface {

	/**
	 * Check id.
	 *
	 * @var string
	 */
	private string $id;
	/**
	 * Directive.
	 *
	 * @var string
	 */
	private string $directive;
	/**
	 * The setting is a problem when it has this value.
	 *
	 * @var bool
	 */
	private bool $bad_when;
	/**
	 * Severity when it is a problem.
	 *
	 * @var Severity
	 */
	private Severity $severity;
	/**
	 * Why it matters.
	 *
	 * @var string
	 */
	private string $why;
	/**
	 * What to do.
	 *
	 * @var string
	 */
	private string $fix;
	/**
	 * Decides whether the check applies at all.
	 *
	 * @var (callable(EnvironmentInterface): bool)|null
	 */
	private $applies;
	/**
	 * Decides whether a problem is only informational.
	 *
	 * @var (callable(EnvironmentInterface): bool)|null
	 */
	private $downgrade;

	/**
	 * Set up the check.
	 *
	 * @param string                                      $id        Check id (wpb_...).
	 * @param string                                      $directive php.ini directive.
	 * @param bool                                        $bad_when  Problem when the flag has this value.
	 * @param Severity                                    $severity  Severity of a problem.
	 * @param string                                      $why       Why it matters.
	 * @param string                                      $fix       What to do.
	 * @param (callable(EnvironmentInterface): bool)|null $applies   Return false to skip the check.
	 * @param (callable(EnvironmentInterface): bool)|null $downgrade Return true to report a problem as Info.
	 */
	public function __construct( string $id, string $directive, bool $bad_when, Severity $severity, string $why, string $fix, ?callable $applies = null, ?callable $downgrade = null ) {
		$this->id        = $id;
		$this->directive = $directive;
		$this->bad_when  = $bad_when;
		$this->severity  = $severity;
		$this->why       = $why;
		$this->fix       = $fix;
		$this->applies   = $applies;
		$this->downgrade = $downgrade;
	}

	/** {@inheritDoc} */
	public function id(): string {
		return $this->id;
	}

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult {
		$title = $this->directive;
		if ( null !== $this->applies && ! ( $this->applies )( $env ) ) {
			return new CheckResult( $this->id, CheckResult::GROUP_PHP, Severity::Ok, $title, __( 'Does not apply here', 'wp-bouncer' ) );
		}
		$flag = IniValue::flag( $env->ini( $this->directive ), $this->directive );
		if ( null === $flag ) {
			return new CheckResult( $this->id, CheckResult::GROUP_PHP, Severity::Unknown, $title, __( 'Unknown (could not read it)', 'wp-bouncer' ), $this->why, $this->fix );
		}
		$value = $flag ? __( 'On', 'wp-bouncer' ) : __( 'Off', 'wp-bouncer' );
		if ( $flag !== $this->bad_when ) {
			return new CheckResult( $this->id, CheckResult::GROUP_PHP, Severity::Ok, $title, $value, $this->why, $this->fix );
		}
		$severity = null !== $this->downgrade && ( $this->downgrade )( $env ) ? Severity::Info : $this->severity;
		return new CheckResult( $this->id, CheckResult::GROUP_PHP, $severity, $title, $value, $this->why, $this->fix );
	}
}
