<?php
/**
 * One environment check.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Checks are read-only and pure: everything they know comes from the
 * EnvironmentInterface they are given.
 */
interface CheckInterface {

	/** Unique id, 3 to 64 characters of a-z, 0-9 and underscore. */
	public function id(): string;

	/**
	 * Run the check.
	 *
	 * @param EnvironmentInterface $env The environment.
	 */
	public function run( EnvironmentInterface $env ): CheckResult;
}
