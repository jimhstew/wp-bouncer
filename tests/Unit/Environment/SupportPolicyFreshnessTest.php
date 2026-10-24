<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Environment;

use PHPUnit\Framework\TestCase;
use WPBouncer\Environment\SupportPolicy;

/**
 * Release checklist guard: re-verify the end-of-life dates and bump VERIFIED_ON.
 *
 * @coversNothing
 */
final class SupportPolicyFreshnessTest extends TestCase {

	public function test_verified_on_is_not_more_than_six_months_before_the_latest_release(): void {
		$changelog = (string) file_get_contents( dirname( __DIR__, 3 ) . '/documentation/CHANGELOG.md' );
		$release   = time();
		if ( 1 === preg_match( '/^## \[(?!Unreleased)[^\]]+\] - (\d{4}-\d{2}-\d{2})/mi', $changelog, $m ) ) {
			$release = (int) strtotime( $m[1] . ' UTC' );
		}
		$verified = (int) strtotime( SupportPolicy::VERIFIED_ON . ' UTC' );
		$this->assertGreaterThan( $release - 183 * 86400, $verified, 'Re-check the dates in SupportPolicy against php.net, the MySQL lifecycle page and mariadb.org, then bump VERIFIED_ON.' );
	}
}
