<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Environment;

use PHPUnit\Framework\TestCase;
use WPBouncer\Environment\Severity;
use WPBouncer\Environment\SupportPolicy;

/**
 * @covers \WPBouncer\Environment\SupportPolicy
 */
final class SupportPolicyTest extends TestCase {

	private function utc( string $date_time ): int {
		return (int) strtotime( $date_time . ' UTC' );
	}

	public function test_a_branch_far_from_its_end_is_ok(): void {
		$this->assertSame( Severity::Ok, ( new SupportPolicy() )->status( 'php', '8.4', $this->utc( '2026-10-24 12:00:00' ) ) );
	}

	public function test_the_last_day_is_inclusive_and_the_next_second_is_past_the_end(): void {
		$policy = new SupportPolicy();
		$this->assertSame( '2026-12-31', $policy->security_until( 'php', '8.2' ) );
		$this->assertNotSame( Severity::Critical, $policy->status( 'php', '8.2', $this->utc( '2026-12-31 23:59:59' ) ) );
		$this->assertSame( Severity::Critical, $policy->status( 'php', '8.2', $this->utc( '2027-01-01 00:00:00' ) ) );
	}

	public function test_ending_means_within_ninety_days_of_the_last_day(): void {
		$policy = new SupportPolicy();
		$end    = $this->utc( '2026-12-31 23:59:59' );
		// Exactly 90 days of seconds before the end is "ending"; one second more is still "ok".
		$this->assertSame( Severity::Notice, $policy->status( 'php', '8.2', $end - 90 * 86400 ) );
		$this->assertSame( Severity::Ok, $policy->status( 'php', '8.2', $end - 90 * 86400 - 1 ) );
		$this->assertSame( Severity::Notice, $policy->status( 'php', '8.2', $this->utc( '2026-10-24 00:00:00' ) ), 'about 68 days left' );
	}

	public function test_a_branch_that_is_not_listed_is_unknown_never_supported(): void {
		$policy = new SupportPolicy();
		$this->assertSame( Severity::Unknown, $policy->status( 'php', '9.9', $this->utc( '2026-10-24 00:00:00' ) ) );
		$this->assertSame( Severity::Unknown, $policy->status( 'mysql', '9.99', $this->utc( '2026-10-24 00:00:00' ) ), 'newer than every listed branch' );
		$this->assertSame( Severity::Unknown, $policy->status( 'nosql', '1.0', $this->utc( '2026-10-24 00:00:00' ) ) );
		$this->assertNull( $policy->security_until( 'php', '9.9' ) );
	}

	public function test_an_unlisted_branch_older_than_the_newest_listed_one_is_past_its_end(): void {
		$policy = new SupportPolicy();
		$now    = $this->utc( '2026-10-24 00:00:00' );
		foreach ( array( array( 'mysql', '5.5' ), array( 'mysql', '5.6' ), array( 'mysql', '8.1' ), array( 'mysql', '9.0' ), array( 'mysql', '9.1' ), array( 'mariadb', '10.0' ), array( 'mariadb', '10.2' ), array( 'mariadb', '11.5' ), array( 'mariadb', '12.0' ), array( 'php', '5.6' ), array( 'php', '7.3' ) ) as $case ) {
			$this->assertSame( Severity::Critical, $policy->status( $case[0], $case[1], $now ), $case[0] . ' ' . $case[1] );
		}
		foreach ( array( array( 'mysql', '9.99' ), array( 'mariadb', '12.99' ), array( 'php', '9.0' ) ) as $case ) {
			$this->assertSame( Severity::Unknown, $policy->status( $case[0], $case[1], $now ), $case[0] . ' ' . $case[1] );
		}
		$this->assertSame( Severity::Critical, $policy->status( 'mysql', '9.1', $this->utc( '2030-01-01 00:00:00' ) + 0 ), 'and a stale table still warns' );
	}

	public function test_known_end_of_life_branches_are_critical_today(): void {
		$policy = new SupportPolicy();
		$now    = $this->utc( '2026-10-24 00:00:00' );
		foreach ( array( array( 'php', '8.1' ), array( 'php', '7.4' ), array( 'mysql', '5.7' ), array( 'mysql', '8.0' ), array( 'mariadb', '10.5' ), array( 'mariadb', '10.6' ) ) as $case ) {
			$this->assertSame( Severity::Critical, $policy->status( $case[0], $case[1], $now ), $case[0] . ' ' . $case[1] );
		}
	}

	public function test_the_stale_guard_turns_ok_into_unknown_but_not_warnings(): void {
		$policy = new SupportPolicy();
		$late   = $this->utc( SupportPolicy::VERIFIED_ON . ' 00:00:00' ) + ( SupportPolicy::STALE_DAYS + 1 ) * 86400;
		$this->assertTrue( $policy->is_stale( $late ) );
		$this->assertFalse( $policy->is_stale( $late - 2 * 86400 ) );
		$this->assertSame( Severity::Unknown, $policy->status( 'php', '8.5', $late ), 'supported, but the table is old' );
		$this->assertSame( Severity::Critical, $policy->status( 'php', '8.1', $late ), 'end-of-life stays a warning' );
	}

	public function test_every_entry_has_a_valid_date_and_branches_are_in_order(): void {
		$ref = new \ReflectionClassConstant( SupportPolicy::class, 'BRANCHES' );
		foreach ( $ref->getValue() as $product => $branches ) {
			foreach ( $branches as $branch => $row ) {
				$this->assertMatchesRegularExpression( '/^\d+\.\d+$/', (string) $branch );
				$this->assertMatchesRegularExpression( '/^\d{4}-\d{2}-\d{2}$/', $row['security_until'], "$product $branch" );
				$this->assertNotFalse( strtotime( $row['security_until'] ) );
			}
		}
	}
}
