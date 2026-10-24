<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Hardening;

use PHPUnit\Framework\TestCase;
use WPBouncer\Hardening\UploadsGuard;

/**
 * @covers \WPBouncer\Hardening\UploadsGuard::serving_streak
 */
final class ServingStreakTest extends TestCase {

	public function test_one_failure_does_not_remove_the_block(): void {
		$r = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$this->assertSame( array( 'fail_streak' => 1, 'fail_time' => 1000, 'remove' => false ), $r );
	}

	public function test_a_503_then_a_200_never_removes_it(): void {
		$one = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$two = UploadsGuard::serving_streak( $one, 'ok', 1400 );
		$this->assertSame( 0, $two['fail_streak'] );
		$this->assertFalse( $two['remove'] );
		$three = UploadsGuard::serving_streak( $two, 'broken', 1800 );
		$this->assertFalse( $three['remove'] );
	}

	public function test_two_failures_five_minutes_apart_remove_it(): void {
		$one = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$two = UploadsGuard::serving_streak( $one, 'broken', 1000 + UploadsGuard::RECHECK_SECONDS );
		$this->assertTrue( $two['remove'] );
	}

	public function test_a_second_failure_too_soon_is_not_counted(): void {
		$one = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$two = UploadsGuard::serving_streak( $one, 'broken', 1000 + UploadsGuard::RECHECK_SECONDS - 1 );
		$this->assertFalse( $two['remove'] );
		$this->assertSame( 1, $two['fail_streak'] );
		$this->assertSame( 1000, $two['fail_time'] );
	}

	public function test_unknown_results_change_nothing(): void {
		$one = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$two = UploadsGuard::serving_streak( $one, 'unknown', 1200 );
		$this->assertSame( 1, $two['fail_streak'] );
		$this->assertFalse( $two['remove'] );
	}

	public function test_a_failure_older_than_an_hour_starts_a_new_count(): void {
		$one = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$two = UploadsGuard::serving_streak( $one, 'broken', 1000 + UploadsGuard::STREAK_SECONDS + 1 );
		$this->assertFalse( $two['remove'] );
		$this->assertSame( 1, $two['fail_streak'] );
		$this->assertSame( 1000 + UploadsGuard::STREAK_SECONDS + 1, $two['fail_time'] );
	}

	public function test_an_unknown_result_after_a_long_gap_clears_a_stale_streak(): void {
		$one = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$two = UploadsGuard::serving_streak( $one, 'unknown', 1000 + UploadsGuard::STREAK_SECONDS + 1 );
		$this->assertSame( 0, $two['fail_streak'] );
	}

	public function test_a_failure_just_inside_the_hour_still_counts(): void {
		$one = UploadsGuard::serving_streak( array(), 'broken', 1000 );
		$two = UploadsGuard::serving_streak( $one, 'broken', 1000 + UploadsGuard::STREAK_SECONDS );
		$this->assertTrue( $two['remove'] );
	}
}
