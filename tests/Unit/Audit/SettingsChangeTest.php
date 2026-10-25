<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Audit;

use PHPUnit\Framework\TestCase;
use WPBouncer\Audit\SettingsChange;
use WPBouncer\Settings;

/**
 * @covers \WPBouncer\Audit\SettingsChange
 */
final class SettingsChangeTest extends TestCase {

	public function test_no_change_gives_null(): void {
		$this->assertNull( SettingsChange::from( Settings::defaults(), Settings::defaults() ) );
	}

	public function test_activation_defaults_over_a_missing_option_give_null(): void {
		$this->assertNull( SettingsChange::from( Settings::defaults(), Settings::defaults() ) );
		$this->assertNull( SettingsChange::from( array(), Settings::defaults() ) );
	}

	public function test_a_raw_only_difference_gives_null(): void {
		$partial = Settings::defaults();
		unset( $partial['log_retention_days'] );
		$partial['junk'] = 'x';
		$this->assertNull( SettingsChange::from( $partial, Settings::defaults() ) );
	}

	public function test_a_partial_write_is_filled_in_before_the_diff(): void {
		$change = SettingsChange::from( Settings::defaults(), array( 'mode' => 'monitor' ) );
		$this->assertNotNull( $change );
		$this->assertSame( array( 'mode' ), $change->changes );
		$this->assertSame( array( 'mode' ), $change->risky );
		$this->assertSame( 'monitor', $change->new['mode'] );
		$this->assertSame( Settings::defaults()['log_retention_days'], $change->new['log_retention_days'] );
	}

	public function test_a_non_risky_change_is_not_risky(): void {
		$change = SettingsChange::from( Settings::defaults(), array( 'block_message' => 'Hi' ) );
		$this->assertNotNull( $change );
		$this->assertSame( array(), $change->risky );
	}

	public function test_a_junk_scalar_adds_the_settings_path_and_is_risky(): void {
		$change = SettingsChange::from( array( 'mode' => 'monitor' ), 'garbage' );
		$this->assertNotNull( $change );
		$this->assertContains( 'settings', $change->changes );
		$this->assertContains( 'settings', $change->risky );
	}

	public function test_a_delete_adds_settings_plus_the_diff_from_defaults(): void {
		$change = SettingsChange::from( array( 'mode' => 'monitor' ), Settings::defaults(), true );
		$this->assertNotNull( $change );
		$this->assertSame( array( 'mode', 'settings' ), $change->changes );
	}

	public function test_deleting_an_option_equal_to_defaults_still_reports_settings(): void {
		$change = SettingsChange::from( Settings::defaults(), Settings::defaults(), true );
		$this->assertNotNull( $change );
		$this->assertSame( array( 'settings' ), $change->changes );
	}

	public function test_listed_values_never_reach_the_reason(): void {
		$change = SettingsChange::from( Settings::defaults(), array( 'allowlist' => array( '203.0.113.7' ) ) );
		$this->assertNotNull( $change );
		$reason = $change->reason( 'jim (cli)' );
		$this->assertSame( 'Settings changed by jim (cli): allowlist', $reason );
		$this->assertStringNotContainsString( '203.0.113.7', $reason );
	}
}
