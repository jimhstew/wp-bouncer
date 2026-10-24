<?php
/**
 * The WordPress-too-old branch of wp-bouncer.php, with the version as a seam.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Update;

use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Update\OldWordPressGuard;
use WPBouncer\Update\Updater;

/**
 * @covers \WPBouncer\Update\OldWordPressGuard
 */
final class OldWordPressGuardTest extends IntegrationTestCase {

	public function set_up() {
		parent::set_up();
		delete_site_option( OldWordPressGuard::FLAG_OPTION );
		wp_clear_scheduled_hook( OldWordPressGuard::CRON_HOOK );
		$this->clear_mail();
	}

	public function tear_down() {
		delete_site_option( OldWordPressGuard::FLAG_OPTION );
		wp_clear_scheduled_hook( OldWordPressGuard::CRON_HOOK );
		remove_all_filters( 'update_plugins_github.com' );
		parent::tear_down();
	}

	private function guard(): OldWordPressGuard {
		return new OldWordPressGuard( WP_BOUNCER_FILE, '6.4.3', '7.0' );
	}

	public function test_register_keeps_the_updater_and_schedules_the_email(): void {
		remove_all_filters( 'update_plugins_github.com' );
		$this->guard()->register();

		$this->assertTrue( has_filter( 'update_plugins_github.com' ), 'the updater is registered' );
		$this->assertNotFalse( has_action( 'admin_notices' ) );
		$this->assertNotFalse( wp_next_scheduled( OldWordPressGuard::CRON_HOOK ) );
		$this->assertTrue( class_exists( Updater::class ) );
	}

	public function test_the_email_goes_out_once_to_the_admin(): void {
		update_option( 'admin_email', 'owner@example.org' );
		$this->clear_mail();
		$guard = $this->guard();

		$guard->maybe_email();
		$guard->maybe_email();

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'owner@example.org', wp_json_encode( $mail[0]['to'] ) );
		$this->assertStringContainsString( 'firewall is OFF', (string) $mail[0]['body'] );
		$this->assertStringContainsString( '6.4.3', (string) $mail[0]['body'] );
	}

	public function test_it_is_reported_again_only_after_the_condition_clears(): void {
		$guard = $this->guard();
		$guard->maybe_email();
		$guard->maybe_email();
		$this->assertCount( 1, $this->sent_mail(), 'once while the condition lasts' );

		OldWordPressGuard::reset();
		$guard->maybe_email();
		$this->assertCount( 2, $this->sent_mail(), 'a recurrence is reported afresh' );
	}

	public function test_the_notice_says_the_firewall_is_off(): void {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		wp_set_current_user( $id );
		ob_start();
		$this->guard()->render_notice();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'the firewall is OFF', $html );
		$this->assertStringContainsString( '7.0', $html );
	}

	public function test_the_notice_is_hidden_from_people_who_cannot_manage_plugins(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		ob_start();
		$this->guard()->render_notice();
		$this->assertSame( '', ob_get_clean() );
	}
}
