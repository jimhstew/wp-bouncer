<?php
/**
 * The site-wide IP setup notices (RT-03, RT-04, RT-24).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\SetupNotices;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Admin\SetupNotices
 */
final class SetupNoticesTest extends IntegrationTestCase {

	/** @var SetupNotices */
	private $notices;

	public function set_up() {
		parent::set_up();
		$this->notices = new SetupNotices( $this->plugin );
	}

	private function login( string $role = 'administrator' ): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => $role ) ) );
	}

	private function html(): string {
		ob_start();
		$this->notices->render();
		return (string) ob_get_clean();
	}

	public function test_it_hooks_admin_notices(): void {
		$this->notices->register();
		$this->assertNotFalse( has_action( 'admin_notices', array( $this->notices, 'render' ) ) );
	}

	public function test_header_without_proxies_shows_a_non_dismissible_error_with_both_fixes(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.44', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );
		set_current_screen( 'dashboard' );

		$out = $this->html();

		$this->assertStringContainsString( 'notice-error', $out );
		$this->assertStringNotContainsString( 'is-dismissible', $out );
		$this->assertStringContainsString( '10.0.0.44', $out );
		$this->assertStringContainsString( 'X-Real-IP', $out );
		$this->assertStringContainsString( 'Trust 10.0.0.44 as my proxy', $out );
		$this->assertStringContainsString( 'name="peer" value="10.0.0.44"', $out );
		$this->assertStringContainsString( 'suspended (login attempts are logged)', $out );
		$this->assertStringContainsString( 'I have no proxy', $out );
		$this->assertStringContainsString( 'name="action" value="wp_bouncer_ip_setup"', $out );
		$this->assertStringContainsString( 'name="fix" value="trust_peer"', $out );
		$this->assertStringContainsString( 'name="fix" value="use_remote_addr"', $out );
		$this->assertStringContainsString( 'name="_wpnonce"', $out );
		$this->assertStringContainsString( 'admin-post.php', $out );
		$this->assertStringContainsString( 'The header was present on this request', $out );
	}

	public function test_a_public_peer_gets_cdn_advice_and_no_trust_button(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );

		$out = $this->html();

		$this->assertStringNotContainsString( 'as my proxy', $out );
		$this->assertStringNotContainsString( 'value="trust_peer"', $out );
		$this->assertStringContainsString( 'CDN', $out );
		$this->assertStringContainsString( 'published IP ranges', $out );
		$this->assertStringContainsString( 'I have no proxy', $out );
		$this->assertStringContainsString( '#wpb-proxies', $out );
	}

	public function test_a_private_peer_without_the_header_gets_no_trust_button(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.44' ) );

		$out = $this->html();

		$this->assertStringNotContainsString( 'as my proxy', $out );
		$this->assertStringContainsString( 'I have no proxy', $out );
	}

	public function test_the_nonce_in_the_buttons_is_valid_for_the_handler(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );

		preg_match( '/name="_wpnonce" value="([0-9a-f]+)"/', $this->html(), $m );

		$this->assertNotEmpty( $m );
		$this->assertSame( 1, wp_verify_nonce( $m[1], 'wp_bouncer_ip_setup' ) );
	}

	public function test_the_notice_is_site_wide_not_only_on_the_plugin_screen(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_forwarded_for', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );

		foreach ( array( 'dashboard', 'plugins', 'toplevel_page_wp-bouncer' ) as $screen ) {
			set_current_screen( $screen );
			$this->assertStringContainsString( 'wpb-ip-setup', $this->html(), $screen );
		}
		unset( $GLOBALS['current_screen'] );
	}

	public function test_it_is_hidden_from_users_who_cannot_manage_options(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );

		foreach ( array( 'editor', 'author', 'subscriber' ) as $role ) {
			$this->login( $role );
			$this->assertSame( '', $this->html(), $role );
		}
		wp_set_current_user( 0 );
		$this->assertSame( '', $this->html() );
	}

	public function test_a_correct_setup_is_silent(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '127.0.0.1' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );
		$this->assertSame( '', $this->html() );

		$this->set_settings( array( 'ip_source' => 'remote_addr' ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );
		$this->assertSame( '', $this->html() );
	}

	public function test_a_loopback_peer_with_a_forwarding_header_offers_to_read_the_header(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'remote_addr' ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5' ) );

		$out = $this->html();

		$this->assertStringContainsString( 'notice-error', $out );
		$this->assertStringContainsString( 'Read the IP from X-Forwarded-For and trust 127.0.0.1', $out );
		$this->assertStringContainsString( 'name="header" value="x_forwarded_for"', $out );
	}

	public function test_over_broad_entries_are_named(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'remote_addr' ) );
		update_option( \WPBouncer\Settings::OPTION, array_merge( \WPBouncer\Settings::defaults(), array( 'trusted_proxies' => array( '0.0.0.0/0' ), 'allowlist' => array( '::/0' ) ) ) );
		$this->plugin->reload_settings();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );

		$out = $this->html();

		$this->assertStringContainsString( '0.0.0.0/0', $out );
		$this->assertStringContainsString( '::/0', $out );
		$this->assertStringContainsString( 'too broad', $out );
	}

	public function test_untrusted_text_is_escaped(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44', 'HTTP_X_REAL_IP' => '<script>alert(1)</script>' ) );

		$this->assertStringNotContainsString( '<script>', $this->html() );
	}
}
