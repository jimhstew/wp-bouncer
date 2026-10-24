<?php
/**
 * Admin menu, assets, notices and the seven tabs rendered for real.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Admin\AdminController
 * @covers \WPBouncer\Admin\LogListTable
 * @covers \WPBouncer\Admin\TrafficListTable
 */
final class AdminScreensTest extends IntegrationTestCase {

	/** @var AdminController */
	private $admin;

	public function set_up() {
		parent::set_up();
		$this->admin = new AdminController( $this->plugin );
		$this->fake_request();
		// wp-admin/admin.php sets $hook_suffix before a page renders. Older WordPress (5.9) reads it
		// unchecked when WP_List_Table is built ("Undefined index: hook_suffix").
		$GLOBALS['hook_suffix'] = 'toplevel_page_wp-bouncer';
		set_current_screen( 'toplevel_page_wp-bouncer' );
	}

	public function tear_down() {
		unset( $GLOBALS['current_screen'], $GLOBALS['hook_suffix'] );
		parent::tear_down();
	}

	private function login( string $role = 'administrator' ): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => $role ) ) );
	}

	private function render( string $tab ): string {
		$_GET['tab'] = $tab;
		ob_start();
		$this->admin->render();
		return (string) ob_get_clean();
	}

	private function notices(): string {
		ob_start();
		$this->admin->notices();
		return (string) ob_get_clean();
	}

	public function test_add_menu_registers_a_manage_options_page(): void {
		$this->login();

		$this->admin->add_menu();

		$this->assertArrayHasKey( AdminController::SLUG, $GLOBALS['admin_page_hooks'] );
		$found = false;
		foreach ( $GLOBALS['menu'] as $item ) {
			if ( AdminController::SLUG === $item[2] ) {
				$found = true;
				$this->assertSame( 'manage_options', $item[1] );
			}
		}
		$this->assertTrue( $found );
	}

	public function test_render_refuses_users_without_manage_options(): void {
		$this->login( 'editor' );

		$e = $this->die_of( array( $this->admin, 'render' ) );

		$this->assertStringContainsString( 'permission', $e->getMessage() );
	}

	/** @return array<string, array{0: string}> */
	public static function tabs(): array {
		$out = array();
		foreach ( array_keys( AdminController::tabs() ) as $tab ) {
			$out[ $tab ] = array( $tab );
		}
		return $out;
	}

	/**
	 * @dataProvider tabs
	 */
	public function test_every_tab_renders_for_an_administrator( string $tab ): void {
		$this->login();

		$html = $this->render( $tab );

		$this->assertStringContainsString( 'wrap wp-bouncer', $html );
		$this->assertStringContainsString( 'nav-tab-active', $html );
		$this->assertStringContainsString( 'tab=' . $tab, $html );
		$this->assertStringNotContainsString( 'Warning:', $html );
		$this->assertStringNotContainsString( 'Notice:', $html );
		$this->assertStringNotContainsString( 'Fatal error', $html );
	}

	public function test_forms_carry_nonces_and_post_to_admin_post(): void {
		$this->login();

		$html = $this->render( 'general' );

		$this->assertStringContainsString( 'admin-post.php', $html );
		$this->assertStringContainsString( 'name="action" value="wp_bouncer_save"', $html );
		$this->assertStringContainsString( '_wpnonce', $html );
	}

	public function test_an_unknown_tab_shows_the_dashboard(): void {
		$this->login();

		$html = $this->render( 'bogus' );

		$this->assertStringContainsString( 'tab=dashboard', $html );
		$this->assertMatchesRegularExpression( '/nav-tab-active[^>]*>\s*Dashboard/', $html );
	}

	public function test_the_log_tab_lists_entries_and_escapes_attacker_controlled_text(): void {
		$this->login();
		$this->plugin->log()->record(
			array(
				'ip'         => '198.51.100.23',
				'rule'       => 'waf',
				'reason'     => 'XSS payload',
				'uri'        => '/?q=<script>alert(1)</script>',
				'user_agent' => '"><img src=x onerror=alert(2)>',
			)
		);

		$html = $this->render( 'log' );

		$this->assertStringContainsString( '198.51.100.23', $html );
		$this->assertStringNotContainsString( '<script>alert(1)</script>', $html );
		$this->assertStringNotContainsString( '<img src=x', $html );
	}

	public function test_the_traffic_tab_lists_requests_and_escapes_text(): void {
		$this->login();
		$this->plugin->traffic_log()->record(
			array(
				'ip'         => '198.51.100.24',
				'method'     => 'GET',
				'uri'        => '/<script>alert(3)</script>',
				'status'     => 404,
				'user_agent' => 'curl/8',
			)
		);

		$html = $this->render( 'traffic' );

		$this->assertStringContainsString( '198.51.100.24', $html );
		$this->assertStringNotContainsString( '<script>alert(3)</script>', $html );
	}

	public function test_the_log_tab_honours_filters_from_the_query_string(): void {
		$this->login();
		$this->plugin->log()->record( array( 'ip' => '198.51.100.31', 'rule' => 'waf' ) );
		$this->plugin->log()->record( array( 'ip' => '198.51.100.32', 'rule' => 'xmlrpc' ) );
		$_REQUEST['rule'] = 'xmlrpc';
		$_GET['rule']     = 'xmlrpc';

		$html = $this->render( 'log' );

		$this->assertStringContainsString( '198.51.100.32', $html );
		$this->assertStringNotContainsString( '198.51.100.31', $html );
	}

	/* ---------------- notices ---------------- */

	public function test_notices_warn_about_monitor_mode_on_our_screen(): void {
		$this->login();
		$this->set_settings( array( 'mode' => 'monitor' ) );

		$this->assertStringContainsString( 'Monitor mode is on', $this->notices() );
	}

	public function test_notices_are_silent_for_users_who_cannot_manage_options(): void {
		$this->login( 'editor' );
		$this->set_settings( array( 'mode' => 'monitor' ) );

		$this->assertSame( '', $this->notices() );
	}

	public function test_notices_are_silent_on_other_screens(): void {
		$this->login();
		$this->set_settings( array( 'mode' => 'monitor' ) );
		set_current_screen( 'dashboard' );

		$this->assertSame( '', $this->notices() );
	}

	public function test_the_proxy_warning_moved_to_the_site_wide_setup_notices(): void {
		$this->login();
		$this->set_settings( array( 'ip_source' => 'x_forwarded_for', 'trusted_proxies' => array() ) );

		$this->assertStringNotContainsString( 'forge that header', $this->notices() );
	}

	public function test_notices_warn_when_country_blocking_has_no_database(): void {
		$this->login();
		$this->set_settings( array( 'rules' => array( 'country' => array( 'enabled' => true, 'countries' => array( 'DE' ) ) ) ) );

		$this->assertStringContainsString( 'no geo database is loaded', $this->notices() );
	}

	public function test_free_text_in_wpb_msg_renders_nothing(): void {
		$this->login();
		foreach ( array( '<script>alert(4)</script>Saved', 'Settings saved.', 'Your site is hacked, call 555-0100', 'nope' ) as $text ) {
			$_GET['wpb_msg'] = $text;
			$this->assertSame( '', trim( $this->notices() ), $text );
		}
	}

	public function test_a_known_code_renders_its_string_and_the_error_flag_sets_the_style(): void {
		$this->login();
		$_GET['wpb_msg'] = 'log_cleared';

		$out = $this->notices();

		$this->assertStringContainsString( 'Activity log cleared.', $out );
		$this->assertStringContainsString( 'notice-success', $out );
		$this->assertStringContainsString( 'role="status"', $out );
		$_GET['wpb_err'] = '1';
		$out = $this->notices();
		$this->assertStringContainsString( 'notice-error', $out );
		$this->assertStringContainsString( 'role="alert"', $out );
	}

	public function test_a_crafted_detail_code_shows_nothing_and_keeps_a_pending_flash(): void {
		$this->login();
		\WPBouncer\Admin\MessageCodes::flash( 'pending detail' );
		$_GET['wpb_msg'] = 'log_cleared';
		$this->notices();
		$_GET['wpb_msg'] = 'ip_blocked';
		$this->notices();

		$this->assertSame( 'pending detail', \WPBouncer\Admin\MessageCodes::take_flash(), 'codes without detail left it' );
		$_GET['wpb_msg'] = 'test_sent';
		$this->assertSame( '', trim( $this->notices() ) );
	}

	public function test_code_arguments_are_validated_before_display(): void {
		$this->login();
		$_GET['wpb_msg'] = 'ip_blocked';
		$_GET['wpb_ip']  = '<b>evil</b>';
		$this->assertSame( '', trim( $this->notices() ), 'invalid IP: nothing shown' );

		$_GET['wpb_ip'] = '198.51.100.7';
		$this->assertStringContainsString( '198.51.100.7 added to the IP blocklist.', $this->notices() );

		$_GET['wpb_msg'] = 'geo_done';
		$_GET['wpb_n']   = '1234abc';
		$this->assertStringContainsString( '1,234 ranges loaded', $this->notices() );
	}

	/* ---------------- assets ---------------- */

	public function test_assets_load_only_on_our_screen_with_a_geo_nonce(): void {
		$this->login();

		$this->admin->enqueue_assets( 'plugins.php' );
		$this->assertFalse( wp_script_is( 'wp-bouncer-admin', 'enqueued' ) );

		$this->admin->enqueue_assets( 'toplevel_page_wp-bouncer' );
		$this->assertTrue( wp_script_is( 'wp-bouncer-admin', 'enqueued' ) );
		$this->assertTrue( wp_style_is( 'wp-bouncer-admin', 'enqueued' ) );
		$data = wp_scripts()->get_data( 'wp-bouncer-admin', 'data' );
		$this->assertStringContainsString( 'geoNonce', $data );
		$this->assertStringContainsString( 'admin-ajax.php', $data );
	}
}
