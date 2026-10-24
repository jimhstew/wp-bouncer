<?php
/**
 * AdminController handlers (admin-post.php and AJAX), capability and nonce checks.
 *
 * Handlers that finish with wp_safe_redirect() + exit are driven through a
 * wp_redirect filter that throws (see PluginHelpers::redirect_of()); wp_die() is
 * turned into WPDieException by the test library. The CSV export handlers end
 * in a bare exit and are only tested up to their permission checks.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Geo\GeoImport;
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Log\BlockLog;
use WPBouncer\Plugin;
use WPBouncer\Rules\NotFoundFloodRule;
use WPBouncer\Rules\RateLimitRule;
use WPBouncer\Rules\SensitiveFileRule;
use WPBouncer\Settings;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Traffic\TrafficLog;

/**
 * @covers \WPBouncer\Admin\AdminController
 */
final class AdminControllerTest extends IntegrationTestCase {

	/** @var AdminController */
	private $admin;

	public function set_up() {
		parent::set_up();
		$this->admin = new AdminController( $this->plugin );
		$this->fake_request();
		// The default list is the real download hosts; tests fetch from a fixed address.
		add_filter(
			'wp_bouncer_geo_import_hosts',
			static function ( $hosts ) {
				$hosts[] = '93.184.216.34';
				return $hosts;
			}
		);
	}

	/* ---------------- helpers ---------------- */

	private function login( string $role = 'administrator' ): int {
		$id = self::factory()->user->create( array( 'role' => $role ) );
		wp_set_current_user( $id );
		return $id;
	}

	/** An administrator who also holds wpb_manage_firewall (a super admin on multisite). */
	private function login_network(): int {
		$id = $this->login();
		if ( is_multisite() ) {
			grant_super_admin( $id );
			wp_set_current_user( $id );
		}
		return $id;
	}

	/**
	 * Prepare a POST as the browser would send it.
	 *
	 * @param string               $action Nonce action ('' for none).
	 * @param array<string, mixed> $post   Fields.
	 */
	private function post( string $action, array $post = array() ): void {
		if ( '' !== $action ) {
			$post['_wpnonce'] = wp_create_nonce( $action );
		}
		$_POST    = $post;
		$_REQUEST = $post;
		$_SERVER['REQUEST_METHOD'] = 'POST';
	}

	/** @return array<string, mixed> The stored settings. */
	private function stored(): array {
		return (array) get_option( Settings::OPTION );
	}

	/** @return array<int, array<string, string>> */
	private function log_rows( array $filters = array() ): array {
		global $wpdb;
		return (array) ( new BlockLog( $wpdb ) )->query( $filters );
	}

	/** Run a handler, expecting a redirect. */
	private function call( string $method ): \WPBouncer\Tests\Integration\Redirected {
		return $this->redirect_of( array( $this->admin, $method ) );
	}

	/** Make wp_send_json_*() end in an exception instead of exit. */
	private function enable_ajax_capture(): void {
		add_filter( 'wp_doing_ajax', '__return_true' );
		add_filter(
			'wp_die_ajax_handler',
			static function () {
				return static function ( $message = '' ) {
					throw new \WPDieException( is_scalar( $message ) ? (string) $message : '' );
				};
			}
		);
	}

	/** Call an AJAX handler and return its decoded JSON (or the die message). */
	private function ajax( string $method ) {
		$this->enable_ajax_capture();
		ob_start();
		try {
			$this->admin->$method();
		} catch ( \WPDieException $e ) {
			$out = ob_get_clean();
			$json = json_decode( $out, true );
			return null === $json ? 'DIED:' . $e->getMessage() : $json;
		}
		ob_end_clean();
		$this->fail( 'The handler returned without wp_send_json_*().' );
	}

	private function fixture_csv(): string {
		return dirname( __DIR__, 2 ) . '/fixtures/geo-sample.csv';
	}

	/* ---------------- registration ---------------- */

	public function test_register_hooks_every_action(): void {
		$this->admin->register();

		foreach ( array( 'save', 'toggle_rule', 'block_ip', 'unlock_ip', 'clear_log', 'export_log', 'clear_traffic', 'export_traffic', 'geo_import', 'geo_step', 'geo_cancel', 'test_alert', 'uploads_probe', 'uploads_sync', 'ip_setup' ) as $name ) {
			$method = 'handle_' . $name;
			$this->assertNotFalse( has_action( 'admin_post_wp_bouncer_' . $name, array( $this->admin, $method ) ), $name );
			$this->assertFalse( has_action( 'admin_post_nopriv_wp_bouncer_' . $name ), "{$name} must not be reachable when logged out" );
		}
		$this->assertNotFalse( has_action( 'wp_ajax_wp_bouncer_geo_step', array( $this->admin, 'ajax_geo_step' ) ) );
		$this->assertFalse( has_action( 'wp_ajax_nopriv_wp_bouncer_geo_step' ) );
		$this->assertNotFalse( has_action( 'admin_menu', array( $this->admin, 'add_menu' ) ) );
		$this->assertNotFalse( has_filter( 'plugin_action_links_' . plugin_basename( WP_BOUNCER_FILE ), array( $this->admin, 'action_links' ) ) );
	}

	/* ---------------- permission matrix ---------------- */

	/** @return array<string, array{0: string, 1: string}> */
	public static function protected_handlers(): array {
		return array(
			'save'           => array( 'handle_save', 'wp_bouncer_save' ),
			'toggle_rule'    => array( 'handle_toggle_rule', 'wp_bouncer_toggle_rule' ),
			'block_ip'       => array( 'handle_block_ip', 'wp_bouncer_block_ip' ),
			'unlock_ip'      => array( 'handle_unlock_ip', 'wp_bouncer_unlock_ip' ),
			'clear_log'      => array( 'handle_clear_log', 'wp_bouncer_clear_log' ),
			'export_log'     => array( 'handle_export_log', 'wp_bouncer_export_log' ),
			'clear_traffic'  => array( 'handle_clear_traffic', 'wp_bouncer_clear_traffic' ),
			'export_traffic' => array( 'handle_export_traffic', 'wp_bouncer_export_traffic' ),
			'geo_import'     => array( 'handle_geo_import', 'wp_bouncer_geo_import' ),
			'geo_step'       => array( 'handle_geo_step', 'wp_bouncer_geo_step' ),
			'geo_cancel'     => array( 'handle_geo_cancel', 'wp_bouncer_geo_cancel' ),
			'test_alert'     => array( 'handle_test_alert', 'wp_bouncer_test_alert' ),
			'uploads_probe'  => array( 'handle_uploads_probe', 'wp_bouncer_uploads_probe' ),
			'uploads_sync'   => array( 'handle_uploads_sync', 'wp_bouncer_uploads_sync' ),
			'ip_setup'       => array( 'handle_ip_setup', 'wp_bouncer_ip_setup' ),
		);
	}

	/**
	 * @dataProvider protected_handlers
	 */
	public function test_a_user_without_manage_options_is_refused_even_with_a_valid_nonce( string $method, string $action ): void {
		$this->login( 'editor' );
		$this->post( $action, array( 'ip' => '198.51.100.1', 'rule' => 'waf', 'tab' => 'general' ) );
		$before = $this->stored();

		$e = $this->die_of( array( $this->admin, $method ) );

		$this->assertStringContainsString( 'permission', $e->getMessage() );
		$this->assertSame( $before, $this->stored(), 'nothing was changed' );
	}

	/**
	 * @dataProvider protected_handlers
	 */
	public function test_a_logged_out_visitor_is_refused( string $method, string $action ): void {
		wp_set_current_user( 0 );
		$this->post( $action );

		$this->die_of( array( $this->admin, $method ) );
		$this->addToAssertionCount( 1 );
	}

	/**
	 * @dataProvider protected_handlers
	 */
	public function test_a_missing_nonce_is_refused( string $method ): void {
		$this->login();
		$this->post( '', array( 'ip' => '198.51.100.1', 'rule' => 'waf', 'tab' => 'general' ) );
		$before = $this->stored();

		$this->die_of( array( $this->admin, $method ) );

		$this->assertSame( $before, $this->stored() );
	}

	/**
	 * @dataProvider protected_handlers
	 */
	public function test_a_forged_nonce_is_refused( string $method ): void {
		$this->login();
		$this->post( '', array( '_wpnonce' => 'deadbeef00', 'ip' => '198.51.100.1', 'rule' => 'waf', 'tab' => 'general' ) );
		$before = $this->stored();

		$this->die_of( array( $this->admin, $method ) );

		$this->assertSame( $before, $this->stored() );
	}

	/**
	 * @dataProvider protected_handlers
	 */
	public function test_a_nonce_for_another_action_is_refused( string $method, string $action ): void {
		$this->login();
		$other = 'wp_bouncer_save' === $action ? 'wp_bouncer_clear_log' : 'wp_bouncer_save';
		$this->post( $other, array( 'ip' => '198.51.100.1', 'rule' => 'waf', 'tab' => 'general' ) );
		$before = $this->stored();

		$this->die_of( array( $this->admin, $method ) );

		$this->assertSame( $before, $this->stored() );
	}

	public function test_a_refused_clear_log_keeps_the_rows(): void {
		$this->plugin->log()->record( array( 'ip' => '198.51.100.1', 'rule' => 'waf' ) );
		$this->login( 'subscriber' );
		$this->post( 'wp_bouncer_clear_log' );

		$this->die_of( array( $this->admin, 'handle_clear_log' ) );

		$this->assertCount( 1, $this->log_rows() );
	}

	public function test_ajax_step_refuses_missing_capability_and_bad_nonce(): void {
		$this->login( 'editor' );
		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'wp_bouncer_geo_step' );
		$out = $this->ajax( 'ajax_geo_step' );
		$this->assertFalse( $out['success'] );
		$this->assertStringContainsString( 'permission', $out['data']['message'] );

		$this->login();
		$_REQUEST['_ajax_nonce'] = 'bad';
		$this->assertStringStartsWith( 'DIED:', (string) $this->ajax( 'ajax_geo_step' ) );

		unset( $_REQUEST['_ajax_nonce'] );
		$this->assertStringStartsWith( 'DIED:', (string) $this->ajax( 'ajax_geo_step' ) );
	}

	/* ---------------- save ---------------- */

	public function test_save_sanitises_input_through_settings(): void {
		$this->login();
		$this->post(
			'wp_bouncer_save',
			array(
				'tab'        => 'general',
				'wp_bouncer' => array(
					'mode'               => 'monitor',
					'ip_source'          => 'evil_source',
					'allowlist'          => "198.51.100.0/24\nnot-an-ip\n2001:db8::1",
					'log_retention_days' => '99999',
					'block_message'      => '<b>Go</b> <script>alert(1)</script> away',
					'geo_header'         => 'bad header!',
					'alerts'             => array( 'enabled' => '1', 'recipients' => "ops@example.org\nbogus", 'new_admin' => '1' ),
				),
			)
		);

		$r = $this->call( 'handle_save' );

		$s = $this->stored();
		$this->assertSame( 'monitor', $s['mode'] );
		$this->assertSame( 'remote_addr', $s['ip_source'], 'unknown choice falls back to the default' );
		$this->assertSame( array( '198.51.100.0/24', '2001:db8::1' ), $s['allowlist'] );
		$this->assertSame( 365, $s['log_retention_days'] );
		$this->assertStringNotContainsString( '<', $s['block_message'] );
		$this->assertSame( 'CF-IPCountry', $s['geo_header'] );
		$this->assertSame( array( 'ops@example.org' ), $s['alerts']['recipients'] );
		$this->assertTrue( $s['alerts']['enabled'] );
		$this->assertFalse( $s['alerts']['plugin_changes'], 'unticked checkbox on this tab means off' );
		$this->assertSame( 'Settings saved.', $r->message() );
		$this->assertFalse( $r->is_error() );
		$this->assertStringContainsString( 'tab=general', $r->location );
		$this->assertTrue( $this->plugin->settings()->is_monitor_mode(), 'the live settings were reloaded' );
	}

	public function test_saving_one_tab_leaves_the_other_tabs_alone(): void {
		$this->set_settings( array( 'traffic' => array( 'enabled' => true ), 'rules' => array( 'waf' => array( 'xss' => false ) ) ) );
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'general', 'wp_bouncer' => array( 'mode' => 'monitor' ) ) );

		$this->call( 'handle_save' );

		$s = $this->stored();
		$this->assertTrue( $s['traffic']['enabled'] );
		$this->assertFalse( $s['rules']['waf']['xss'] );
	}

	public function test_saving_the_rules_tab_treats_missing_checkboxes_as_off(): void {
		$this->login();
		$this->post(
			'wp_bouncer_save',
			array(
				'tab'        => 'rules',
				'wp_bouncer' => array(
					'rules' => array(
						'waf'           => array( 'enabled' => '1', 'sqli' => '1' ),
						'login_lockout' => array( 'enabled' => '1', 'max_attempts' => '0', 'lockout_minutes' => '5' ),
					),
				),
			)
		);

		$this->call( 'handle_save' );

		$rules = $this->stored()['rules'];
		$this->assertTrue( $rules['waf']['enabled'] );
		$this->assertTrue( $rules['waf']['sqli'] );
		$this->assertFalse( $rules['waf']['xss'] );
		$this->assertSame( 1, $rules['login_lockout']['max_attempts'], 'clamped to the minimum' );
		$this->assertSame( 5, $rules['login_lockout']['lockout_minutes'] );
		$this->assertFalse( $rules['xmlrpc']['enabled'], 'a rule absent from the form is switched off' );
		$this->assertTrue( $rules['country']['enabled'] === false, 'the countries tab is untouched' );
	}

	public function test_saving_the_traffic_tab(): void {
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'traffic', 'wp_bouncer' => array( 'traffic' => array( 'enabled' => '1', 'retention_days' => '30', 'skip_admins' => '1' ) ) ) );

		$r = $this->call( 'handle_save' );

		$t = $this->stored()['traffic'];
		$this->assertTrue( $t['enabled'] );
		$this->assertSame( 7, $t['retention_days'], 'never more than a week' );
		$this->assertTrue( $t['skip_admins'] );
		$this->assertFalse( $t['skip_background'] );
		$this->assertStringContainsString( 'tab=traffic', $r->location );
	}

	public function test_save_with_an_unknown_tab_is_an_error_and_changes_nothing(): void {
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'nonsense', 'wp_bouncer' => array( 'mode' => 'monitor' ) ) );
		$before = $this->stored();

		$r = $this->call( 'handle_save' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( 'Unknown settings section.', $r->message() );
		$this->assertSame( $before, $this->stored() );
	}

	public function test_save_with_no_form_data_resets_that_tab_to_empty_not_to_garbage(): void {
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'general' ) );

		$this->call( 'handle_save' );

		$s = $this->stored();
		$this->assertSame( 'enforce', $s['mode'] );
		$this->assertSame( array(), $s['allowlist'] );
		$this->assertNotSame( '', $s['block_message'] );
	}

	public function test_save_refuses_to_lock_the_admin_out_and_allowlists_them(): void {
		$this->login();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.55' ) );
		$this->post( 'wp_bouncer_save', array( 'tab' => 'rules', 'wp_bouncer' => array( 'rules' => array( 'ip_blocklist' => array( 'enabled' => '1', 'ips' => '198.51.100.0/24' ) ) ) ) );

		$r = $this->call( 'handle_save' );

		$s = $this->stored();
		$this->assertContains( '198.51.100.55', $s['allowlist'] );
		$this->assertContains( '198.51.100.0/24', $s['rules']['ip_blocklist']['ips'] );
		$this->assertStringContainsString( 'would have blocked you', $r->message() );
		$this->assertStringContainsString( '198.51.100.55', $r->message() );
	}

	public function test_save_warns_when_the_user_agent_rule_would_block_the_admin(): void {
		$this->login();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.56', 'HTTP_USER_AGENT' => 'MyOddBrowser/1.0' ) );
		$this->post( 'wp_bouncer_save', array( 'tab' => 'rules', 'wp_bouncer' => array( 'rules' => array( 'user_agent' => array( 'enabled' => '1', 'patterns' => 'MyOddBrowser' ) ) ) ) );

		$r = $this->call( 'handle_save' );

		$this->assertContains( '198.51.100.56', $this->stored()['allowlist'] );
		$this->assertStringContainsString( 'would have blocked you', $r->message() );
	}

	public function test_save_does_not_allowlist_when_nothing_would_block_the_admin(): void {
		$this->login();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.57' ) );
		$this->post( 'wp_bouncer_save', array( 'tab' => 'rules', 'wp_bouncer' => array( 'rules' => array( 'ip_blocklist' => array( 'enabled' => '1', 'ips' => '203.0.113.0/24' ) ) ) ) );

		$r = $this->call( 'handle_save' );

		$this->assertSame( array(), $this->stored()['allowlist'] );
		$this->assertSame( 'Settings saved.', $r->message() );
	}

	/* ---------------- toggle rule ---------------- */

	public function test_toggle_rule_flips_the_switch(): void {
		$this->login();
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'waf' ) );
		$r = $this->call( 'handle_toggle_rule' );
		$this->assertFalse( $this->stored()['rules']['waf']['enabled'] );
		$this->assertStringContainsString( 'disabled', $r->message() );

		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'waf' ) );
		$r = $this->call( 'handle_toggle_rule' );
		$this->assertTrue( $this->stored()['rules']['waf']['enabled'] );
		$this->assertStringContainsString( 'enabled', $r->message() );
		$this->assertStringContainsString( 'tab=dashboard', $r->location );
	}

	public function test_toggle_on_adds_the_admins_ip_to_the_allowlist_when_it_would_lock_them_out(): void {
		$this->login();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.55' ) );
		$this->set_settings( array( 'rules' => array( 'ip_blocklist' => array( 'enabled' => false, 'ips' => array( '198.51.100.55' ) ) ) ) );
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'ip_blocklist' ) );

		$r = $this->call( 'handle_toggle_rule' );

		$s = $this->stored();
		$this->assertTrue( $s['rules']['ip_blocklist']['enabled'] );
		$this->assertContains( '198.51.100.55', $s['allowlist'] );
		$this->assertStringContainsString( 'would have blocked you', $r->message() );
	}

	public function test_toggle_on_is_refused_when_the_admin_address_is_shared(): void {
		$country = $this->germany_only();
		$country['rules']['country']['enabled'] = false;
		$this->set_settings( array_replace_recursive( $country, array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$this->login();
		$before = $this->stored();
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'country' ) );

		$r = $this->call( 'handle_toggle_rule' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( 'shared_refusal', $r->code() );
		$this->assertSame( $before, $this->stored(), 'nothing saved' );
	}

	public function test_toggle_on_a_harmless_rule_leaves_the_allowlist_alone(): void {
		$this->login();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.58' ) );
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'ip_blocklist' ) );

		$this->call( 'handle_toggle_rule' );

		$this->assertSame( array(), $this->stored()['allowlist'] );
	}

	public function test_toggle_rule_with_an_unknown_rule_is_an_error(): void {
		$this->login();
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'no_such_rule' ) );
		$before = $this->stored();

		$r = $this->call( 'handle_toggle_rule' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( 'Unknown rule.', $r->message() );
		$this->assertSame( $before, $this->stored() );
	}

	public function test_toggle_rule_with_no_rule_is_an_error(): void {
		$this->login();
		$this->post( 'wp_bouncer_toggle_rule' );

		$this->assertTrue( $this->call( 'handle_toggle_rule' )->is_error() );
	}

	/* ---------------- block IP ---------------- */

	/**
	 * Prepare the Block IP GET link as the browser would send it.
	 *
	 * @param string      $ip       Value of the ip argument.
	 * @param string|null $nonce_ip Address the nonce was made for (default: the same).
	 * @param array       $extra    More query arguments.
	 */
	private function get_block( string $ip, ?string $nonce_ip = null, array $extra = array() ): void {
		$get = array_merge(
			array(
				'ip'       => $ip,
				'_wpnonce' => wp_create_nonce( 'wp_bouncer_block_ip|' . ( $nonce_ip ?? $ip ) ),
			),
			$extra
		);
		$_GET     = $get;
		$_POST    = array();
		$_REQUEST = $get;
	}

	public function test_block_ip_adds_to_the_blocklist_and_enables_the_rule(): void {
		$this->set_settings( array( 'rules' => array( 'ip_blocklist' => array( 'enabled' => false ) ) ) );
		$this->login();
		$this->get_block( '198.51.100.99' );

		$r = $this->call( 'handle_block_ip' );

		$rule = $this->stored()['rules']['ip_blocklist'];
		$this->assertTrue( $rule['enabled'] );
		$this->assertContains( '198.51.100.99', $rule['ips'] );
		$this->assertSame( 'ip_blocked', $r->code() );
		$this->assertStringContainsString( 'added to the IP blocklist', $r->message() );
		$this->assertStringContainsString( 'tab=log', $r->location );
	}

	public function test_block_ip_returns_to_the_traffic_tab(): void {
		$this->login();
		$this->get_block( '192.0.2.7', null, array( 'back' => 'traffic' ) );

		$r = $this->call( 'handle_block_ip' );

		$this->assertContains( '192.0.2.7', $this->stored()['rules']['ip_blocklist']['ips'] );
		$this->assertStringContainsString( 'tab=traffic', $r->location );
	}

	public function test_block_ip_nonce_for_one_address_is_refused_for_another(): void {
		$this->login();
		$this->get_block( '198.51.100.2', '198.51.100.1' );

		try {
			$this->call( 'handle_block_ip' );
			$this->fail( 'expected a 403' );
		} catch ( \WPDieException $e ) {
			$this->assertSame( 403, $e->getCode() );
		}
		$this->assertSame( array(), $this->stored()['rules']['ip_blocklist']['ips'] );
	}

	public function test_block_ip_refuses_a_range_even_with_a_matching_nonce(): void {
		$this->login();
		$this->get_block( '192.0.2.0/24' );

		$r = $this->call( 'handle_block_ip' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( array(), $this->stored()['rules']['ip_blocklist']['ips'] );
	}

	public function test_block_ip_ignores_post_values(): void {
		$this->login();
		$_GET     = array();
		$_POST    = array( 'ip' => '198.51.100.9', '_wpnonce' => wp_create_nonce( 'wp_bouncer_block_ip|198.51.100.9' ) );
		$_REQUEST = $_POST;

		try {
			$this->call( 'handle_block_ip' );
			$this->fail( 'expected a 403' );
		} catch ( \WPDieException $e ) {
			$this->assertSame( 403, $e->getCode() );
		}
	}

	public function test_block_ip_url_carries_a_per_address_nonce(): void {
		$url = AdminController::block_ip_url( '2001:db8::1', 'traffic' );
		parse_str( (string) wp_parse_url( html_entity_decode( $url ), PHP_URL_QUERY ), $q );

		$this->assertSame( '2001:db8::1', $q['ip'] );
		$this->assertSame( 'traffic', $q['back'] );
		$this->assertSame( 1, wp_verify_nonce( $q['_wpnonce'], 'wp_bouncer_block_ip|2001:db8::1' ) ?: 0 );
		$this->assertFalse( wp_verify_nonce( $q['_wpnonce'], 'wp_bouncer_block_ip|2001:db8::2' ) );
	}

	public function test_block_ip_rejects_garbage(): void {
		$this->login();
		foreach ( array( 'not-an-ip', '', '999.1.1.1', '198.51.100.1/99' ) as $bad ) {
			$this->get_block( $bad );
			$r = $this->call( 'handle_block_ip' );
			$this->assertTrue( $r->is_error(), "'{$bad}'" );
		}
		$this->assertSame( array(), $this->stored()['rules']['ip_blocklist']['ips'] );
	}

	public function test_block_ip_with_markup_in_the_address_is_refused(): void {
		$this->login();
		$this->get_block( '<script>alert(1)</script>' );

		try {
			$this->call( 'handle_block_ip' );
			$this->fail( 'expected a 403' );
		} catch ( \WPDieException $e ) {
			$this->addToAssertionCount( 1 );
		}
		$this->assertSame( array(), $this->stored()['rules']['ip_blocklist']['ips'] );
	}

	public function test_block_ip_refuses_the_admins_own_address(): void {
		$this->login();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.55' ) );

		$this->get_block( '198.51.100.55' );
		$r = $this->call( 'handle_block_ip' );
		$this->assertTrue( $r->is_error() );
		$this->assertSame( 'Refusing to block your own IP address.', $r->message() );
		$this->assertSame( array(), $this->stored()['rules']['ip_blocklist']['ips'] );
	}

	public function test_block_ip_does_not_duplicate_an_entry(): void {
		$this->login();
		for ( $i = 0; $i < 2; $i++ ) {
			$this->get_block( '198.51.100.99' );
			$this->call( 'handle_block_ip' );
		}

		$this->assertSame( array( '198.51.100.99' ), $this->stored()['rules']['ip_blocklist']['ips'] );
	}

	/* ---------------- unlock IP ---------------- */

	public function test_unlock_ip_lifts_lockouts_and_bans(): void {
		$ip    = '198.51.100.77';
		$store = $this->plugin->store();
		$this->plugin->login_guard()->record_failure( $ip, 'admin' ); // Banned username: instant lockout.
		$store->set( RateLimitRule::ban_key( $ip ), 1, 600 );
		$store->set( RateLimitRule::counter_key( $ip ), 9, 600 );
		$store->set( SensitiveFileRule::ban_key( $ip ), 1, 600 );
		$store->set( NotFoundFloodRule::ban_key( $ip ), 1, 600 );
		$store->set( NotFoundFloodRule::counter_key( $ip ), 9, 600 );
		$this->assertTrue( $this->plugin->login_guard()->is_locked_out( $ip ) );
		$this->login();
		$this->post( 'wp_bouncer_unlock_ip', array( 'ip' => $ip ) );

		$r = $this->call( 'handle_unlock_ip' );

		$this->assertFalse( $this->plugin->login_guard()->is_locked_out( $ip ) );
		foreach ( array( RateLimitRule::ban_key( $ip ), RateLimitRule::counter_key( $ip ), SensitiveFileRule::ban_key( $ip ), NotFoundFloodRule::ban_key( $ip ), NotFoundFloodRule::counter_key( $ip ) ) as $key ) {
			$this->assertNull( $store->get( $key ), $key );
		}
		$this->assertStringContainsString( $ip, $r->message() );
		$this->assertFalse( $r->is_error() );
		$this->assertStringContainsString( 'tab=tools', $r->location );
	}

	public function test_unlock_ip_rejects_invalid_addresses_and_ranges(): void {
		$this->login();
		foreach ( array( 'abc', '', '198.51.100.0/24' ) as $bad ) {
			$this->post( 'wp_bouncer_unlock_ip', array( 'ip' => $bad ) );
			$r = $this->call( 'handle_unlock_ip' );
			$this->assertTrue( $r->is_error(), "'{$bad}'" );
			$this->assertSame( 'That is not a valid IP address.', $r->message() );
		}
	}

	/* ---------------- clear logs ---------------- */

	public function test_clear_log_empties_the_activity_log(): void {
		$this->plugin->log()->record( array( 'ip' => '198.51.100.1' ) );
		$this->login();
		$this->post( 'wp_bouncer_clear_log' );

		$r = $this->call( 'handle_clear_log' );

		$rows = $this->log_rows();
		$this->assertCount( 1, $rows, 'only the audit row of the clearing itself is left' );
		$this->assertSame( 'settings', $rows[0]['rule'] );
		$this->assertSame( 'Activity log cleared.', $r->message() );
		$this->assertStringContainsString( 'tab=log', $r->location );
	}

	public function test_clear_traffic_empties_the_traffic_log(): void {
		global $wpdb;
		$this->plugin->traffic_log()->record( array( 'ip' => '198.51.100.1' ) );
		$this->login();
		$this->post( 'wp_bouncer_clear_traffic' );

		$r = $this->call( 'handle_clear_traffic' );

		$this->assertSame( 0, ( new TrafficLog( $wpdb ) )->count() );
		$this->assertSame( 'Traffic log cleared.', $r->message() );
	}

	/* ---------------- test alert ---------------- */

	public function test_test_alert_sends_mail_and_names_the_recipients(): void {
		$this->set_settings( array( 'alerts' => array( 'recipients' => array( 'ops@example.org' ) ) ) );
		$this->login();
		$this->post( 'wp_bouncer_test_alert' );
		$this->clear_mail();

		$r = $this->call( 'handle_test_alert' );

		$this->assertCount( 1, $this->sent_mail() );
		$this->assertStringContainsString( 'Test email sent to ops@example.org', $r->message() );
		$this->assertFalse( $r->is_error() );
		$this->assertStringContainsString( 'tab=general', $r->location );
	}

	public function test_test_alert_reports_the_mail_error(): void {
		add_filter( 'wp_mail_from', static function () {
			return 'broken address';
		} );
		$this->login();
		$this->post( 'wp_bouncer_test_alert' );

		$r = $this->call( 'handle_test_alert' );

		$this->assertTrue( $r->is_error() );
		$message = $r->message();
		$this->assertStringContainsString( 'The test email was not sent:', $message );
		$this->assertStringContainsString( 'broken address', $message );
	}

	/* ---------------- uploads ---------------- */

	public function test_uploads_probe_redirects_with_the_result(): void {
		add_filter(
			'pre_http_request',
			static function () {
				return array( 'headers' => array(), 'body' => 'Forbidden', 'response' => array( 'code' => 403, 'message' => '' ), 'cookies' => array(), 'filename' => null );
			}
		);
		$this->login_network();
		$this->post( 'wp_bouncer_uploads_probe' );

		$r = $this->call( 'handle_uploads_probe' );

		$this->assertFalse( $r->is_error() );
		$this->assertStringStartsWith( 'Protected:', $r->message() );
		$this->assertStringContainsString( 'tab=rules', $r->location );
	}

	public function test_uploads_probe_flags_unprotected_as_an_error(): void {
		add_filter(
			'pre_http_request',
			static function () {
				return array( 'headers' => array(), 'body' => 'wpb-php-ran', 'response' => array( 'code' => 200, 'message' => '' ), 'cookies' => array(), 'filename' => null );
			}
		);
		$this->login_network();
		$this->post( 'wp_bouncer_uploads_probe' );

		$r = $this->call( 'handle_uploads_probe' );

		$this->assertTrue( $r->is_error() );
		$this->assertStringStartsWith( 'Not protected:', $r->message() );
	}

	public function test_uploads_sync_writes_the_block_then_removes_it(): void {
		$this->login_network();
		$this->post( 'wp_bouncer_uploads_sync' );
		$r = $this->call( 'handle_uploads_sync' );
		$this->assertTrue( UploadsGuard::block_present() );
		$this->assertSame( 'The block is in wp-content/uploads/.htaccess.', $r->message() );

		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'htaccess' => false ) ) ) );
		$this->post( 'wp_bouncer_uploads_sync' );
		$r = $this->call( 'handle_uploads_sync' );
		$this->assertFalse( UploadsGuard::block_present() );
		$this->assertStringContainsString( 'was removed', $r->message() );
	}

	public function test_uploads_sync_reports_an_unwritable_folder(): void {
		chmod( $this->uploads_dir, 0555 );
		if ( is_writable( $this->uploads_dir ) ) {
			chmod( $this->uploads_dir, 0755 );
			$this->markTestSkipped( 'Directory permissions are not enforced here (running as root?).' );
		}
		$this->login_network();
		$this->post( 'wp_bouncer_uploads_sync' );

		$r = $this->call( 'handle_uploads_sync' );
		chmod( $this->uploads_dir, 0755 );

		$this->assertTrue( $r->is_error() );
		$this->assertStringContainsString( 'Could not update', $r->message() );
	}

	public function test_probe_messages_cover_every_result(): void {
		foreach ( array( 'protected', 'unprotected', 'broken', 'unknown', 'anything-else' ) as $result ) {
			$this->assertNotSame( '', AdminController::probe_message( $result ) );
		}
		$this->assertNotSame( AdminController::probe_message( 'protected' ), AdminController::probe_message( 'unprotected' ) );
	}

	/* ---------------- geo import (admin-post) ---------------- */

	public function test_geo_import_without_a_file_or_url_is_an_error(): void {
		$this->login();
		$this->post( 'wp_bouncer_geo_import' );

		$r = $this->call( 'handle_geo_import' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( 'Choose a file or enter a URL.', $r->message() );
	}

	public function test_geo_import_rejects_invalid_urls(): void {
		$this->login_network();
		foreach ( array( 'not a url', 'ftp://example.com/geo.csv', 'javascript:alert(1)', 'http://localhost:1/geo.csv' ) as $bad ) {
			$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => $bad ) );
			$r = $this->call( 'handle_geo_import' );
			$this->assertTrue( $r->is_error(), $bad );
			$this->assertNull( ( new GeoImport( $this->plugin->geo_database() ) )->status(), $bad );
		}
	}

	public function test_geo_import_reports_a_failed_download(): void {
		add_filter( 'pre_http_request', static function () {
			return new \WP_Error( 'http_request_failed', 'Connection refused' );
		} );
		$this->login_network();
		$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => 'https://93.184.216.34/geo.csv.gz' ) );

		$r = $this->call( 'handle_geo_import' );

		$this->assertTrue( $r->is_error() );
		$this->assertStringContainsString( 'Download failed: The file could not be downloaded.', $r->message() );
	}

	public function test_geo_import_by_url_starts_an_import_and_keeps_the_old_data_if_the_file_is_wrong(): void {
		$this->plugin->geo_database()->insert_batch( array( array( 'from' => str_repeat( '0', 31 ) . '1', 'to' => str_repeat( '0', 31 ) . '2', 'country' => 'AU' ) ) );
		$body = "<html><body>404 Not Found</body></html>\n";
		add_filter(
			'pre_http_request',
			static function ( $pre, $args ) use ( $body ) {
				file_put_contents( $args['filename'], $body );
				return array( 'headers' => array(), 'body' => '', 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => $args['filename'] );
			},
			10,
			2
		);
		$this->login_network();
		$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => 'https://93.184.216.34/geo.csv' ) );

		$r = $this->call( 'handle_geo_import' );

		$this->assertTrue( $r->is_error() );
		$this->assertStringNotContainsString( 'not valid', $r->message(), 'the URL was accepted; the file was refused' );
		$this->assertSame( 1, $this->plugin->geo_database()->count(), 'existing ranges untouched' );
		$this->assertNull( $this->plugin->geo_import()->status() );
	}

	public function test_geo_import_by_url_starts_then_the_steps_load_the_ranges(): void {
		$csv = (string) file_get_contents( $this->fixture_csv() );
		add_filter(
			'pre_http_request',
			static function ( $pre, $args ) use ( $csv ) {
				file_put_contents( $args['filename'], $csv );
				return array( 'headers' => array(), 'body' => '', 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array(), 'filename' => $args['filename'] );
			},
			10,
			2
		);
		$this->login_network();
		$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => 'https://93.184.216.34/geo.csv' ) );

		$r = $this->call( 'handle_geo_import' );

		$this->assertFalse( $r->is_error() );
		$this->assertSame( '', $r->message() );
		$this->assertStringContainsString( 'tab=tools', $r->location );
		$state = $this->plugin->geo_import()->status();
		$this->assertNotNull( $state );
		$this->assertSame( '93.184.216.34/…/geo.csv', $state['source'] );

		$this->post( 'wp_bouncer_geo_step' );
		$r = $this->call( 'handle_geo_step' );

		$this->assertStringContainsString( 'Geo database imported: 5 ranges loaded, 2 lines skipped.', $r->message() );
		$this->assertNull( $this->plugin->geo_import()->status() );
		$this->assertSame( 'AU', $this->plugin->geo_database()->lookup( '1.0.0.5' ) );
	}

	public function test_geo_import_refuses_a_file_that_was_not_really_uploaded(): void {
		$tmp = $this->uploads_dir . '/fake.csv';
		copy( $this->fixture_csv(), $tmp );
		$_FILES['geo_file'] = array( 'name' => 'fake.csv', 'tmp_name' => $tmp, 'error' => UPLOAD_ERR_OK, 'size' => filesize( $tmp ), 'type' => 'text/csv' );
		$this->login();
		$this->post( 'wp_bouncer_geo_import' );

		$r = $this->call( 'handle_geo_import' );

		$this->assertTrue( $r->is_error(), 'is_uploaded_file() stops a path the browser did not upload' );
		$this->assertStringContainsString( 'did not arrive', $r->message() );
		$this->assertNull( $this->plugin->geo_import()->status() );
	}

	public function test_geo_import_rejects_the_wrong_file_type_and_upload_errors(): void {
		$this->login();
		$_FILES['geo_file'] = array( 'name' => 'geo.exe', 'tmp_name' => '/tmp/x', 'error' => UPLOAD_ERR_OK, 'size' => 1, 'type' => '' );
		$this->post( 'wp_bouncer_geo_import' );
		$r = $this->call( 'handle_geo_import' );
		$this->assertStringContainsString( 'Please upload a .csv or .csv.gz file.', $r->message() );

		$_FILES['geo_file'] = array( 'name' => 'geo.csv', 'tmp_name' => '', 'error' => UPLOAD_ERR_INI_SIZE, 'size' => 0, 'type' => '' );
		$this->post( 'wp_bouncer_geo_import' );
		$r = $this->call( 'handle_geo_import' );
		$this->assertTrue( $r->is_error() );
		$this->assertStringContainsString( 'larger than this server accepts', $r->message() );

		$_FILES['geo_file'] = array( 'name' => 'geo.csv', 'tmp_name' => '', 'error' => UPLOAD_ERR_PARTIAL, 'size' => 0, 'type' => '' );
		$this->post( 'wp_bouncer_geo_import' );
		$this->assertStringContainsString( 'interrupted', $this->call( 'handle_geo_import' )->message() );
	}

	public function test_geo_import_explains_a_body_over_post_max_size_even_though_the_nonce_is_gone(): void {
		$this->login();
		$_POST                     = array();
		$_REQUEST                  = array();
		$_SERVER['CONTENT_LENGTH'] = '99999999';

		$r = $this->call( 'handle_geo_import' );

		$this->assertTrue( $r->is_error() );
		$this->assertStringContainsString( 'larger than this server accepts', $r->message() );
	}

	public function test_upload_error_messages(): void {
		$this->assertStringContainsString( 'larger than this server accepts', AdminController::upload_error_message( UPLOAD_ERR_FORM_SIZE ) );
		$this->assertStringContainsString( 'interrupted', AdminController::upload_error_message( UPLOAD_ERR_PARTIAL ) );
		$this->assertStringContainsString( 'PHP upload error 7', AdminController::upload_error_message( UPLOAD_ERR_CANT_WRITE ) );
	}

	public function test_geo_step_without_an_import_is_an_error(): void {
		$this->login();
		$this->post( 'wp_bouncer_geo_step' );

		$r = $this->call( 'handle_geo_step' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( 'No geo database import is running.', $r->message() );
	}

	public function test_geo_step_continues_until_done_without_javascript(): void {
		add_filter( 'wp_bouncer_geo_step_seconds', '__return_zero' );
		$big = $this->uploads_dir . '/big.csv';
		$out = "ip_start,ip_end,country\n";
		for ( $i = 0; $i < 1200; $i++ ) {
			$out .= '40.0.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . ',40.0.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . ",FR\n";
		}
		file_put_contents( $big, $out );
		$this->plugin->geo_import()->start( $big, 'big.csv' );
		$this->login();

		$steps = 0;
		do {
			$this->post( 'wp_bouncer_geo_step' );
			$r = $this->call( 'handle_geo_step' );
			++$steps;
			$this->assertLessThan( 15, $steps );
		} while ( null !== $this->plugin->geo_import()->status() );

		$this->assertGreaterThan( 1, $steps );
		$this->assertStringContainsString( 'ranges loaded', $r->message() );
	}

	public function test_geo_cancel_keeps_loaded_ranges(): void {
		add_filter( 'wp_bouncer_geo_step_seconds', '__return_zero' );
		$big = $this->uploads_dir . '/big.csv';
		$out = '';
		for ( $i = 0; $i < 1200; $i++ ) {
			$out .= '41.0.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . ',41.0.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . ",FR\n";
		}
		file_put_contents( $big, $out );
		$this->plugin->geo_import()->start( $big, 'big.csv' );
		$this->plugin->geo_import()->step( 0.0 );
		$this->login();
		$this->post( 'wp_bouncer_geo_cancel' );

		$r = $this->call( 'handle_geo_cancel' );

		$this->assertNull( $this->plugin->geo_import()->status() );
		$this->assertStringContainsString( 'Import stopped', $r->message() );
		$this->assertGreaterThan( 0, $this->plugin->geo_database()->count() );
	}

	/* ---------------- geo import (AJAX) ---------------- */

	public function test_ajax_geo_step_reports_progress_and_completion(): void {
		$this->plugin->geo_import()->start( $this->fixture_csv(), 'sample.csv' );
		$this->login();
		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'wp_bouncer_geo_step' );

		$out = $this->ajax( 'ajax_geo_step' );

		$this->assertTrue( $out['success'] );
		$this->assertTrue( $out['data']['done'] );
		$this->assertSame( 100, $out['data']['percent'] );
		$this->assertSame( 5, $out['data']['imported'] );
		$this->assertArrayNotHasKey( 'message', $out['data'] );
	}

	public function test_ajax_geo_step_without_an_import_returns_a_json_error(): void {
		$this->login();
		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'wp_bouncer_geo_step' );

		$out = $this->ajax( 'ajax_geo_step' );

		$this->assertFalse( $out['success'] );
		$this->assertSame( 'No geo database import is running.', $out['data']['message'] );
	}

	/* ---------------- export: permission only ---------------- */

	public function test_exports_are_not_reachable_without_the_right_nonce_action(): void {
		$this->login();
		// A nonce for the other export must not unlock this one.
		$this->post( 'wp_bouncer_export_traffic' );
		$this->die_of( array( $this->admin, 'handle_export_log' ) );
		$this->post( 'wp_bouncer_export_log' );
		$this->die_of( array( $this->admin, 'handle_export_traffic' ) );
		$this->addToAssertionCount( 1 );
	}

	/* ---------------- request filters and helpers ---------------- */

	public function test_log_filters_from_request_are_sanitised(): void {
		$_REQUEST = array( 'rule' => 'WAF<script>', 'log_action' => 'blocked', 'country' => 'de', 's' => '  <b>needle</b> ', 'other' => 'x' );

		$filters = AdminController::log_filters_from_request();

		$this->assertSame( array( 'rule' => 'wafscript', 'action' => 'blocked', 'country' => 'DE', 'search' => 'needle' ), $filters );
		$this->assertSame( array( 'rule' => 'wafscript', 'log_action' => 'blocked', 'country' => 'DE', 's' => 'needle' ), AdminController::log_filters_to_args( $filters ) );
	}

	public function test_traffic_filters_from_request_accept_only_known_values(): void {
		$_REQUEST = array( 'client' => 'bot', 'status' => '4xx', 'ip' => '198.51.100.1', 's' => 'x' );
		$this->assertSame( array( 'client' => 'bot', 'status' => '4xx', 'ip' => '198.51.100.1', 'search' => 'x' ), AdminController::traffic_filters_from_request() );

		$_REQUEST = array( 'client' => 'martian', 'status' => '9xx', 'ip' => 'nope' );
		$this->assertSame( array(), AdminController::traffic_filters_from_request() );
	}

	public function test_a_filter_cannot_smuggle_sql_into_the_log_query(): void {
		$this->plugin->log()->record( array( 'ip' => '198.51.100.1', 'rule' => 'waf' ) );
		$_REQUEST = array( 'rule' => "waf' OR '1'='1", 's' => "' OR 1=1 -- " );

		$rows = $this->plugin->log()->query( AdminController::log_filters_from_request() );

		$this->assertSame( array(), $rows );
	}

	public function test_csv_safe_defuses_formulas(): void {
		$this->assertSame( "'=cmd|' /C calc'!A0", AdminController::csv_safe( "=cmd|' /C calc'!A0" ) );
		$this->assertSame( "'+1", AdminController::csv_safe( '+1' ) );
		$this->assertSame( "'@SUM(1)", AdminController::csv_safe( '@SUM(1)' ) );
		$this->assertSame( '-2', AdminController::csv_safe( '-2' ), 'plain numbers are left alone' );
		$this->assertSame( "'-x", AdminController::csv_safe( '-x' ) );
		$this->assertSame( 'plain', AdminController::csv_safe( 'plain' ) );
		$this->assertSame( '', AdminController::csv_safe( '' ) );
		$this->assertSame( '404', AdminController::csv_safe( 404 ) );
	}

	public function test_labels_and_helpers(): void {
		$this->assertArrayHasKey( 'waf', AdminController::rule_labels() );
		$this->assertSame( 'Email alerts', AdminController::rule_title( 'alerts' ) );
		$this->assertSame( 'custom_rule', AdminController::rule_title( 'custom_rule' ), 'third-party rule ids fall back to the id' );
		$this->assertSame( 'Alert', AdminController::action_label( 'alert' ) );
		$this->assertSame( 'Blocked', AdminController::action_label( 'whatever' ) );
		$this->assertSame( array( 'dashboard', 'general', 'rules', 'countries', 'log', 'traffic', 'tools' ), array_keys( AdminController::tabs() ) );
		$this->assertSame( '', AdminController::flag( 'zz' ) );
		$this->assertSame( '', AdminController::flag( 'XX' ) );
		$this->assertNotSame( '', AdminController::flag( 'DE' ) );
		$this->assertStringContainsString( 'page=wp-bouncer', AdminController::url( 'log', array( 'x' => '1' ) ) );
		$this->assertStringContainsString( 'tab=log', AdminController::url( 'log' ) );
	}

	public function test_action_links_add_a_settings_link_first(): void {
		$links = $this->admin->action_links( array( '<a href="x">Deactivate</a>' ) );

		$this->assertCount( 2, $links );
		$this->assertStringContainsString( 'page=wp-bouncer', $links[0] );
	}

	/* ---------------- IP setup fixes (RT-03) ---------------- */

	public function test_ip_setup_trust_peer_adds_the_peer_and_keeps_the_source(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.44' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'header' => 'x_real_ip', 'peer' => '10.0.0.44' ) );

		$r = $this->call( 'handle_ip_setup' );

		$s = $this->stored();
		$this->assertSame( 'x_real_ip', $s['ip_source'] );
		$this->assertSame( array( '10.0.0.44' ), $s['trusted_proxies'] );
		$this->assertFalse( $r->is_error() );
		$this->assertStringContainsString( 'tab=general', $r->location );
	}

	public function test_ip_setup_trust_peer_without_a_header_keeps_the_configured_one(): void {
		$this->set_settings( array( 'ip_source' => 'cf_connecting_ip', 'trusted_proxies' => array( '192.0.2.0/24' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.44' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'peer' => '10.0.0.44' ) );

		$this->call( 'handle_ip_setup' );

		$s = $this->stored();
		$this->assertSame( 'cf_connecting_ip', $s['ip_source'] );
		$this->assertSame( array( '192.0.2.0/24', '10.0.0.44' ), $s['trusted_proxies'] );
	}

	public function test_ip_setup_trust_peer_can_switch_a_remote_addr_site_to_the_forwarding_header(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'header' => 'x_real_ip', 'peer' => '127.0.0.1' ) );

		$this->call( 'handle_ip_setup' );

		$s = $this->stored();
		$this->assertSame( 'x_real_ip', $s['ip_source'] );
		$this->assertSame( array( '127.0.0.1' ), $s['trusted_proxies'], 'loopback is the right proxy for a same-host setup' );
	}

	public function test_ip_setup_trust_peer_refuses_when_there_is_no_header_to_read(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.44' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'peer' => '10.0.0.44' ) );
		$before = $this->stored();

		$r = $this->call( 'handle_ip_setup' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( $before, $this->stored() );
	}

	public function test_ip_setup_rejects_an_unknown_or_remote_addr_header_and_unknown_fixes(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.44' ) );
		$this->login();
		$before = $this->stored();

		foreach ( array( array( 'trust_peer', 'evil' ), array( 'trust_peer', 'remote_addr' ), array( 'nonsense', '' ) ) as $case ) {
			$this->post( 'wp_bouncer_ip_setup', array( 'fix' => $case[0], 'header' => $case[1], 'peer' => '10.0.0.44' ) );
			$r = $this->call( 'handle_ip_setup' );
			$this->assertTrue( $r->is_error(), implode( '/', $case ) );
			$this->assertSame( $before, $this->stored() );
		}
	}

	public function test_ip_setup_use_remote_addr(): void {
		$this->set_settings( array( 'ip_source' => 'x_forwarded_for', 'trusted_proxies' => array() ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'use_remote_addr' ) );

		$r = $this->call( 'handle_ip_setup' );

		$this->assertSame( 'remote_addr', $this->stored()['ip_source'] );
		$this->assertFalse( $r->is_error() );
	}

	public function test_ip_setup_leaves_the_other_settings_alone(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'mode' => 'monitor', 'rules' => array( 'waf' => array( 'xss' => false ) ), 'allowlist' => array( '203.0.113.0/24' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'header' => 'x_real_ip', 'peer' => '198.51.100.44' ) );

		$this->call( 'handle_ip_setup' );

		$s = $this->stored();
		$this->assertSame( 'monitor', $s['mode'] );
		$this->assertFalse( $s['rules']['waf']['xss'] );
		$this->assertSame( array( '203.0.113.0/24' ), $s['allowlist'] );
	}

	public function test_saving_general_drops_broad_ranges_and_warns_about_a_header_without_proxies(): void {
		$this->login();
		$this->post(
			'wp_bouncer_save',
			array(
				'tab'        => 'general',
				'wp_bouncer' => array(
					'ip_source'       => 'x_real_ip',
					'trusted_proxies' => "0.0.0.0/0\n::/0",
					'allowlist'       => '198.51.100.0/24',
				),
			)
		);

		$r = $this->call( 'handle_save' );

		$s = $this->stored();
		$this->assertSame( 'x_real_ip', $s['ip_source'], 'saving is allowed' );
		$this->assertSame( array(), $s['trusted_proxies'] );
		$this->assertStringContainsString( '0.0.0.0/0', $r->message() );
		$this->assertStringContainsString( '::/0', $r->message() );
		$this->assertStringContainsString( 'no trusted proxies', $r->message() );
	}

	public function test_saving_another_tab_keeps_the_ip_settings(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '127.0.0.1' ) ) );
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'rules', 'wp_bouncer' => array( 'rules' => array( 'waf' => array( 'enabled' => '1' ) ) ) ) );

		$this->call( 'handle_save' );

		$s = $this->stored();
		$this->assertSame( 'x_real_ip', $s['ip_source'] );
		$this->assertSame( array( '127.0.0.1' ), $s['trusted_proxies'] );
	}

	/* ---------------- NEW-1 / NEW-4 / NEW-3c ---------------- */

	/** @return array<string, mixed> Settings that exclude everyone but Germany. */
	private function germany_only(): array {
		return array( 'rules' => array( 'country' => array( 'enabled' => true, 'mode' => 'allow', 'countries' => array( 'DE' ), 'block_unknown' => true ) ) );
	}

	public function test_save_refuses_instead_of_allowlisting_a_shared_address(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'countries', 'wp_bouncer' => array( 'rules' => array( 'country' => array( 'enabled' => '1', 'mode' => 'allow', 'countries' => 'DE', 'block_unknown' => '1' ) ) ) ) );
		$before = $this->stored();

		$r = $this->call( 'handle_save' );

		$this->assertTrue( $r->is_error() );
		$this->assertStringContainsString( 'Nothing was saved', $r->message() );
		$this->assertStringContainsString( 'IP setup notice', $r->message() );
		$this->assertSame( $before, $this->stored(), 'settings and allowlist unchanged' );
		$this->assertSame( array(), $this->stored()['allowlist'] );
	}

	public function test_save_still_allowlists_an_address_that_can_be_banned(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'countries', 'wp_bouncer' => array( 'rules' => array( 'country' => array( 'enabled' => '1', 'mode' => 'allow', 'countries' => 'DE', 'block_unknown' => '1' ) ) ) ) );

		$r = $this->call( 'handle_save' );

		$this->assertFalse( $r->is_error() );
		$this->assertSame( array( '203.0.113.9' ), $this->stored()['allowlist'] );
	}

	public function test_ip_setup_allowlists_the_new_address_and_not_the_proxy(): void {
		// After trusting the peer, the admin's resolved IP is the forwarded 203.0.113.9 (bannable) ...
		$this->set_settings( array_replace_recursive( $this->germany_only(), array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.9' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'header' => 'x_real_ip', 'peer' => '10.0.0.5' ) );

		$this->call( 'handle_ip_setup' );

		$s = $this->stored();
		$this->assertSame( array( '10.0.0.5' ), $s['trusted_proxies'] );
		$this->assertSame( array( '203.0.113.9' ), $s['allowlist'], 'the NEW address is allowlisted, not the proxy' );
	}

	public function test_ip_setup_use_remote_addr_refuses_a_change_that_would_block_a_shared_address(): void {
		// ... while switching to the connection address makes the admin the shared loopback proxy: refuse.
		$this->set_settings( array_replace_recursive( $this->germany_only(), array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '127.0.0.1' ) ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.9' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'use_remote_addr' ) );
		$before = $this->stored();

		$r = $this->call( 'handle_ip_setup' );

		$this->assertTrue( $r->is_error() );
		$this->assertStringContainsString( 'Nothing was saved', $r->message() );
		$this->assertSame( $before, $this->stored() );
	}

	public function test_ip_setup_use_remote_addr_allowlists_a_bannable_connection_address(): void {
		$this->set_settings( array_replace_recursive( $this->germany_only(), array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'use_remote_addr' ) );

		$r = $this->call( 'handle_ip_setup' );

		$this->assertFalse( $r->is_error() );
		$this->assertSame( 'remote_addr', $this->stored()['ip_source'] );
		$this->assertSame( array( '203.0.113.9' ), $this->stored()['allowlist'] );
	}

	public function test_ip_setup_trust_peer_refuses_a_peer_that_differs_from_the_connection(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.44' ) );
		$this->login();
		$before = $this->stored();

		foreach ( array( '10.0.0.45', '', '0.0.0.0/0' ) as $peer ) {
			$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'header' => 'x_real_ip', 'peer' => $peer ) );
			$r = $this->call( 'handle_ip_setup' );
			$this->assertTrue( $r->is_error(), $peer );
			$this->assertSame( $before, $this->stored() );
		}
	}

	public function test_ip_setup_trust_peer_refuses_a_public_peer_server_side(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );
		$this->login();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'trust_peer', 'header' => 'x_real_ip', 'peer' => '198.51.100.44' ) );
		$before = $this->stored();

		$r = $this->call( 'handle_ip_setup' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( $before, $this->stored() );
	}

	/** R2: a refused header makes the proxy the counter subject, but the proxy must never be allowlisted. */
	public function test_save_refuses_instead_of_allowlisting_the_proxy_when_the_header_was_refused(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '127.0.0.1' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '192.168.1.20' ) );
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'countries', 'wp_bouncer' => array( 'rules' => array( 'country' => array( 'enabled' => '1', 'mode' => 'allow', 'countries' => 'DE', 'block_unknown' => '1' ) ) ) ) );
		$before = $this->stored();

		$r = $this->call( 'handle_save' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( $before, $this->stored() );
		$this->assertSame( array(), $this->stored()['allowlist'] );
	}

	public function test_saving_a_new_ip_source_is_checked_against_the_address_it_would_resolve_to(): void {
		// Today remote_addr: the admin is 10.0.0.5. Switching to the header makes the admin 203.0.113.9.
		$this->set_settings( array( 'ip_source' => 'remote_addr', 'rules' => array( 'ip_blocklist' => array( 'enabled' => true, 'ips' => array( '203.0.113.9' ) ) ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.9' ) );
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'general', 'wp_bouncer' => array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => '127.0.0.1' ) ) );

		$this->call( 'handle_save' );

		$this->assertSame( array( '203.0.113.9' ), $this->stored()['allowlist'], 'the address the new settings give the admin' );
	}

	public function test_save_refuses_instead_of_allowlisting_an_unlisted_cdn_edge(): void {
		$this->set_settings( array( 'ip_source' => 'x_forwarded_for', 'trusted_proxies' => array( '198.51.100.1' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '203.0.113.99' ) );
		$this->login();
		$this->post( 'wp_bouncer_save', array( 'tab' => 'countries', 'wp_bouncer' => array( 'rules' => array( 'country' => array( 'enabled' => '1', 'mode' => 'allow', 'countries' => 'DE', 'block_unknown' => '1' ) ) ) ) );
		$before = $this->stored();

		$r = $this->call( 'handle_save' );

		$this->assertTrue( $r->is_error() );
		$this->assertSame( $before, $this->stored() );
		$this->assertSame( array(), $this->stored()['allowlist'] );
	}
}
