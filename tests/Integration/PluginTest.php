<?php
/**
 * The composition root: hooks, service wiring and the firewall rule chain.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

use WPBouncer\Installer;
use WPBouncer\Log\BlockLog;
use WPBouncer\Plugin;
use WPBouncer\Rules\CountryRule;
use WPBouncer\Rules\IpBlocklistRule;
use WPBouncer\Rules\LoginLockoutRule;
use WPBouncer\Rules\NotFoundFloodRule;
use WPBouncer\Rules\RateLimitRule;
use WPBouncer\Rules\RuleInterface;
use WPBouncer\Rules\SensitiveFileRule;
use WPBouncer\Rules\UserAgentRule;
use WPBouncer\Rules\UserEnumerationRule;
use WPBouncer\Rules\WafRule;
use WPBouncer\Rules\XmlRpcRule;
use WPBouncer\Storage\TransientStore;
use WPBouncer\Traffic\TrafficRecorder;

/**
 * @covers \WPBouncer\Plugin
 */
final class PluginTest extends IntegrationTestCase {

	/** @return array<int, array<string, mixed>> Log rows. */
	private function log_rows( array $filters = array() ): array {
		global $wpdb;
		return (array) ( new BlockLog( $wpdb ) )->query( $filters );
	}

	/* ---------------- boot and hooks ---------------- */

	public function test_boot_is_a_singleton_and_the_constants_are_defined(): void {
		$this->assertSame( $this->plugin, Plugin::boot( WP_BOUNCER_FILE ) );
		$this->assertSame( $this->plugin, Plugin::instance() );
		$this->assertSame( Plugin::VERSION, WP_BOUNCER_VERSION );
		$this->assertSame( WP_BOUNCER_FILE, $this->plugin->file() );
		$this->assertFalse( Plugin::is_disabled() );
	}

	public function test_activation_and_deactivation_hooks_are_registered(): void {
		$base = plugin_basename( WP_BOUNCER_FILE );

		$this->assertNotFalse( has_action( 'activate_' . $base, array( Installer::class, 'activate' ) ) );
		$this->assertNotFalse( has_action( 'deactivate_' . $base, array( Installer::class, 'deactivate' ) ) );
	}

	public function test_core_hooks_are_registered_with_the_expected_priorities(): void {
		$this->assertSame( 0, has_action( 'plugins_loaded', array( Installer::class, 'maybe_upgrade' ) ) );
		$this->assertSame( 1, has_action( 'plugins_loaded', array( $this->plugin, 'run_firewall' ) ), 'firewall runs first' );
		$this->assertSame( 10, has_action( 'init', array( $this->plugin, 'load_textdomain' ) ) );
		$this->assertSame( 10, has_action( Installer::CRON_HOOK, array( $this->plugin, 'daily_maintenance' ) ) );
		$this->assertSame( 999, has_action( 'template_redirect', array( $this->plugin, 'track_not_found' ) ), 'late, so other plugins can fix a 404 first' );
		$this->assertSame( 999, has_filter( 'authenticate', array( $this->plugin, 'filter_authenticate' ) ), 'after core authenticators' );
		$this->assertNotFalse( has_action( 'wp_login_failed' ) );
	}

	public function test_alert_upload_and_traffic_hooks_are_registered(): void {
		$alerts = $this->plugin->alerts();
		foreach ( array( 'user_register' => 'on_user_register', 'set_user_role' => 'on_set_user_role', 'add_user_role' => 'on_add_user_role', 'activated_plugin' => 'on_activated_plugin', 'deactivated_plugin' => 'on_deactivated_plugin', 'deleted_plugin' => 'on_deleted_plugin', 'upgrader_process_complete' => 'on_upgrader_complete' ) as $hook => $method ) {
			$this->assertSame( 20, has_action( $hook, array( $alerts, $method ) ), $hook );
		}
		$guard = $this->plugin->uploads_guard();
		$this->assertNotFalse( has_action( 'init', array( $guard, 'maybe_sync' ) ) );
		$this->assertNotFalse( has_filter( 'wp_handle_upload_prefilter', array( $guard, 'filter_upload' ) ) );
		$this->assertNotFalse( has_action( TrafficRecorder::PURGE_HOOK ) );
	}

	public function test_update_hooks_are_registered(): void {
		$this->assertNotFalse( has_filter( 'update_plugins_github.com' ) );
		$this->assertNotFalse( has_filter( 'plugins_api' ) );
		$this->assertNotFalse( has_filter( 'upgrader_pre_download' ) );
	}

	public function test_admin_hooks_are_not_registered_outside_the_admin(): void {
		$this->assertFalse( is_admin() );
		$this->assertFalse( has_action( 'admin_menu', 'x' ) );
		$this->assertFalse( has_action( 'admin_post_wp_bouncer_save' ) );
	}

	public function test_default_hardening_hooks_follow_the_default_settings(): void {
		$this->assertNotFalse( has_filter( 'xmlrpc_enabled', '__return_false' ) );
		$this->assertFalse( apply_filters( 'wp_sitemaps_add_provider', 'provider', 'users' ), 'users sitemap removed' );
		$this->assertSame( 'provider', apply_filters( 'wp_sitemaps_add_provider', 'provider', 'posts' ) );
		$this->assertArrayNotHasKey( 'X-Pingback', apply_filters( 'wp_headers', array( 'X-Pingback' => 'x', 'A' => 'b' ) ) );
	}

	public function test_traffic_recording_is_off_by_default(): void {
		$this->assertFalse( has_action( 'shutdown', array( new TrafficRecorder( $this->plugin ), 'record' ) ) );
		$this->assertFalse( $this->plugin->settings()->get( 'traffic' )['enabled'] );
	}

	/* ---------------- services ---------------- */

	public function test_services_are_built_once(): void {
		$this->assertInstanceOf( TransientStore::class, $this->plugin->store() );
		$this->assertSame( $this->plugin->store(), $this->plugin->store() );
		$this->assertSame( $this->plugin->log(), $this->plugin->log() );
		$this->assertSame( $this->plugin->traffic_log(), $this->plugin->traffic_log() );
		$this->assertSame( $this->plugin->geo_database(), $this->plugin->geo_database() );
		$this->assertSame( $this->plugin->alerts(), $this->plugin->alerts() );
		$this->assertSame( $this->plugin->uploads_guard(), $this->plugin->uploads_guard() );
		$this->assertSame( $GLOBALS['wpdb']->prefix . 'bouncer_log', $this->plugin->log()->table() );
	}

	public function test_client_ip_comes_from_the_resolved_request(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4' ) );

		$this->assertSame( '198.51.100.44', $this->plugin->client_ip(), 'forwarded headers are ignored for remote_addr' );
	}

	public function test_client_ip_honours_a_trusted_proxy_header(): void {
		$this->set_settings( array( 'ip_source' => 'x_forwarded_for', 'trusted_proxies' => array( '10.0.0.0/8' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '198.51.100.99' ) );

		$this->assertSame( '198.51.100.99', $this->plugin->client_ip() );
	}

	public function test_allowlist_and_loopback(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1' ) );
		$this->assertTrue( $this->plugin->client_is_allowlisted(), 'loopback always passes' );

		$this->set_settings( array( 'allowlist' => array( '198.51.100.0/24' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.7' ) );
		$this->assertTrue( $this->plugin->client_is_allowlisted() );

		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.7' ) );
		$this->assertFalse( $this->plugin->client_is_allowlisted() );
	}

	public function test_current_request_is_built_from_the_superglobals_unslashed(): void {
		$this->fake_request( array( 'REQUEST_URI' => '/search?q=a', 'REQUEST_METHOD' => 'POST' ), array( 'q' => "O\\'Brien" ), array( 'n' => 'x' ) );

		$request = $this->plugin->current_request();

		$this->assertSame( 'POST', $request->method() );
		$this->assertSame( '/search?q=a', $request->uri() );
		$this->assertSame( array( 'q' => "O'Brien" ), $request->query(), 'WordPress-added slashes are removed' );
		$this->assertSame( array( 'n' => 'x' ), $request->post() );
		$this->assertFalse( $request->is_logged_in() );
	}

	public function test_current_request_knows_the_user(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->fake_request();

		$this->assertTrue( $this->plugin->current_request()->is_logged_in() );
		$this->assertTrue( $this->plugin->current_request()->is_trusted() );
	}

	public function test_reload_settings_picks_up_changes_and_drops_cached_services(): void {
		$guard = $this->plugin->login_guard();

		$this->set_settings( array( 'mode' => 'monitor' ) );

		$this->assertTrue( $this->plugin->settings()->is_monitor_mode() );
		$this->assertNotSame( $guard, $this->plugin->login_guard() );
	}

	public function test_the_log_budget_filter_is_floored_at_ten_and_the_priority_budget_at_five(): void {
		$filter = static fn() => 1;
		add_filter( 'wp_bouncer_log_budget_per_minute', $filter );
		add_filter( 'wp_bouncer_log_priority_budget_per_minute', $filter );
		$plugin = Plugin::instance();
		$ref    = new \ReflectionProperty( Plugin::class, 'write_budget' );
		$ref->setValue( $plugin, null );
		try {
			$budget = $plugin->write_budget();
			$this->assertSame( 10, ( new \ReflectionProperty( $budget, 'per_minute' ) )->getValue( $budget ) );
			$this->assertSame( 5, ( new \ReflectionProperty( $budget, 'priority_per_minute' ) )->getValue( $budget ) );
		} finally {
			remove_filter( 'wp_bouncer_log_budget_per_minute', $filter );
			remove_filter( 'wp_bouncer_log_priority_budget_per_minute', $filter );
			$ref->setValue( $plugin, null );
		}
	}

	public function test_log_writer_stops_writing_once_the_minute_budget_is_spent(): void {
		$plugin = Plugin::instance();
		// A fixed clock, far from "now", so a minute boundary cannot split the run.
		$budget = new \WPBouncer\Log\WriteBudget( $plugin->store(), new \WPBouncer\Tests\Support\FrozenClock( 1800000000 ), 10 );
		( new \ReflectionProperty( Plugin::class, 'write_budget' ) )->setValue( $plugin, $budget );
		( new \ReflectionProperty( Plugin::class, 'log_writer' ) )->setValue( $plugin, null );
		try {
			$written = 0;
			for ( $i = 0; $i < 15; $i++ ) {
				$written += $plugin->log_writer()->record( array( 'ip' => '203.0.113.' . ( $i + 1 ), 'rule' => 'test', 'action' => 'blocked', 'reason' => 'x' ) ) > 0 ? 1 : 0;
			}
			$this->assertSame( 10, $written );
		} finally {
			( new \ReflectionProperty( Plugin::class, 'write_budget' ) )->setValue( $plugin, null );
			( new \ReflectionProperty( Plugin::class, 'log_writer' ) )->setValue( $plugin, null );
		}
	}

	public function test_geo_uses_the_database_only_once_rows_are_loaded(): void {
		$this->assertNull( $this->plugin->geo()->lookup( '1.0.0.9' ) );

		$this->plugin->geo_database()->insert_batch( array( array( 'from' => \WPBouncer\Support\IpUtils::to_hex16( '1.0.0.0' ), 'to' => \WPBouncer\Support\IpUtils::to_hex16( '1.0.0.255' ), 'country' => 'AU' ) ) );
		update_option( Plugin::GEO_META_OPTION, array( 'rows' => 1 ) );
		$this->plugin->reload_settings();

		$this->assertSame( 'AU', $this->plugin->geo()->lookup( '1.0.0.9' ) );
	}

	public function test_geo_header_mode_trusts_the_header_from_a_listed_proxy(): void {
		$this->set_settings( array( 'geo_source' => 'header', 'geo_header' => 'CF-IPCountry', 'ip_source' => 'remote_addr', 'trusted_proxies' => array( '198.51.100.0/24' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.5', 'HTTP_CF_IPCOUNTRY' => 'DE' ) );

		$this->assertFalse( $this->plugin->geo_header_gated() );
		$this->assertSame( 'DE', $this->plugin->geo()->lookup( $this->plugin->client_ip() ) );
	}

	public function test_geo_header_is_ignored_from_an_unlisted_peer_and_the_database_answers(): void {
		$this->set_settings( array( 'geo_source' => 'header', 'geo_header' => 'CF-IPCountry', 'trusted_proxies' => array( '192.0.2.0/24' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.5', 'HTTP_CF_IPCOUNTRY' => 'DE' ) );
		$this->assertFalse( $this->plugin->geo_header_gated(), 'proxies are configured' );
		$this->assertFalse( $this->plugin->country_paused() );
		$this->assertNull( $this->plugin->geo()->lookup( '198.51.100.5' ), 'forged header ignored' );

		$this->plugin->geo_database()->insert_batch( array( array( 'from' => \WPBouncer\Support\IpUtils::to_hex16( '198.51.100.0' ), 'to' => \WPBouncer\Support\IpUtils::to_hex16( '198.51.100.255' ), 'country' => 'NL' ) ) );
		update_option( Plugin::GEO_META_OPTION, array( 'rows' => 1 ) );
		$this->plugin->reload_settings();
		$this->assertSame( 'NL', $this->plugin->geo()->lookup( '198.51.100.5' ) );
	}

	public function test_an_unlisted_peer_with_no_database_fails_closed(): void {
		$this->set_settings( array( 'geo_source' => 'header', 'geo_header' => 'CF-IPCountry', 'trusted_proxies' => array( '192.0.2.0/24' ), 'rules' => array( 'country' => array( 'enabled' => true, 'block_unknown' => true ) ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.5', 'HTTP_CF_IPCOUNTRY' => 'DE' ) );

		$this->assertFalse( $this->plugin->country_paused() );
		$rules = array_filter( $this->plugin->build_rules(), static fn( $r ) => $r instanceof CountryRule );
		$rule  = reset( $rules );
		$this->assertNotNull( $rule->inspect( \WPBouncer\Firewall\Request::from_globals( '198.51.100.5', $_SERVER, array(), array(), '__return_false', '__return_false' ) ) );
	}

	public function test_country_blocking_pauses_when_the_header_is_gated_and_no_database_is_loaded(): void {
		$this->set_settings( array( 'geo_source' => 'header', 'geo_header' => 'CF-IPCountry', 'rules' => array( 'country' => array( 'enabled' => true, 'block_unknown' => true ) ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.5', 'HTTP_CF_IPCOUNTRY' => 'DE' ) );

		$this->assertTrue( $this->plugin->country_paused() );
		$rules = array_filter( $this->plugin->build_rules(), static fn( $r ) => $r instanceof CountryRule );
		$rule  = reset( $rules );
		$this->assertNull( $rule->inspect( \WPBouncer\Firewall\Request::from_globals( '198.51.100.5', $_SERVER, array(), array(), '__return_false', '__return_false' ) ) );
	}

	public function test_a_server_variable_geo_source_is_never_gated(): void {
		$this->set_settings( array( 'geo_source' => 'header', 'geo_header' => 'GEOIP_COUNTRY_CODE' ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.5', 'GEOIP_COUNTRY_CODE' => 'DE', 'HTTP_GEOIP_COUNTRY_CODE' => 'US' ) );

		$this->assertFalse( $this->plugin->geo_header_gated() );
		$this->assertSame( 'DE', $this->plugin->geo()->lookup( '198.51.100.5' ) );
	}

	/* ---------------- rule chain ---------------- */

	public function test_build_rules_returns_the_documented_order(): void {
		$classes = array_map( 'get_class', $this->plugin->build_rules() );

		$this->assertSame(
			array(
				IpBlocklistRule::class,
				SensitiveFileRule::class,
				NotFoundFloodRule::class,
				LoginLockoutRule::class,
				RateLimitRule::class,
				UserAgentRule::class,
				XmlRpcRule::class,
				UserEnumerationRule::class,
				CountryRule::class,
				WafRule::class,
			),
			$classes
		);
	}

	public function test_build_rules_ids_match_the_settings_keys(): void {
		$ids = array_map(
			static function ( RuleInterface $rule ): string {
				return $rule->id();
			},
			$this->plugin->build_rules()
		);

		$this->assertSame( array( 'ip_blocklist', 'sensitive_files', 'not_found', 'login_lockout', 'rate_limit', 'user_agent', 'xmlrpc', 'user_enumeration', 'country', 'waf' ), $ids );
		foreach ( $ids as $id ) {
			$this->assertArrayHasKey( $id, $this->plugin->settings()->to_array()['rules'] );
		}
	}

	public function test_default_enablement_in_the_rule_chain(): void {
		$enabled = array();
		foreach ( $this->plugin->build_rules() as $rule ) {
			$enabled[ $rule->id() ] = $rule->is_enabled();
		}

		$this->assertFalse( $enabled['country'], 'country blocking needs configuring first' );
		$this->assertFalse( $enabled['rate_limit'] );
		$this->assertTrue( $enabled['waf'] );
		$this->assertTrue( $enabled['login_lockout'] );
	}

	public function test_the_rules_filter_can_add_reorder_and_is_sanitised(): void {
		$custom = new class() implements RuleInterface {
			public function id(): string {
				return 'custom';
			}
			public function is_enabled(): bool {
				return true;
			}
			public function inspect( \WPBouncer\Firewall\Request $request ): ?\WPBouncer\Firewall\Verdict {
				return null;
			}
		};
		add_filter(
			'wp_bouncer_rules',
			static function ( $rules ) use ( $custom ) {
				array_unshift( $rules, $custom );
				$rules[] = 'not a rule';
				$rules[] = null;
				return $rules;
			}
		);

		$rules = $this->plugin->build_rules();

		$this->assertCount( 11, $rules, 'the junk entries are dropped' );
		$this->assertSame( $custom, $rules[0] );
		$this->assertSame( array_values( $rules ), $rules, 're-indexed' );
	}

	public function test_a_filter_returning_a_non_array_yields_an_empty_chain(): void {
		add_filter( 'wp_bouncer_rules', '__return_null' );

		$this->assertSame( array(), $this->plugin->build_rules() );
	}

	/* ---------------- firewall run ---------------- */

	public function test_run_firewall_lets_a_normal_request_through_silently(): void {
		$this->fake_request( array( 'REQUEST_URI' => '/hello-world/' ) );

		ob_start();
		$this->plugin->run_firewall();
		$out = ob_get_clean();

		$this->assertSame( '', $out );
		$this->assertCount( 0, $this->log_rows() );
	}

	public function test_run_firewall_in_monitor_mode_logs_but_does_not_block(): void {
		$this->set_settings( array( 'mode' => 'monitor' ) );
		$this->fake_request( array( 'HTTP_USER_AGENT' => 'sqlmap/1.7', 'REQUEST_URI' => '/?id=1' ) );

		ob_start();
		$this->plugin->run_firewall();
		$out = ob_get_clean();

		$this->assertSame( '', $out, 'no block page in monitor mode' );
		$rows = $this->log_rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'monitored', $rows[0]['action'] );
		$this->assertSame( 'user_agent', $rows[0]['rule'] );
		$this->assertSame( '203.0.113.9', $rows[0]['ip'] );
	}

	public function test_a_blocked_request_is_stored_with_secrets_redacted(): void {
		// Monitor mode, so the block page doesn't end the test process; the row is written the same way.
		$this->set_settings( array( 'mode' => 'monitor' ) );
		$this->fake_request( array( 'HTTP_USER_AGENT' => 'sqlmap/1.7', 'REQUEST_URI' => '/?key=SECRETKEY&token=SECRETTOKEN&email=jane%40example.org&ok=1' ) );

		ob_start();
		$this->plugin->run_firewall();
		ob_get_clean();

		$rows = $this->log_rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( '/?key=[removed]&token=[removed]&email=[removed]&ok=1', $rows[0]['uri'] );
	}

	public function test_a_login_lockout_does_not_store_an_unknown_username(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9', 'REQUEST_URI' => '/wp-login.php?key=SECRETKEY' ) );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'hunter2-typed-as-username' );
		}
		$rows = $this->log_rows( array( 'rule' => 'login_lockout' ) );
		$this->assertNotEmpty( $rows );
		$this->assertStringNotContainsString( 'hunter2', $rows[0]['reason'] );
		$this->assertStringContainsString( 'unknown username', $rows[0]['reason'] );
		$this->assertStringNotContainsString( 'SECRETKEY', $rows[0]['uri'] );
	}

	public function test_a_login_lockout_keeps_an_existing_username(): void {
		self::factory()->user->create( array( 'user_login' => 'realuser' ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'realuser' );
		}
		$rows = $this->log_rows( array( 'rule' => 'login_lockout' ) );
		$this->assertStringContainsString( '"realuser"', $rows[0]['reason'] );
	}

	public function test_the_purge_runs_from_admin_init_when_it_is_overdue(): void {
		global $wpdb;
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$old = $this->plugin->log()->record( array( 'rule' => 'waf', 'reason' => 'old' ) );
		$wpdb->update( $this->plugin->log()->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 400 * DAY_IN_SECONDS ) ), array( 'id' => $old ) );
		update_option( \WPBouncer\Plugin::LAST_PURGE_OPTION, time() - 3 * DAY_IN_SECONDS, false );

		$this->plugin->maybe_purge();

		$this->assertCount( 0, $this->log_rows( array( 'search' => 'old' ) ) );
		$this->assertGreaterThan( time() - 60, (int) get_option( \WPBouncer\Plugin::LAST_PURGE_OPTION ) );
	}

	public function test_a_lockout_stores_the_canonical_login_not_the_typed_one(): void {
		self::factory()->user->create( array( 'user_login' => 'realuser2' ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'REALUSER2' );
		}
		$rows = $this->log_rows( array( 'rule' => 'login_lockout' ) );
		$this->assertStringContainsString( '"realuser2"', $rows[0]['reason'] );
		$this->assertStringNotContainsString( 'REALUSER2', $rows[0]['reason'] );
	}

	public function test_maybe_purge_does_nothing_when_not_overdue(): void {
		global $wpdb;
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$old = $this->plugin->log()->record( array( 'rule' => 'waf', 'reason' => 'keepme' ) );
		$wpdb->update( $this->plugin->log()->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 400 * DAY_IN_SECONDS ) ), array( 'id' => $old ) );
		$stamp = time() - DAY_IN_SECONDS;
		update_option( \WPBouncer\Plugin::LAST_PURGE_OPTION, $stamp, true );

		$this->plugin->maybe_purge();

		$this->assertCount( 1, $this->log_rows( array( 'search' => 'keepme' ) ) );
		$this->assertSame( $stamp, (int) get_option( \WPBouncer\Plugin::LAST_PURGE_OPTION ) );
	}

	public function test_maybe_purge_needs_manage_options(): void {
		global $wpdb;
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );
		$old = $this->plugin->log()->record( array( 'rule' => 'waf', 'reason' => 'keepme2' ) );
		$wpdb->update( $this->plugin->log()->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 400 * DAY_IN_SECONDS ) ), array( 'id' => $old ) );
		update_option( \WPBouncer\Plugin::LAST_PURGE_OPTION, time() - 9 * DAY_IN_SECONDS, true );

		$this->plugin->maybe_purge();

		$this->assertCount( 1, $this->log_rows( array( 'search' => 'keepme2' ) ) );
	}

	public function test_the_overdue_fallback_also_purges_the_traffic_log(): void {
		global $wpdb;
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$table = $wpdb->prefix . 'bouncer_traffic';
		$wpdb->insert( $table, array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 60 * DAY_IN_SECONDS ), 'ip' => '203.0.113.5', 'method' => 'GET', 'uri' => '/old', 'status' => 200 ) );
		update_option( \WPBouncer\Plugin::LAST_PURGE_OPTION, time() - 9 * DAY_IN_SECONDS, true );

		$this->plugin->maybe_purge();

		$this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE uri = '/old'" ) ); // phpcs:ignore WordPress.DB
	}

	public function test_run_firewall_never_blocks_the_allowlist(): void {
		$this->set_settings( array( 'allowlist' => array( '203.0.113.9' ) ) );
		$this->fake_request( array( 'HTTP_USER_AGENT' => 'sqlmap/1.7' ) );

		ob_start();
		$this->plugin->run_firewall();
		$out = ob_get_clean();

		$this->assertSame( '', $out );
		$this->assertCount( 0, $this->log_rows() );
	}

	/* ---------------- login hooks ---------------- */

	public function test_failed_logins_lock_the_ip_out_and_authenticate_refuses_it(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );

		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}

		$result = $this->plugin->filter_authenticate( null );
		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_locked_out', $result->get_error_code() );
		$this->assertNotEmpty( $this->log_rows( array( 'rule' => 'login_lockout' ) ) );
		// A different visitor is unaffected.
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.10' ) );
		$this->assertNull( $this->plugin->filter_authenticate( null ) );
	}

	public function test_an_allowlisted_ip_is_never_counted_or_locked(): void {
		$this->set_settings( array( 'allowlist' => array( '203.0.113.9' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );

		for ( $i = 0; $i < 8; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}

		$this->assertNull( $this->plugin->filter_authenticate( null ) );
		$this->assertCount( 0, $this->log_rows() );
	}

	public function test_authentication_errors_are_made_generic(): void {
		$this->fake_request();
		$error = new \WP_Error( 'incorrect_password', 'The password you entered for the username admin is incorrect.' );

		$result = $this->plugin->filter_authenticate( $error );

		$this->assertSame( 'wp_bouncer_invalid_credentials', $result->get_error_code() );
		$this->assertStringNotContainsString( 'admin', $result->get_error_message() );
	}

	public function test_other_authentication_errors_and_users_pass_through(): void {
		$this->fake_request();
		$other = new \WP_Error( 'empty_password', 'Empty' );
		$user  = new \WP_User( 1 );

		$this->assertSame( $other, $this->plugin->filter_authenticate( $other ) );
		$this->assertSame( $user, $this->plugin->filter_authenticate( $user ) );
	}

	public function test_generic_errors_can_be_switched_off(): void {
		$this->set_settings( array( 'rules' => array( 'login_lockout' => array( 'generic_errors' => false ) ) ) );
		$this->fake_request();
		$error = new \WP_Error( 'incorrect_password', 'Specific' );

		$this->assertSame( $error, $this->plugin->filter_authenticate( $error ) );
	}

	public function test_monitor_mode_does_not_refuse_a_locked_out_ip(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}
		$this->set_settings( array( 'mode' => 'monitor' ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );

		$this->assertNull( $this->plugin->filter_authenticate( null ) );
	}

	public function test_failures_at_the_limit_refuse_before_any_lockout_exists(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$this->plugin->store()->set( 'login_fail:203.0.113.9', 5, 900 );

		$this->assertNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ) );
		$result = $this->plugin->filter_authenticate( null );
		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_locked_out', $result->get_error_code() );

		$this->plugin->store()->set( 'login_fail:203.0.113.9', 4, 900 );
		$this->assertNull( $this->plugin->filter_authenticate( null ), 'below the limit' );
	}

	/* ---------------- user enumeration leaks (RT-15) ---------------- */

	public function test_oembed_author_fields_are_dropped_and_the_rest_kept(): void {
		$this->assertNotFalse( has_filter( 'oembed_response_data', array( $this->plugin, 'filter_oembed_response' ) ) );
		$data = $this->plugin->filter_oembed_response( array( 'title' => 'T', 'author_name' => 'admin', 'author_url' => 'https://x/author/admin/' ) );
		$this->assertSame( array( 'title' => 'T' ), $data );
	}

	public function test_lost_password_unknown_email_error_gets_the_generic_wording(): void {
		$this->assertNotFalse( has_filter( 'lostpassword_errors', array( $this->plugin, 'filter_lostpassword_errors' ) ) );
		$errors = $this->plugin->filter_lostpassword_errors( new \WP_Error( 'invalid_email', 'There is no account with that username or email address.' ) );
		$this->assertSame( array( 'wp_bouncer_lostpassword' ), $errors->get_error_codes() );
		$this->assertStringNotContainsString( 'no account', $errors->get_error_message() );
		// Core adds invalidcombo after this filter runs, so it is not touched here.
		$other = $this->plugin->filter_lostpassword_errors( new \WP_Error( 'empty_username', 'Enter a username.' ) );
		$this->assertSame( array( 'empty_username' ), $other->get_error_codes() );
	}

	public function test_rest_user_objects_lose_name_slug_and_link_for_logged_out_visitors(): void {
		$this->assertNotFalse( has_filter( 'rest_prepare_user', array( $this->plugin, 'filter_rest_user' ) ) );
		wp_set_current_user( 0 );
		$out = $this->plugin->filter_rest_user( new \WP_REST_Response( array( 'id' => 3, 'name' => 'Jane', 'slug' => 'jane_admin', 'link' => 'https://x/author/jane_admin/', 'avatar_urls' => array() ) ) );
		$this->assertSame( array( 'id' => 3, 'avatar_urls' => array() ), $out->get_data() );
	}

	public function test_rest_user_objects_are_untouched_for_logged_in_users(): void {
		wp_set_current_user( self::factory()->user->create() );
		$out = $this->plugin->filter_rest_user( new \WP_REST_Response( array( 'id' => 3, 'slug' => 'jane' ) ) );
		$this->assertSame( array( 'id' => 3, 'slug' => 'jane' ), $out->get_data() );
		wp_set_current_user( 0 );
	}

	/* ---------------- IP trust (RT-03, RT-04, RT-24, Q1) ---------------- */

	public function test_a_header_source_without_proxies_uses_the_connection_address_and_suspends_bans(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );

		$this->assertSame( '198.51.100.44', $this->plugin->client_ip() );
		$this->assertTrue( $this->plugin->ip_resolver()->fallback_active() );
		$this->assertFalse( $this->plugin->client_can_be_banned() );
		$this->assertFalse( $this->plugin->current_request()->can_be_banned() );
	}

	public function test_failed_logins_during_the_fallback_are_logged_as_monitored_and_never_lock_anyone_out(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );

		for ( $i = 0; $i < 12; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}

		$this->assertNull( $this->plugin->filter_authenticate( null ), 'no lockout' );
		$rows = $this->log_rows( array( 'rule' => 'login_lockout' ) );
		$this->assertCount( 1, $rows, 'one monitored row per minute and address' );
		$this->assertSame( 'monitored', $rows[0]['action'] );
		$this->assertSame( '198.51.100.44', $rows[0]['ip'] );
		$this->assertStringNotContainsString( 'someone', $rows[0]['reason'], 'the username is not stored' );
	}

	public function test_a_lockout_that_already_exists_is_not_enforced_during_the_fallback(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}
		$this->assertWPError( $this->plugin->filter_authenticate( null ) );

		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array() ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );

		$this->assertNull( $this->plugin->filter_authenticate( null ) );
	}

	public function test_a_trusted_proxy_address_is_never_banned(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '192.0.2.5' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '192.0.2.5' ) );

		$this->assertSame( '192.0.2.5', $this->plugin->client_ip() );
		$this->assertFalse( $this->plugin->client_can_be_banned() );

		for ( $i = 0; $i < 12; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}
		$this->assertNull( $this->plugin->filter_authenticate( null ) );
		$this->assertCount( 0, $this->log_rows(), 'the proxy itself is not locked out or logged' );
	}

	public function test_a_visitor_behind_a_trusted_proxy_can_be_banned_individually(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '192.0.2.5' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '192.0.2.5', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );

		$this->assertSame( '203.0.113.5', $this->plugin->client_ip() );
		$this->assertTrue( $this->plugin->client_can_be_banned() );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}
		$this->assertWPError( $this->plugin->filter_authenticate( null ) );

		$this->fake_request( array( 'REMOTE_ADDR' => '192.0.2.5', 'HTTP_X_REAL_IP' => '203.0.113.6' ) );
		$this->assertNull( $this->plugin->filter_authenticate( null ), 'another visitor behind the same proxy is fine' );
	}

	public function test_a_private_or_loopback_header_value_resolves_to_the_proxy(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '192.0.2.5' ) ) );
		foreach ( array( '127.0.0.1', '10.0.0.1', '::1', '0.0.0.0' ) as $value ) {
			$this->fake_request( array( 'REMOTE_ADDR' => '192.0.2.5', 'HTTP_X_REAL_IP' => $value ) );
			$this->assertSame( '192.0.2.5', $this->plugin->client_ip(), $value );
		}
	}

	public function test_an_over_broad_proxy_entry_in_stored_settings_is_ignored_at_runtime(): void {
		update_option( \WPBouncer\Settings::OPTION, array_merge( \WPBouncer\Settings::defaults(), array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '0.0.0.0/0' ) ) ) );
		$this->plugin->reload_settings();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );

		$this->assertSame( '198.51.100.44', $this->plugin->client_ip() );
		$this->assertTrue( $this->plugin->ip_resolver()->fallback_active() );
	}

	public function test_an_over_broad_allowlist_entry_in_stored_settings_exempts_nobody(): void {
		update_option( \WPBouncer\Settings::OPTION, array_merge( \WPBouncer\Settings::defaults(), array( 'allowlist' => array( '0.0.0.0/0' ) ) ) );
		$this->plugin->reload_settings();
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.44' ) );

		$this->assertFalse( $this->plugin->client_is_allowlisted() );
	}

	public function test_loopback_is_exempt_only_when_the_request_is_really_local(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1' ) );
		$this->assertTrue( $this->plugin->client_is_allowlisted(), 'plain loopback (WP-Cron, health checks)' );
		$this->assertTrue( $this->plugin->current_request()->is_local() );

		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_FORWARDED' ) as $header ) {
			$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', $header => '203.0.113.5' ) );
			$this->assertFalse( $this->plugin->client_is_allowlisted(), $header );
			$this->assertFalse( $this->plugin->current_request()->is_local(), $header );
		}
	}

	public function test_a_loopback_request_with_a_forwarding_header_is_firewalled_and_never_banned(): void {
		// Monitor mode, so the block page doesn't end the test process; the verdict is logged all the same.
		$this->set_settings( array( 'mode' => 'monitor' ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5', 'REQUEST_URI' => '/.env' ) );

		$this->assertFalse( $this->plugin->client_can_be_banned() );
		ob_start();
		$this->plugin->run_firewall();
		ob_end_clean();
		$this->assertCount( 1, $this->log_rows( array( 'rule' => 'sensitive_files' ) ), 'the probe was matched (not exempt) and logged' );
		$this->assertNull( $this->plugin->store()->get( \WPBouncer\Rules\SensitiveFileRule::ban_key( '127.0.0.1' ) ), 'but loopback was not banned' );
	}

	public function test_a_refused_header_from_a_trusted_proxy_is_still_counted_under_its_own_subject(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '127.0.0.1' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '10.0.0.1' ) );

		$this->assertSame( '127.0.0.1', $this->plugin->client_ip() );
		$this->assertSame( 'rejected:127.0.0.1', $this->plugin->client_key() );
		$this->assertTrue( $this->plugin->client_can_be_banned() );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}
		$this->assertWPError( $this->plugin->filter_authenticate( null ) );
		$rows = $this->log_rows( array( 'rule' => 'login_lockout' ) );
		$this->assertSame( '127.0.0.1', $rows[0]['ip'], 'the log keeps a real IP' );

		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.7' ) );
		$this->assertNull( $this->plugin->filter_authenticate( null ), 'visitors with a valid header are not affected' );
		unset( $_SERVER['HTTP_X_REAL_IP'] );
		$this->fake_request( array( 'REMOTE_ADDR' => '127.0.0.1' ) );
		$this->assertFalse( $this->plugin->client_can_be_banned() );
	}

	public function test_a_forwarding_header_from_an_unlisted_private_peer_suspends_bans(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '198.51.100.1' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );

		$this->assertFalse( $this->plugin->client_can_be_banned() );
		for ( $i = 0; $i < 8; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}
		$this->assertNull( $this->plugin->filter_authenticate( null ) );
	}

	public function test_a_forwarding_header_from_an_unlisted_public_peer_does_not_switch_bans_off(): void {
		$this->set_settings( array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => array( '198.51.100.1' ) ) );
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_REAL_IP' => '203.0.113.5' ) );

		$this->assertTrue( $this->plugin->client_can_be_banned() );
		for ( $i = 0; $i < 5; $i++ ) {
			do_action( 'wp_login_failed', 'someone' );
		}
		$this->assertWPError( $this->plugin->filter_authenticate( null ) );
	}

	/* ---------------- 404 flood, maintenance ---------------- */

	public function test_track_not_found_counts_404s_and_logs_the_ban(): void {
		$this->set_settings( array( 'rules' => array( 'not_found' => array( 'max_404' => 3, 'window_seconds' => 60 ) ) ) );
		$this->go_to( '/?p=987654' );
		$this->assertTrue( is_404() );
		$this->fake_request( array( 'REQUEST_URI' => '/?p=987654' ) );

		$this->plugin->track_not_found();
		$this->plugin->track_not_found();
		$this->plugin->track_not_found();
		$this->assertCount( 0, $this->log_rows(), 'three 404s are within the limit of three' );
		$this->plugin->track_not_found();

		$rows = $this->log_rows( array( 'rule' => 'not_found' ) );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'lockout', $rows[0]['action'] );
		$this->assertSame( '203.0.113.9', $rows[0]['ip'] );
	}

	public function test_track_not_found_ignores_pages_that_exist_and_allowlisted_ips(): void {
		$this->set_settings( array( 'rules' => array( 'not_found' => array( 'max_404' => 3 ) ), 'allowlist' => array( '203.0.113.9' ) ) );
		$this->go_to( '/' );
		$this->fake_request();
		for ( $i = 0; $i < 6; $i++ ) {
			$this->plugin->track_not_found();
		}
		$this->go_to( '/?p=987655' );
		$this->fake_request();
		for ( $i = 0; $i < 6; $i++ ) {
			$this->plugin->track_not_found();
		}

		$this->assertCount( 0, $this->log_rows() );
	}

	public function test_daily_maintenance_purges_by_the_retention_setting(): void {
		global $wpdb;
		$this->set_settings( array( 'log_retention_days' => 10 ) );
		$old = $this->plugin->log()->record( array( 'ip' => '198.51.100.1' ) );
		$new = $this->plugin->log()->record( array( 'ip' => '198.51.100.2' ) );
		$wpdb->update( $this->plugin->log()->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 11 * DAY_IN_SECONDS ) ), array( 'id' => $old ) );

		do_action( Installer::CRON_HOOK );

		$rows = $this->log_rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( (string) $new, $rows[0]['id'] );
	}

	public function test_the_users_sitemap_request_is_a_404(): void {
		$this->assertSame( 1, has_action( 'template_redirect', array( $this->plugin, 'block_users_sitemap' ) ), 'before WP_Sitemaps at priority 10' );

		$this->go_to( '/' );
		$GLOBALS['wp_query']->set( 'sitemap', 'users' ); // What the sitemap rewrite rule sets.
		$this->plugin->block_users_sitemap();

		$this->assertTrue( is_404() );
		$this->assertSame( '', get_query_var( 'sitemap' ) );
	}

	public function test_other_sitemaps_and_pages_are_left_alone(): void {
		$this->go_to( '/' );
		$GLOBALS['wp_query']->set( 'sitemap', 'posts' );
		$this->plugin->block_users_sitemap();
		$this->assertFalse( is_404() );

		$this->go_to( '/' );
		$this->plugin->block_users_sitemap();
		$this->assertFalse( is_404() );
	}
}
