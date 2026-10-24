<?php
/**
 * The WordPress Dashboard widget: registration, numbers, escaping and cache.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\DashboardWidget;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Admin\DashboardWidget
 * @covers \WPBouncer\Log\BlockLog
 */
final class DashboardWidgetTest extends IntegrationTestCase {

	/** @var DashboardWidget */
	private $widget;

	/** @var string[] Statements run against the log table while counting. */
	private $log_queries = array();

	public function set_up() {
		parent::set_up();
		require_once ABSPATH . 'wp-admin/includes/dashboard.php';
		set_current_screen( 'dashboard' );
		$GLOBALS['wp_meta_boxes'] = array();
		DashboardWidget::flush();
		$this->widget = new DashboardWidget( $this->plugin );
		// The plugin booted outside wp-admin, so its own copy never registered; hooks of the same callable are added once.
		$this->widget->register();
		$this->login( 'administrator' );
		// TRUNCATE ends the test's transaction; clearing the log goes through DELETE here.
		add_filter(
			'query',
			static function ( $sql ) {
				return (string) preg_replace( '/^\s*TRUNCATE TABLE\s+(\S+)/i', 'DELETE FROM $1', (string) $sql );
			}
		);
	}

	public function tear_down() {
		remove_all_filters( 'wp_bouncer_widget_cache_ttl' );
		DashboardWidget::flush();
		unset( $GLOBALS['current_screen'] );
		$GLOBALS['wp_meta_boxes'] = array();
		parent::tear_down();
	}

	private function login( string $role ): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => $role ) ) );
	}

	/**
	 * Insert a log row directly.
	 *
	 * @param array<string, string> $row     Columns.
	 * @param int                   $seconds How long ago.
	 */
	private function seed( array $row, int $seconds = 60 ): void {
		global $wpdb;
		$wpdb->insert(
			$wpdb->prefix . 'bouncer_log',
			array_merge(
				array(
					'ip'     => '203.0.113.5',
					'rule'   => 'waf',
					'action' => 'blocked',
				),
				$row,
				array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - $seconds ) )
			)
		);
	}

	private function render(): string {
		ob_start();
		$this->widget->render();
		return (string) ob_get_clean();
	}

	private function registered(): bool {
		return isset( $GLOBALS['wp_meta_boxes']['dashboard']['normal']['core'][ DashboardWidget::WIDGET_ID ] );
	}

	private function count_log_queries( callable $fn ): int {
		global $wpdb;
		$table = $wpdb->prefix . 'bouncer_log';
		$seen  = 0;
		$count = static function ( $sql ) use ( &$seen, $table ) {
			if ( false !== strpos( (string) $sql, $table ) ) {
				++$seen;
			}
			return $sql;
		};
		add_filter( 'query', $count );
		try {
			$fn();
		} finally {
			remove_filter( 'query', $count );
		}
		return $seen;
	}

	/* ---------------- capability ---------------- */

	public function test_it_hooks_into_the_dashboard_setup(): void {
		$this->assertNotFalse( has_action( 'wp_dashboard_setup' ) );
		$this->assertNotFalse( has_action( 'wp_bouncer_log_cleared', array( DashboardWidget::class, 'flush' ) ) );
		$this->assertNotFalse( has_action( 'wp_bouncer_settings_changed', array( DashboardWidget::class, 'flush' ) ) );
	}

	public function test_it_is_added_for_an_administrator(): void {
		$this->widget->add_widget();

		$this->assertTrue( $this->registered() );
	}

	/** @dataProvider lesser_roles */
	public function test_it_is_not_added_for_other_roles( string $role ): void {
		$this->login( $role );

		$this->widget->add_widget();

		$this->assertFalse( $this->registered() );
	}

	/** @return array<string, array<int, string>> */
	public static function lesser_roles(): array {
		return array(
			'editor'      => array( 'editor' ),
			'author'      => array( 'author' ),
			'contributor' => array( 'contributor' ),
			'subscriber'  => array( 'subscriber' ),
		);
	}

	public function test_it_is_not_added_for_a_visitor(): void {
		wp_set_current_user( 0 );

		$this->widget->add_widget();

		$this->assertFalse( $this->registered() );
	}

	public function test_a_direct_render_by_an_editor_prints_nothing_and_queries_nothing(): void {
		$this->seed( array() );
		$this->login( 'editor' );

		$out     = '';
		$queries = $this->count_log_queries(
			function () use ( &$out ): void {
				$out = $this->render();
			}
		);

		$this->assertSame( '', $out );
		$this->assertSame( 0, $queries );
	}

	/* ---------------- content ---------------- */

	public function test_an_empty_log_says_nothing_blocked_yet(): void {
		$out = $this->render();

		$this->assertStringContainsString( 'Nothing blocked in the last 14 days', $out );
		$this->assertStringContainsString( 'View Activity Log', $out );
		$this->assertStringNotContainsString( 'Top rules', $out );
	}

	public function test_numbers_match_the_dashboard_tab_definition(): void {
		$log = $this->plugin->log();
		for ( $i = 0; $i < 3; $i++ ) {
			$this->seed( array(), 600 );
		}
		$this->seed( array(), 3 * DAY_IN_SECONDS );
		$this->seed( array(), 30 * HOUR_IN_SECONDS );
		$this->seed( array(), 10 * DAY_IN_SECONDS );
		$this->seed( array( 'action' => 'lockout' ), 600 );
		$this->seed( array( 'action' => 'monitored' ), 600 );
		$this->seed( array( 'action' => 'alert' ), 600 );

		$data = $this->widget->data();

		$expected24 = $log->count(
			array(
				'since'  => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
				'action' => 'blocked',
			)
		);
		$expected7  = $log->count(
			array(
				'since'  => gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS ),
				'action' => 'blocked',
			)
		);
		$this->assertSame( 3, $expected24 );
		$this->assertSame( $expected24, $data['h24'] );
		$this->assertSame( 5, $expected7 );
		$this->assertSame( $expected7, $data['d7'] );
		$this->assertSame( 1, $data['h24_prev'], 'the row 30 hours ago' );
		$this->assertSame( 'up', $data['trend24'] );
		$this->assertSame( 1, $data['d7_prev'], 'the row 10 days ago' );
		$this->assertSame( 1, $data['secondary']['lockout'] );
		$this->assertSame( 1, $data['secondary']['monitored'] );
	}

	public function test_alerts_are_never_counted_or_listed(): void {
		$this->seed( array( 'action' => 'blocked' ), 100 );
		$this->seed(
			array(
				'action' => 'alert',
				'rule'   => 'alerts',
				'ip'     => '198.51.100.77',
			),
			10
		);

		$data = $this->widget->data();
		$out  = $this->render();

		$this->assertSame( 1, $data['h24'] );
		$this->assertStringNotContainsString( '198.51.100.77', $out );
	}

	public function test_top_lists_recent_and_links(): void {
		$this->seed(
			array(
				'ip'      => '203.0.113.9',
				'rule'    => 'sensitive_files',
				'country' => 'NL',
			)
		);
		$this->seed(
			array(
				'ip'      => '203.0.113.9',
				'rule'    => 'sensitive_files',
				'country' => 'NL',
			)
		);
		update_option( \WPBouncer\Plugin::GEO_META_OPTION, array( 'rows' => 5 ) );

		$out = $this->render();

		$this->assertStringContainsString( 'Top rules', $out );
		$this->assertStringContainsString(
			esc_url(
				AdminController::url(
					'log',
					array(
						'rule'       => 'sensitive_files',
						'log_action' => 'blocked',
					)
				)
			),
			$out
		); // phpcs:ignore Universal.Arrays.MultiLineArrayItemTrailingComma
		$this->assertStringContainsString( 'log_ip=203.0.113.9', $out );
		$this->assertStringContainsString( 'country=NL', $out );
		$this->assertStringContainsString( 'ago', $out );
		delete_option( \WPBouncer\Plugin::GEO_META_OPTION );
	}

	public function test_without_a_geo_database_countries_are_hidden_with_a_pointer_to_tools(): void {
		$this->seed( array( 'country' => 'NL' ) );
		delete_option( \WPBouncer\Plugin::GEO_META_OPTION );

		$out = $this->render();

		$this->assertStringNotContainsString( 'Top countries', $out );
		$this->assertStringContainsString( 'no geo database is loaded', $out );
		$this->assertStringContainsString( 'tab=tools', $out );
	}

	public function test_monitor_mode_labels_the_numbers(): void {
		$this->set_settings( array( 'mode' => 'monitor' ) );
		$this->seed( array( 'action' => 'monitored' ) );
		$this->seed( array( 'action' => 'blocked' ) );

		$out  = $this->render();
		$data = $this->widget->data();

		$this->assertStringContainsString( 'Monitor mode: requests are logged, not blocked', $out );
		$this->assertStringContainsString( 'Would have been blocked', $out );
		$this->assertSame( 1, $data['h24'] );
		$this->assertSame( 'monitored', $data['headline_action'] );
	}

	public function test_the_status_line_counts_rules(): void {
		$out = $this->render();

		$total = count( AdminController::rule_labels() );
		$this->assertStringContainsString( 'Enforcing', $out );
		$this->assertMatchesRegularExpression( '/\(\d+ of ' . $total . ' rules on\)/', $out );
	}

	public function test_a_flood_summary_marks_the_numbers_as_a_lower_bound(): void {
		$this->seed( array(), 100 );
		$this->seed( array( 'action' => 'suppressed' ), 100 );

		$this->assertStringContainsString( 'lower bound', $this->render() );
	}

	/* ---------------- escaping and privacy ---------------- */

	public function test_attacker_controlled_fields_are_escaped(): void {
		$this->seed(
			array(
				'ip'         => '<img src=x onerror=alert(1)>',
				'rule'       => '<script>alert(1)</script>',
				'country'    => '<b',
				'uri'        => '/<script>uri()</script>',
				'user_agent' => '<script>ua()</script>',
				'reason'     => '<script>reason()</script>',
			)
		);
		update_option( \WPBouncer\Plugin::GEO_META_OPTION, array( 'rows' => 5 ) );

		$out = $this->render();

		$this->assertStringNotContainsString( '<script>', $out );
		$this->assertStringNotContainsString( '<img', $out );
		$this->assertStringNotContainsString( '<b>', $out );
		$this->assertStringNotContainsString( '<b ', $out );
		$this->assertStringContainsString( '&lt;script&gt;alert(1)&lt;/script&gt;', $out );
		$this->assertStringContainsString( '&lt;img src=x onerror=alert(1)&gt;', $out );
		$this->assertStringNotContainsString( 'log_ip=', $out, 'a malformed IP is not turned into a link' );
		$this->assertStringNotContainsString( 'uri()', $out );
		$this->assertStringNotContainsString( 'ua()', $out );
		$this->assertStringNotContainsString( 'reason()', $out );
		delete_option( \WPBouncer\Plugin::GEO_META_OPTION );
	}

	public function test_a_rule_name_that_cannot_survive_the_log_filter_is_not_linked(): void {
		$this->seed( array( 'rule' => 'Custom Rule' ) );

		$out = $this->render();

		$this->assertStringContainsString( 'Custom Rule', $out );
		$this->assertStringNotContainsString( 'rule=Custom', $out );
	}

	public function test_uri_user_agent_and_reason_are_not_cached(): void {
		$this->seed(
			array(
				'uri'        => '/secret-uri-marker',
				'user_agent' => 'secret-ua-marker',
				'reason'     => 'secret-reason-marker',
			)
		);

		$this->render();

		$cached = wp_json_encode( get_transient( DashboardWidget::TRANSIENT ) );
		$this->assertStringNotContainsString( 'secret-', (string) $cached );
	}

	/* ---------------- the log's ip filter ---------------- */

	public function test_the_log_filters_by_exact_ip_and_ignores_garbage(): void {
		$this->seed( array( 'ip' => '203.0.113.5' ) );
		$this->seed( array( 'ip' => '203.0.113.50' ) );

		$_REQUEST = array( 'log_ip' => '203.0.113.5' );
		$filters  = AdminController::log_filters_from_request();
		$this->assertSame( 1, $this->plugin->log()->count( $filters ) );
		$this->assertSame( array( 'log_ip' => rawurlencode( '203.0.113.5' ) ), AdminController::log_filters_to_args( $filters ) );

		$_REQUEST = array( 'log_ip' => '203.0.113.%' );
		$this->assertArrayNotHasKey( 'ip', AdminController::log_filters_from_request() );
	}

	/* ---------------- caching ---------------- */

	public function test_cold_makes_at_most_five_log_queries_and_warm_makes_none(): void {
		$this->seed( array( 'country' => 'NL' ) );
		update_option( \WPBouncer\Plugin::GEO_META_OPTION, array( 'rows' => 5 ) );

		$cold = $this->count_log_queries( fn() => $this->render() );
		$warm = $this->count_log_queries( fn() => $this->render() );

		$this->assertGreaterThan( 0, $cold );
		$this->assertLessThanOrEqual( 5, $cold );
		$this->assertSame( 0, $warm );
		delete_option( \WPBouncer\Plugin::GEO_META_OPTION );
	}

	public function test_the_transient_lives_for_five_minutes_by_default_and_the_ttl_is_clamped(): void {
		$this->widget->data();
		$timeout = (int) get_option( '_transient_timeout_' . DashboardWidget::TRANSIENT );
		$this->assertEqualsWithDelta( time() + 300, $timeout, 5 );

		DashboardWidget::flush();
		add_filter( 'wp_bouncer_widget_cache_ttl', static fn() => 5 );
		$this->widget->data();
		$this->assertEqualsWithDelta( time() + 60, (int) get_option( '_transient_timeout_' . DashboardWidget::TRANSIENT ), 5 );

		DashboardWidget::flush();
		remove_all_filters( 'wp_bouncer_widget_cache_ttl' );
		add_filter( 'wp_bouncer_widget_cache_ttl', static fn() => 999999 );
		$this->widget->data();
		$this->assertEqualsWithDelta( time() + 3600, (int) get_option( '_transient_timeout_' . DashboardWidget::TRANSIENT ), 5 );
	}

	public function test_the_numbers_refresh_after_the_cache_expires(): void {
		$this->seed( array() );
		$this->assertSame( 1, $this->widget->data()['h24'] );

		$this->seed( array() );
		$this->assertSame( 1, $this->widget->data()['h24'], 'still the cached value' );

		update_option( '_transient_timeout_' . DashboardWidget::TRANSIENT, time() - 1 );
		$this->assertSame( 2, $this->widget->data()['h24'] );
	}

	public function test_clearing_the_log_clears_the_cache(): void {
		$this->seed( array() );
		$this->widget->data();
		$this->assertNotFalse( get_transient( DashboardWidget::TRANSIENT ) );
		$_POST    = array( '_wpnonce' => wp_create_nonce( 'wp_bouncer_clear_log' ) );
		$_REQUEST = $_POST;

		$this->redirect_of( array( new AdminController( $this->plugin ), 'handle_clear_log' ) );

		$this->assertFalse( get_transient( DashboardWidget::TRANSIENT ) );
	}

	public function test_blocking_an_ip_clears_the_cache(): void {
		$this->widget->data();
		$this->assertNotFalse( get_transient( DashboardWidget::TRANSIENT ) );
		$_GET     = array(
			'ip'       => '198.51.100.99',
			'_wpnonce' => wp_create_nonce( 'wp_bouncer_block_ip|198.51.100.99' ),
		);
		$_REQUEST = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$this->redirect_of( array( new AdminController( $this->plugin ), 'handle_block_ip' ) );

		$this->assertFalse( get_transient( DashboardWidget::TRANSIENT ) );
	}

	public function test_the_daily_maintenance_hook_clears_the_cache(): void {
		$this->widget->data();
		$this->assertNotFalse( get_transient( DashboardWidget::TRANSIENT ) );

		( new DashboardWidget( $this->plugin ) )->register();
		$this->assertSame( 20, has_action( \WPBouncer\Installer::CRON_HOOK, array( DashboardWidget::class, 'flush' ) ) );
		DashboardWidget::flush();

		$this->assertFalse( get_transient( DashboardWidget::TRANSIENT ) );
	}

	public function test_a_mode_change_does_not_show_stale_labels(): void {
		$this->seed( array( 'action' => 'monitored' ) );
		$this->assertSame( 'enforce', $this->widget->data()['status'] );

		$this->set_settings( array( 'mode' => 'monitor' ) );

		$this->assertSame( 'monitor', $this->widget->data()['status'], 'the cached entry is keyed on the status' );
	}

	public function test_an_empty_log_in_monitor_mode_says_nothing_logged(): void {
		$this->set_settings( array( 'mode' => 'monitor' ) );

		$this->assertStringContainsString( 'Nothing logged in the last 14 days', $this->render() );
	}

	public function test_the_flood_note_shows_in_the_empty_state_too(): void {
		$this->seed( array( 'action' => 'suppressed' ) );

		$out = $this->render();

		$this->assertStringContainsString( 'Nothing blocked in the last 14 days', $out );
		$this->assertStringContainsString( 'lower bound', $out );
	}

	public function test_the_switched_off_state_shows_history_and_says_so(): void {
		$this->seed( array(), 600 );
		$widget = new DashboardWidget( $this->plugin, null, static fn() => true );

		ob_start();
		$widget->render();
		$out = (string) ob_get_clean();

		$this->assertStringContainsString( 'WP Bouncer is switched off in wp-config.php', $out );
		$this->assertStringContainsString( 'Blocked before it was switched off', $out );
		$this->assertSame( 'disabled', $widget->data()['status'] );
		$this->assertSame( 1, $widget->data()['h24'] );
	}

	public function test_a_log_ip_filter_is_matched_in_canonical_form(): void {
		$this->seed( array( 'ip' => '203.0.113.5' ) );
		$_REQUEST = array( 'log_ip' => '::FFFF:203.0.113.5' );

		$filters = AdminController::log_filters_from_request();

		$this->assertSame( '203.0.113.5', $filters['ip'] );
		$this->assertSame( 1, $this->plugin->log()->count( $filters ) );
	}

	public function test_recent_ignores_rows_older_than_the_window(): void {
		$this->seed( array( 'ip' => '203.0.113.77' ), 20 * DAY_IN_SECONDS );
		$since = gmdate( 'Y-m-d H:i:s', time() - 14 * DAY_IN_SECONDS );

		$this->assertSame( array(), $this->plugin->log()->recent( 5, array( 'blocked' ), $since ) );
	}

	/* ---------------- stampede lock and flood ---------------- */

	public function test_while_another_request_rebuilds_the_stale_copy_is_served_without_queries(): void {
		$this->seed( array() );
		$first = $this->widget->data();
		$this->assertNotFalse( get_transient( DashboardWidget::STALE_TRANSIENT ) );
		delete_transient( DashboardWidget::TRANSIENT );
		set_transient( DashboardWidget::LOCK_TRANSIENT, 1, 30 );
		$this->seed( array() );

		$served  = null;
		$queries = $this->count_log_queries(
			function () use ( &$served ): void {
				$served = $this->widget->data();
			}
		);

		$this->assertSame( 0, $queries );
		$this->assertSame( $first, $served );
		$this->assertSame( 1, $served['h24'], 'the new row is not in the stale copy' );
	}

	public function test_with_the_lock_held_and_no_stale_copy_it_builds_anyway(): void {
		$this->seed( array() );
		set_transient( DashboardWidget::LOCK_TRANSIENT, 1, 30 );

		$data = $this->widget->data();

		$this->assertSame( 1, $data['h24'] );
		$this->assertFalse( get_transient( DashboardWidget::LOCK_TRANSIENT ), 'the lock is released' );
		$this->assertNotFalse( get_transient( DashboardWidget::TRANSIENT ) );
	}

	public function test_a_stale_copy_for_another_status_is_not_served(): void {
		$this->seed( array() );
		$this->widget->data();
		delete_transient( DashboardWidget::TRANSIENT );
		set_transient( DashboardWidget::LOCK_TRANSIENT, 1, 30 );
		$this->set_settings( array( 'mode' => 'monitor' ) );

		$this->assertSame( 'monitor', $this->widget->data()['status'] );
	}

	public function test_clearing_the_cache_also_drops_the_stale_copy(): void {
		$this->widget->data();

		DashboardWidget::flush();

		$this->assertFalse( get_transient( DashboardWidget::STALE_TRANSIENT ) );
	}

	public function test_a_very_large_window_is_cached_for_an_hour_whatever_the_ttl_filter_says(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'bouncer_log';
		$this->seed( array() );
		for ( $i = 0; $i < 17; $i++ ) { // 2^17 = 131072 rows.
			$wpdb->query( "INSERT INTO {$table} (created_at, ip, rule, action) SELECT created_at, ip, rule, action FROM {$table}" ); // phpcs:ignore WordPress.DB
		}
		add_filter( 'wp_bouncer_widget_cache_ttl', static fn() => 60 );

		$data = $this->widget->data();

		$this->assertGreaterThan( DashboardWidget::FLOOD_ROWS, $data['window_total'] );
		$this->assertEqualsWithDelta( time() + 3600, (int) get_option( '_transient_timeout_' . DashboardWidget::TRANSIENT ), 5 );
	}

	/* ---------------- multisite ---------------- */

	public function test_each_site_shows_its_own_data(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		global $wpdb;
		$this->seed( array( 'ip' => '203.0.113.1' ) );
		$main_out = $this->render();
		$this->assertStringContainsString( '203.0.113.1', $main_out );

		$blog = self::factory()->blog->create();
		add_user_to_blog( $blog, get_current_user_id(), 'administrator' );
		$this->reset_log_service();
		switch_to_blog( $blog );
		try {
			// The plugin keeps one log object, bound to the table prefix it was built with.
			$this->reset_log_service();
			\WPBouncer\Installer::create_tables();
			$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB
			foreach ( array( '198.51.100.20', '198.51.100.21', '198.51.100.22' ) as $ip ) {
				$this->seed( array( 'ip' => $ip ) );
			}
			$this->assertFalse( get_transient( DashboardWidget::TRANSIENT ), 'the cache is per site' );

			$out = $this->render();

			$this->assertStringContainsString( '198.51.100.21', $out );
			$this->assertStringNotContainsString( '203.0.113.1', $out );
			$this->assertSame( 3, $this->widget->data()['h24'] );
			DashboardWidget::flush();
		} finally {
			restore_current_blog();
			$this->reset_log_service();
		}
		$this->assertStringContainsString( '203.0.113.1', $this->render() );
		$this->assertSame( 1, $this->widget->data()['h24'] );
	}

	private function reset_log_service(): void {
		( new \ReflectionProperty( \WPBouncer\Plugin::class, 'log' ) )->setValue( $this->plugin, null );
	}

	public function test_it_is_not_added_to_the_network_dashboard(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $id );
		wp_set_current_user( $id );
		set_current_screen( 'dashboard-network' );

		$this->assertTrue( is_network_admin(), 'the screen stands in for a network admin request' );

		$this->widget->add_widget();

		$this->assertFalse( $this->registered() );
		$this->assertFalse( has_action( 'wp_network_dashboard_setup', array( $this->widget, 'add_widget' ) ) );
	}
}
