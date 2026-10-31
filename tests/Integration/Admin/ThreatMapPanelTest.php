<?php
/**
 * The Activity Log threat map (WPB-11): query, filters, date range, cache, states, escaping, enqueue, permissions.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\ThreatMapPanel;
use WPBouncer\Admin\DashboardWidget;
use WPBouncer\Installer;
use WPBouncer\Log\BlockLog;
use WPBouncer\Plugin;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Tests\Support\FakeThreatSource;
use WPBouncer\Tests\Support\FrozenClock;

/**
 * @covers \WPBouncer\Admin\ThreatMapPanel
 * @covers \WPBouncer\Log\BlockLog::threats_by_country
 * @covers \WPBouncer\Log\BlockLog::where
 * @covers \WPBouncer\Admin\AdminController::log_date_range
 * @covers \WPBouncer\Admin\AdminController::enqueue_assets
 */
final class ThreatMapPanelTest extends IntegrationTestCase {

	public function set_up() {
		parent::set_up();
		set_current_screen( 'toplevel_page_wp-bouncer' );
		$GLOBALS['hook_suffix'] = 'toplevel_page_wp-bouncer';
		$this->login( 'administrator' );
		update_option( Plugin::GEO_META_OPTION, array( 'rows' => 5 ) );
		update_option( ThreatMapPanel::KEYS_OPTION, array(), false );
		$this->panel()->register();
	}

	public function tear_down() {
		remove_all_filters( 'wp_bouncer_map_cache_ttl' );
		ThreatMapPanel::flush();
		foreach ( array( 'wp-bouncer-map', 'wp-bouncer-admin', 'wp-bouncer-cols' ) as $handle ) {
			wp_dequeue_script( $handle );
			wp_deregister_script( $handle );
			wp_dequeue_style( $handle );
			wp_deregister_style( $handle );
		}
		unset( $GLOBALS['current_screen'], $GLOBALS['hook_suffix'] );
		parent::tear_down();
	}

	private function login( string $role ): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => $role ) ) );
	}

	private function panel( ?FakeThreatSource $source = null, ?FrozenClock $clock = null ): ThreatMapPanel {
		return new ThreatMapPanel( $this->plugin, $clock, $source );
	}

	/**
	 * Insert a log row.
	 *
	 * @param array<string, string> $row     Columns.
	 * @param string|int            $created Seconds ago, or a UTC Y-m-d H:i:s.
	 */
	private function seed( array $row, $created = 60 ): void {
		global $wpdb;
		$wpdb->insert(
			$wpdb->prefix . 'bouncer_log',
			array_merge(
				array(
					'ip'      => '203.0.113.5',
					'rule'    => 'waf',
					'action'  => 'blocked',
					'country' => 'US',
				),
				$row,
				array( 'created_at' => is_int( $created ) ? gmdate( 'Y-m-d H:i:s', time() - $created ) : $created )
			)
		);
	}

	/** Render the panel with the request's filters, as views/log.php does. */
	private function render( ?ThreatMapPanel $panel = null, bool $reset_throttle = true ): string {
		if ( $reset_throttle ) {
			delete_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() );
		}
		ob_start();
		( $panel ?? $this->panel() )->render( AdminController::log_filters_from_request(), AdminController::log_date_range() );
		return (string) ob_get_clean();
	}

	/** @return string[] Country codes with a dot. */
	private function dots( string $html ): array {
		preg_match_all( '/<circle [^>]*data-cc="([^"]*)"/', $html, $m );
		return $m[1];
	}

	private function log_queries( callable $fn ): int {
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

	/** @return string[] Names of the cached map boxes. */
	private function box_names(): array {
		global $wpdb;
		return array_map(
			static function ( $n ) {
				return substr( (string) $n, strlen( '_transient_' ) );
			},
			(array) $wpdb->get_col( "SELECT option_name FROM {$wpdb->options} WHERE option_name REGEXP '^_transient_wpb_map_[0-9a-f]{20}$'" ) // phpcs:ignore WordPress.DB
		);
	}

	/* ---------------- what is counted ---------------- */

	public function test_only_blocked_and_lockout_rows_are_counted_and_unknown_country_is_shown_separately(): void {
		$this->seed( array() );
		$this->seed( array() );
		$this->seed( array( 'action' => 'lockout' ) );
		$this->seed(
			array(
				'action'  => 'monitored',
				'country' => 'DE',
			)
		);
		$this->seed(
			array(
				'action'  => 'suppressed',
				'country' => 'FR',
				'ip'      => '',
			)
		);
		$this->seed(
			array(
				'action'  => 'alert',
				'country' => 'GB',
			)
		);
		$this->seed(
			array(
				'action'  => 'login',
				'country' => 'JP',
			)
		);
		$this->seed( array( 'country' => '' ) );
		$this->seed( array( 'country' => '' ) );
		$this->seed( array( 'country' => 'ZZ' ) );

		$html = $this->render();

		$this->assertSame( array( 'US' ), $this->dots( $html ), 'only US has a dot' );
		$this->assertStringContainsString( 'aria-label="United States (US): 3 threats"', $html );
		$this->assertStringContainsString( 'data-title="United States (US)"', $html );
		$this->assertStringContainsString( 'data-count="3 threats"', $html );
		$this->assertStringContainsString( 'Unknown location: 3 threats', $html );
		$this->assertStringNotContainsString( 'Germany', $html );
	}

	public function test_a_single_unknown_row_uses_the_singular(): void {
		$this->seed( array( 'country' => '' ) );
		$this->seed( array() );

		$this->assertMatchesRegularExpression( '/Unknown location: 1 threat\s*</', $this->render() );
	}

	public function test_default_window_is_thirty_days(): void {
		$this->seed( array(), 29 * DAY_IN_SECONDS );
		$this->seed( array( 'country' => 'DE' ), 45 * DAY_IN_SECONDS );

		$html = $this->render();

		$this->assertSame( array( 'US' ), $this->dots( $html ) );
		$this->assertStringContainsString( 'Last 30 days', $html );
		$this->assertStringContainsString( 'Ignores the search box and the IP filter.', $html );
	}

	/* ---------------- filters ---------------- */

	public function test_it_follows_the_country_and_action_filters(): void {
		$this->seed( array() );
		$this->seed( array( 'country' => 'DE' ) );
		$this->seed(
			array(
				'country' => 'DE',
				'action'  => 'lockout',
			)
		);

		$_REQUEST = array( 'country' => 'de' );
		$html     = $this->render();
		$this->assertSame( array( 'DE' ), $this->dots( $html ) );
		$this->assertStringContainsString( 'Country: Germany (DE)', $html );
		$this->assertStringContainsString( 'aria-label="Germany (DE): 2 threats"', $html );

		$_REQUEST = array( 'log_action' => 'lockout' );
		$html     = $this->render();
		$this->assertSame( array( 'DE' ), $this->dots( $html ) );
		$this->assertStringContainsString( 'Germany (DE): 1 threat"', $html );
	}

	public function test_it_follows_the_rule_filter(): void {
		$this->seed( array( 'rule' => 'waf' ) );
		$this->seed(
			array(
				'rule'    => 'login',
				'country' => 'DE',
			)
		);

		$_REQUEST = array( 'rule' => 'login' );

		$this->assertSame( array( 'DE' ), $this->dots( $this->render() ) );
	}

	public function test_it_ignores_the_search_box_and_the_ip_filter(): void {
		$this->seed( array( 'uri' => '/wp-login.php' ) );
		$this->seed(
			array(
				'country' => 'DE',
				'ip'      => '198.51.100.9',
			)
		);

		$_REQUEST = array(
			's'      => 'no-such-text',
			'log_ip' => '192.0.2.99',
		);
		$html     = $this->render();

		$this->assertEqualsCanonicalizing( array( 'US', 'DE' ), $this->dots( $html ) );
		$this->assertCount( 0, $this->plugin->log()->query( AdminController::log_filters_from_request(), 50, 1 ), 'the table, by contrast, follows them' );
	}

	/** @dataProvider non_threat_actions */
	public function test_a_non_threat_action_filter_shows_the_message_and_runs_no_query( string $action ): void {
		$this->seed( array() );
		$_REQUEST = array( 'log_action' => $action );
		$source   = new FakeThreatSource();

		$html = $this->render( $this->panel( $source ) );

		$this->assertSame( array(), $source->calls );
		$this->assertStringContainsString( 'nothing matches the action filter', $html );
		$this->assertSame( array(), $this->dots( $html ) );
	}

	/** @return array<string, array{0: string}> */
	public static function non_threat_actions(): array {
		return array(
			'monitored'  => array( 'monitored' ),
			'alert'      => array( 'alert' ),
			'login'      => array( 'login' ),
			'suppressed' => array( 'suppressed' ),
		);
	}

	public function test_an_unknown_country_filter_is_not_run_and_is_not_echoed(): void {
		$_REQUEST = array( 'country' => '"><script>alert(1)</script>' );
		$source   = new FakeThreatSource();

		$html = $this->render( $this->panel( $source ) );

		$this->assertSame( array(), $source->calls );
		$this->assertStringContainsString( 'No threats match this filter.', $html );
		$this->assertStringNotContainsString( '<script>alert', $html );
	}

	/* ---------------- date range ---------------- */

	public function test_the_range_follows_log_from_and_log_to(): void {
		$day = gmdate( 'Y-m-d', time() - 10 * DAY_IN_SECONDS );
		$this->seed( array(), $day . ' 12:00:00' );
		$this->seed( array( 'country' => 'DE' ), gmdate( 'Y-m-d H:i:s', time() - 3 * DAY_IN_SECONDS ) );

		$_REQUEST = array(
			'log_from' => $day,
			'log_to'   => $day,
		);
		$html     = $this->render();

		$this->assertSame( array( 'US' ), $this->dots( $html ) );
		$this->assertStringNotContainsString( 'Last 30 days', $html );
	}

	/**
	 * Regression (WPB-11): the Activity Log table applies log_from/log_to, not only the map.
	 */
	public function test_the_to_boundary_is_inclusive_in_the_site_time_zone_and_the_next_day_is_excluded(): void {
		update_option( 'timezone_string', 'Pacific/Auckland' ); // NZDT, UTC+13, in March 2026.
		// The local day 2026-03-10 is [2026-03-09 11:00, 2026-03-10 11:00) UTC.
		$this->seed( array( 'country' => 'US' ), '2026-03-09 11:00:00' );
		$this->seed( array( 'country' => 'DE' ), '2026-03-10 10:59:59' );
		$this->seed( array( 'country' => 'FR' ), '2026-03-10 11:00:00' );
		$this->seed( array( 'country' => 'GB' ), '2026-03-09 10:59:59' );
		$_REQUEST = array(
			'log_from' => '2026-03-10',
			'log_to'   => '2026-03-10',
		);

		$this->assertEqualsCanonicalizing( array( 'US', 'DE' ), $this->dots( $this->render() ) );

		$filters = AdminController::log_filters_from_request();
		$this->assertSame( '2026-03-09 11:00:00', $filters['since'] );
		$this->assertSame( '2026-03-10 11:00:00', $filters['until'] );
		$countries = array_column( $this->plugin->log()->query( $filters, 50, 1 ), 'country' );
		sort( $countries );
		$this->assertSame( array( 'DE', 'US' ), $countries, 'the table uses the same window' );
		$this->assertSame( 2, $this->plugin->log()->count( $filters ) );
	}

	/**
	 * Regression (WPB-11): the table and the CSV export carry the date range, and it round-trips.
	 */
	public function test_the_table_and_the_export_filters_carry_the_range_and_round_trip(): void {
		$_REQUEST = array(
			'log_from' => '2026-03-01',
			'log_to'   => '2026-03-05',
			'country'  => 'DE',
		);

		$filters = AdminController::log_filters_from_request();
		$args    = AdminController::log_filters_to_args( $filters );

		$this->assertSame( '2026-03-01', $args['log_from'] );
		$this->assertSame( '2026-03-05', $args['log_to'] );
		$this->assertSame( 'DE', $args['country'] );
		$this->assertArrayNotHasKey( 'since', $args );
		$this->assertArrayNotHasKey( 'until', $args );
	}

	public function test_no_range_leaves_the_table_unfiltered_by_date(): void {
		$this->seed( array(), 200 * DAY_IN_SECONDS );

		$filters = AdminController::log_filters_from_request();

		$this->assertArrayNotHasKey( 'since', $filters );
		$this->assertArrayNotHasKey( 'until', $filters );
		$this->assertSame( 1, $this->plugin->log()->count( $filters ), 'as in 1.2.x' );
	}

	/** @dataProvider bad_dates */
	public function test_bad_dates_are_ignored_and_the_notice_is_shown( array $request, string $notice ): void {
		$this->seed( array(), 200 * DAY_IN_SECONDS );
		$_REQUEST = $request;
		$_GET     = array( 'tab' => 'log' );

		$html = $this->render_log_tab();

		$this->assertStringContainsString( $notice, $html );
		$this->assertStringContainsString( 'notice-warning', $html );
		$filters = AdminController::log_filters_from_request();
		$this->assertArrayNotHasKey( 'since', $filters, 'ignored, so the table is not date filtered' );
		$this->assertSame( 1, $this->plugin->log()->count( $filters ) );
	}

	/** @return array<string, array{0: array<string, string>, 1: string}> */
	public static function bad_dates(): array {
		$invalid  = 'A date was not valid, so it was ignored.';
		$reversed = 'The end date is before the start date, so the date filter was ignored.';
		return array(
			'short month'  => array( array( 'log_from' => '2026-1-01' ), $invalid ),
			'impossible'   => array( array( 'log_to' => '2026-02-30' ), $invalid ),
			'no dashes'    => array( array( 'log_from' => '20261001' ), $invalid ),
			'datetime'     => array( array( 'log_from' => '2026-10-01T00:00' ), $invalid ),
			'phrase'       => array( array( 'log_to' => 'next monday' ), $invalid ),
			'year 0000'    => array( array( 'log_from' => '0000-01-01' ), $invalid ),
			'reversed'     => array(
				array(
					'log_from' => '2026-03-05',
					'log_to'   => '2026-03-01',
				),
				$reversed,
			),
		);
	}

	public function test_a_range_over_365_days_is_capped_to_the_end_date_and_noted(): void {
		$_REQUEST = array(
			'log_from' => '2020-01-01',
			'log_to'   => '2026-03-10',
		);
		$_GET     = array( 'tab' => 'log' );
		$source   = new FakeThreatSource();

		$html = $this->render( $this->panel( $source ) );
		$this->assertStringContainsString( 'limited to 365 days', $this->render_log_tab() );

		$this->assertSame( '2026-03-11 00:00:00', $source->calls[0][2] );
		$this->assertSame( '2025-03-11 00:00:00', $source->calls[0][1], '365 days ending 2026-03-10' );
		$this->assertStringNotContainsString( 'Last 30 days', $html );
	}

	public function test_an_array_value_is_ignored_without_error(): void {
		$_REQUEST = array( 'log_from' => array( '2026-03-01' ) );

		$filters = AdminController::log_filters_from_request();

		$this->assertArrayNotHasKey( 'since', $filters );
		$this->assertStringContainsString( 'Last 30 days', $this->render() );
	}

	public function test_a_future_to_is_clamped_to_today(): void {
		$this->seed( array(), 60 );
		$_REQUEST = array( 'log_to' => '2099-01-01' );

		$this->assertSame( array( 'US' ), $this->dots( $this->render() ) );
	}

	public function test_the_date_inputs_are_refilled_and_a_country_filter_survives_a_new_submit(): void {
		$_REQUEST = array(
			'log_from' => '2026-03-01',
			'log_to'   => '2026-03-05',
			'country'  => 'DE',
		);
		$_GET     = array( 'tab' => 'log' );

		$html = $this->render_log_tab();

		$this->assertMatchesRegularExpression( '/<input type="date" name="log_from"[^>]*value="2026-03-01"/', $html );
		$this->assertMatchesRegularExpression( '/<input type="date" name="log_to"[^>]*value="2026-03-05"/', $html );
		$this->assertMatchesRegularExpression( '/<input type="hidden" name="country" value="DE">/', $html );
		$this->assertMatchesRegularExpression( '/<input type="date" name="log_to"[^>]*max="' . gmdate( 'Y-m-d' ) . '"/', $html );
	}

	private function render_log_tab(): string {
		$admin = new AdminController( $this->plugin );
		ob_start();
		$admin->render();
		return (string) ob_get_clean();
	}

	/* ---------------- states ---------------- */

	public function test_the_empty_state_has_no_map(): void {
		$html = $this->render();

		$this->assertStringContainsString( 'No threats recorded in this period yet.', $html );
		$this->assertStringNotContainsString( 'wpb-map-dots', $html );
	}

	public function test_without_a_geo_database_and_no_known_country_the_map_is_not_drawn(): void {
		delete_option( Plugin::GEO_META_OPTION );
		$this->seed( array( 'country' => '' ) );

		$html = $this->render();

		$this->assertStringContainsString( 'Country data needs the geolocation database.', $html );
		$this->assertStringContainsString( 'tab=tools', $html );
		$this->assertStringContainsString( 'Unknown location: 1 threat', $html );
		$this->assertStringNotContainsString( 'wpb-map-dots', $html );
	}

	public function test_header_only_countries_still_draw_the_map_without_a_geo_database(): void {
		delete_option( Plugin::GEO_META_OPTION );
		$this->seed( array() );

		$html = $this->render();

		$this->assertSame( array( 'US' ), $this->dots( $html ) );
		$this->assertStringContainsString( 'No geolocation database is installed', $html );
	}

	public function test_a_database_error_shows_a_generic_message_and_caches_nothing(): void {
		$source       = new FakeThreatSource();
		$source->rows = null;

		$html = $this->render( $this->panel( $source ) );

		$this->assertStringContainsString( 'The map could not be loaded.', $html );
		$this->assertStringNotContainsString( 'SELECT', $html );
		$this->assertSame( array(), $this->box_names() );
		$this->assertFalse( get_option( ThreatMapPanel::LOCK_OPTION ), 'the lock is released' );
	}

	public function test_a_database_error_on_a_refresh_serves_the_stale_numbers(): void {
		$clock        = new FrozenClock( time() );
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 4 );
		$this->render( $this->panel( $source, $clock ) );
		$clock->advance( 400 ); // Past the 300 s default TTL.
		$source->rows = null;
		delete_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() );

		$html = $this->render( $this->panel( $source, $clock ) );

		$this->assertCount( 2, $source->calls );
		$this->assertSame( array( 'US' ), $this->dots( $html ) );
	}

	public function test_the_table_and_the_map_note_are_not_blocked_by_the_panel_states(): void {
		$_REQUEST = array( 'log_action' => 'monitored' );
		$_GET     = array( 'tab' => 'log' );

		$html = $this->render_log_tab();

		$this->assertStringContainsString( 'wpb-map', $html );
		$this->assertStringContainsString( 'wpb-log-form', $html );
	}

	/* ---------------- cache ---------------- */

	public function test_the_second_render_runs_no_map_query(): void {
		$this->seed( array() );

		$first  = $this->log_queries( fn() => $this->render() );
		$second = $this->log_queries( fn() => $this->render() );

		$this->assertGreaterThanOrEqual( 1, $first );
		$this->assertSame( 0, $second );
		$this->assertCount( 1, $this->box_names() );
		$keys = get_option( ThreatMapPanel::KEYS_OPTION );
		$this->assertCount( 1, $keys['keys'] );
	}

	public function test_a_different_filter_is_a_different_box_and_search_and_ip_are_not(): void {
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 1 );
		$panel        = $this->panel( $source );

		$this->render( $panel );
		$_REQUEST = array(
			's'      => 'x',
			'log_ip' => '192.0.2.1',
		);
		$this->render( $panel );
		$this->assertCount( 1, $source->calls, 'search and IP change nothing' );

		$_REQUEST = array( 'country' => 'US' );
		$this->render( $panel );
		$this->assertCount( 2, $source->calls );
	}

	public function test_the_map_filters_never_pass_search_or_ip_to_the_source(): void {
		$source = new FakeThreatSource();
		$_REQUEST = array(
			's'          => 'needle',
			'log_ip'     => '192.0.2.1',
			'log_action' => 'blocked',
		);

		$this->render( $this->panel( $source ) );

		$this->assertSame( array( 'action' => 'blocked' ), $source->calls[0][0] );
	}

	public function test_at_most_twenty_boxes_survive_a_hundred_filter_sets(): void {
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 1 );
		$clock        = new FrozenClock( time() );
		$panel        = $this->panel( $source, $clock );

		for ( $i = 0; $i < 100; $i++ ) {
			$_REQUEST = array( 'rule' => 'r' . $i );
			delete_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() );
			$clock->advance( 1 );
			$this->render( $panel );
		}

		$this->assertCount( 100, $source->calls );
		$this->assertLessThanOrEqual( 20, count( $this->box_names() ) );
		$keys = get_option( ThreatMapPanel::KEYS_OPTION );
		$this->assertLessThanOrEqual( 20, count( $keys['keys'] ) );
		$this->assertEqualsCanonicalizing( array_keys( $keys['keys'] ), $this->box_names(), 'the index and the transients agree' );
	}

	public function test_the_ttl_is_five_minutes_clamped_and_an_hour_on_a_flooded_log(): void {
		$clock  = new FrozenClock( 1800000000 );
		$source = new FakeThreatSource();
		$ttl    = function ( ?int $filter, int $total ) use ( $source, $clock ): int {
			ThreatMapPanel::flush();
			delete_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() );
			remove_all_filters( 'wp_bouncer_map_cache_ttl' );
			if ( null !== $filter ) {
				add_filter( 'wp_bouncer_map_cache_ttl', static fn() => $filter );
			}
			$source->rows = array( 'US' => $total );
			$this->render( $this->panel( $source, $clock ) );
			$keys = get_option( ThreatMapPanel::KEYS_OPTION );
			$box  = get_transient( (string) array_key_first( $keys['keys'] ) );
			return (int) $box['fresh_until'] - 1800000000;
		};

		$this->assertSame( 300, $ttl( null, 5 ) );
		$this->assertSame( 60, $ttl( 1, 5 ), 'clamped up' );
		$this->assertSame( 3600, $ttl( 999999, 5 ), 'clamped down' );
		$this->assertSame( 3600, $ttl( null, DashboardWidget::FLOOD_ROWS + 1 ), 'flood' );
		$this->assertSame( 300, $ttl( null, DashboardWidget::FLOOD_ROWS ), 'at the limit is not a flood' );
	}

	public function test_the_flush_events_throw_the_cache_away(): void {
		foreach ( array( 'wp_bouncer_log_cleared', 'wp_bouncer_settings_changed' ) as $hook ) {
			$this->seed( array() );
			$this->render();
			$this->assertCount( 1, $this->box_names(), $hook );
			$before = (int) get_option( ThreatMapPanel::GEN_OPTION, 0 );

			do_action( $hook );

			$this->assertSame( array(), $this->box_names(), $hook );
			$after = get_option( ThreatMapPanel::KEYS_OPTION );
			$this->assertSame( array(), $after['keys'] );
			$this->assertSame( $before + 1, (int) get_option( ThreatMapPanel::GEN_OPTION ) );
		}
		$this->render();
		do_action( Installer::CRON_HOOK );
		$this->assertSame( array(), $this->box_names(), 'the daily job flushes it too' );
		$this->assertSame( 20, has_action( Installer::CRON_HOOK, array( ThreatMapPanel::class, 'flush' ) ) );
	}

	public function test_clearing_the_log_shows_fresh_numbers(): void {
		global $wpdb;
		$this->seed( array() );
		$this->assertSame( array( 'US' ), $this->dots( $this->render() ) );
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB
		delete_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() );

		do_action( 'wp_bouncer_log_cleared' );

		$this->assertStringContainsString( 'No threats recorded', $this->render() );
	}

	public function test_an_orphan_box_is_unreachable_after_a_flush(): void {
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 1 );
		$this->render( $this->panel( $source ) );
		// A lost update: the index forgets the box, but the transient is still there.
		update_option( ThreatMapPanel::KEYS_OPTION, array( 'keys' => array() ), false );
		$this->assertCount( 1, $this->box_names() );

		ThreatMapPanel::flush();
		$source->rows = array( 'DE' => 9 );
		delete_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() );
		$html = $this->render( $this->panel( $source ) );

		$this->assertSame( array( 'DE' ), $this->dots( $html ) );
	}

	public function test_a_flush_during_a_rebuild_is_not_undone(): void {
		$source          = new FakeThreatSource();
		$source->rows    = array( 'US' => 1 );
		$source->on_call = static function (): void {
			ThreatMapPanel::flush();
		};
		$gen_before      = (int) get_option( ThreatMapPanel::GEN_OPTION, 0 );

		$this->render( $this->panel( $source ) );

		$index = get_option( ThreatMapPanel::KEYS_OPTION );
		$this->assertSame( $gen_before + 1, (int) get_option( ThreatMapPanel::GEN_OPTION ), 'the flushed generation stands' );
		$this->assertSame( array(), $index['keys'] );
		$this->assertSame( array(), $this->box_names(), 'the pre-flush box was deleted' );
		$plain       = new FakeThreatSource();
		$plain->rows = array( 'DE' => 1 );
		$this->assertSame( array( 'DE' ), $this->dots( $this->render( $this->panel( $plain ) ) ), 'the next render queries again' );
	}

	public function test_a_flush_between_the_recheck_and_the_index_write_cannot_lose_the_bump(): void {
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 1 );
		$gen_before   = (int) get_option( ThreatMapPanel::GEN_OPTION, 0 );
		$fired        = false;
		add_filter(
			'pre_update_option_' . ThreatMapPanel::KEYS_OPTION,
			static function ( $value ) use ( &$fired ) {
				if ( ! $fired ) {
					$fired = true;
					ThreatMapPanel::flush();
				}
				return $value;
			}
		);

		$this->render( $this->panel( $source ) );
		remove_all_filters( 'pre_update_option_' . ThreatMapPanel::KEYS_OPTION );

		$this->assertTrue( $fired );
		$this->assertSame( $gen_before + 1, (int) get_option( ThreatMapPanel::GEN_OPTION ), 'the generation did not go back' );
		$this->assertArrayNotHasKey( 'gen', (array) get_option( ThreatMapPanel::KEYS_OPTION ), 'the index holds no generation' );
		$plain       = new FakeThreatSource();
		$plain->rows = array( 'DE' => 1 );
		$this->assertSame( array( 'DE' ), $this->dots( $this->render( $this->panel( $plain ) ) ), 'the pre-flush box is unreachable' );
	}

	public function test_a_fresh_lock_row_makes_acquire_return_null(): void {
		$held = time() . '|other';
		update_option( ThreatMapPanel::LOCK_OPTION, $held, false );

		$this->assertNull( ThreatMapPanel::acquire_lock() );
		$this->assertSame( $held, get_option( ThreatMapPanel::LOCK_OPTION ) );
	}

	public function test_a_free_lock_is_taken_once_and_the_cache_is_coherent(): void {
		get_option( ThreatMapPanel::LOCK_OPTION ); // Primes notoptions.
		$token = ThreatMapPanel::acquire_lock();

		$this->assertIsString( $token );
		$this->assertStringEndsWith( '|' . $token, (string) get_option( ThreatMapPanel::LOCK_OPTION ) );
		$this->assertNull( ThreatMapPanel::acquire_lock(), 'a second request does not get it' );
	}

	public function test_a_stale_lock_is_swapped_once_and_the_old_value_swaps_no_more(): void {
		global $wpdb;
		$stale = ( time() - 120 ) . '|gone';
		update_option( ThreatMapPanel::LOCK_OPTION, $stale, false );

		$first = ThreatMapPanel::acquire_lock();
		$this->assertIsString( $first );

		// A racing request that read the same stale value: its compare-and-swap matches nothing.
		$late = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $wpdb->options, time() . '|late', ThreatMapPanel::LOCK_OPTION, $stale ) );
		$this->assertSame( 0, $late );
		$this->assertStringEndsWith( '|' . $first, (string) $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, ThreatMapPanel::LOCK_OPTION ) ) );
	}

	public function test_releasing_with_the_wrong_token_leaves_the_row_and_the_right_one_removes_it(): void {
		$token = ThreatMapPanel::acquire_lock();
		$this->assertIsString( $token );

		ThreatMapPanel::release_lock( 'wrongtoken12' );
		$this->assertStringEndsWith( '|' . $token, (string) get_option( ThreatMapPanel::LOCK_OPTION ), 'row left alone' );

		ThreatMapPanel::release_lock( $token );
		$this->assertFalse( get_option( ThreatMapPanel::LOCK_OPTION ) );
	}

	public function test_a_second_build_does_not_run_while_a_build_holds_the_lock(): void {
		$inner           = new FakeThreatSource();
		$inner->rows     = array( 'DE' => 1 );
		$outer           = new FakeThreatSource();
		$outer->rows     = array( 'US' => 1 );
		$outer->on_call  = function () use ( $inner ): void {
			$this->second_render( $inner );
		};

		$this->render( $this->panel( $outer ) );

		$this->assertSame( array(), $inner->calls, 'the overlapping request did not aggregate' );
	}

	/** Called from a fake source: render as another user while a build holds the lock. */
	public function second_render( FakeThreatSource $source ): void {
		$me = get_current_user_id();
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$html = $this->render( $this->panel( $source ) );
		wp_set_current_user( $me );
		$this->assertStringContainsString( 'The map is being updated', $html );
	}

	public function test_the_lock_of_another_request_is_left_alone_and_a_stale_one_is_replaced(): void {
		$held = time() . '|other';
		update_option( ThreatMapPanel::LOCK_OPTION, $held, false );
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 1 );

		$html = $this->render( $this->panel( $source ) );

		$this->assertSame( array(), $source->calls );
		$this->assertStringContainsString( 'The map is being updated', $html );
		$this->assertSame( $held, get_option( ThreatMapPanel::LOCK_OPTION ), 'not deleted by a request that does not own it' );

		update_option( ThreatMapPanel::LOCK_OPTION, ( time() - 120 ) . '|gone', false );
		$this->assertSame( array( 'US' ), $this->dots( $this->render( $this->panel( $source ) ) ) );
		$this->assertFalse( get_option( ThreatMapPanel::LOCK_OPTION ), 'released by its new owner' );
	}

	public function test_overlapping_builds_with_many_filter_sets_keep_at_most_twenty_boxes(): void {
		$inner       = new FakeThreatSource();
		$inner->rows = array( 'DE' => 1 );
		for ( $i = 0; $i < 30; $i++ ) {
			$_REQUEST        = array( 'rule' => 'r' . $i );
			$outer           = new FakeThreatSource();
			$outer->rows     = array( 'US' => 1 );
			$outer->on_call  = function () use ( $inner ): void {
				$this->second_render( $inner );
			};
			$this->render( $this->panel( $outer ) );
		}

		$this->assertSame( array(), $inner->calls, 'no overlapping aggregate ever ran' );
		$this->assertMatchesRegularExpression( '/^\d+$/', (string) count( $this->box_names() ) );
		$this->assertLessThanOrEqual( 20, count( $this->box_names() ) );
		$this->assertCount( count( $this->box_names() ), get_option( ThreatMapPanel::KEYS_OPTION )['keys'] );
	}

	public function test_the_admin_fallback_purge_flushes_the_map_cache(): void {
		$this->seed( array() );
		$this->render();
		$gen = (int) get_option( ThreatMapPanel::GEN_OPTION, 0 );
		update_option( Plugin::LAST_PURGE_OPTION, time() - 3 * DAY_IN_SECONDS );

		$this->plugin->maybe_purge();

		$this->assertSame( $gen + 1, (int) get_option( ThreatMapPanel::GEN_OPTION ) );
		$this->assertSame( array(), $this->box_names() );
	}

	public function test_a_held_throttle_with_no_box_shows_busy_and_runs_no_query(): void {
		set_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id(), 1, 5 );
		$source = new FakeThreatSource();

		$html = $this->render( $this->panel( $source ), false );

		$this->assertSame( array(), $source->calls );
		$this->assertStringContainsString( 'The map is being updated. Reload the page in a few seconds.', $html );
	}

	public function test_a_held_lock_with_a_stale_box_serves_it_with_an_age(): void {
		$clock        = new FrozenClock( time() );
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 2 );
		$this->render( $this->panel( $source, $clock ) );
		$clock->advance( 700 );
		delete_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() );
		update_option( ThreatMapPanel::LOCK_OPTION, time() . '|other', false );
		$source->rows = array( 'DE' => 2 );

		$html = $this->render( $this->panel( $source, $clock ) );

		$this->assertCount( 1, $source->calls, 'no rebuild while another request holds the lock' );
		$this->assertSame( array( 'US' ), $this->dots( $html ) );
		$this->assertStringContainsString( 'Updated 12 minutes ago.', $html );
	}

	public function test_the_throttle_is_per_user(): void {
		$source       = new FakeThreatSource();
		$source->rows = array( 'US' => 1 );
		$this->render( $this->panel( $source ) );
		$this->assertNotFalse( get_transient( ThreatMapPanel::THROTTLE_PREFIX . get_current_user_id() ) );

		$_REQUEST = array( 'country' => 'US' );
		$this->login( 'administrator' );
		$html = $this->render( $this->panel( $source ) );

		$this->assertCount( 2, $source->calls, 'a second admin is not throttled by the first' );
		$this->assertStringContainsString( 'wpb-map-dots', $html );
	}

	/* ---------------- escaping and privacy ---------------- */

	public function test_stored_junk_in_the_country_column_is_never_printed(): void {
		$this->seed( array( 'country' => '<<' ) );
		$this->seed( array( 'country' => '<' ) );
		$this->seed( array( 'country' => 'de' ) );

		$html = $this->render();

		$this->assertStringNotContainsString( 'onerror', $html );
		$this->assertStringNotContainsString( '<img src=x', $html );
		$this->assertSame( array( 'DE' ), $this->dots( $html ), 'lower case is merged into a valid code' );
		$this->assertStringContainsString( 'Unknown location: 2 threats', $html );
	}

	public function test_a_hostile_action_filter_is_escaped(): void {
		$_REQUEST = array( 'log_action' => '<script>alert(1)</script>' );

		$html = $this->render();

		$this->assertStringNotContainsString( '<script>alert', $html );
	}

	public function test_the_rendered_panel_contains_no_ip_uri_or_user_agent(): void {
		$this->seed(
			array(
				'ip'         => '198.51.100.77',
				'uri'        => '/secret-path?x=1',
				'user_agent' => 'EvilBot/9.9',
				'reason'     => 'Reason-text-zzz',
			)
		);
		$this->seed(
			array(
				'ip'      => '2001:db8::dead:beef',
				'country' => 'DE',
				'uri'     => '/other-path',
			)
		);

		$html = $this->render();

		foreach ( array( '198.51.100.77', '2001:db8', 'dead:beef', 'secret-path', 'other-path', 'EvilBot', 'Reason-text-zzz' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, $html, $needle );
		}
		$this->assertDoesNotMatchRegularExpression( '#https?://(?!example\.org)#', (string) preg_replace( '#<a [^>]*href="[^"]*"#', '', $html ), 'no external URL in the markup' );
	}

	public function test_the_panel_references_only_the_plugins_own_base_map(): void {
		$this->seed( array() );

		$html = $this->render();

		$this->assertSame( 1, preg_match( '/<img class="wpb-map-base" src="([^"]+)"/', $html, $m ) );
		$this->assertStringContainsString( '/assets/map/world.svg?ver=' . Plugin::VERSION, $m[1] );
		$this->assertStringContainsString( 'alt=""', $html );
		$this->assertDoesNotMatchRegularExpression( '/<script|<iframe|<object|<embed/i', $html );
	}

	/* ---------------- enqueue ---------------- */

	private function enqueue( ?string $tab, string $hook = 'toplevel_page_wp-bouncer' ): void {
		unset( $_GET['tab'] );
		if ( null !== $tab ) {
			$_GET['tab'] = $tab;
		}
		( new AdminController( $this->plugin ) )->enqueue_assets( $hook );
	}

	public function test_assets_load_on_the_activity_log_tab_only_and_carry_no_nonce(): void {
		$this->enqueue( 'log' );

		$this->assertTrue( wp_script_is( 'wp-bouncer-map', 'enqueued' ) );
		$this->assertTrue( wp_style_is( 'wp-bouncer-map', 'enqueued' ) );
		$scripts = wp_scripts();
		$this->assertSame( array(), $scripts->registered['wp-bouncer-map']->deps, 'no jQuery' );
		$this->assertStringContainsString( 'assets/threat-map.js', (string) $scripts->registered['wp-bouncer-map']->src );
		$this->assertSame( 'defer', $scripts->get_data( 'wp-bouncer-map', 'strategy' ) );
		$data = (string) $scripts->get_data( 'wp-bouncer-map', 'data' );
		$this->assertStringContainsString( 'wpBouncerMap', $data );
		$this->assertStringNotContainsString( 'nonce', strtolower( $data ) );
		$this->assertStringContainsString( 'Hide map', $data );
	}

	/** @dataProvider other_tabs */
	public function test_assets_do_not_load_on_other_tabs( ?string $tab ): void {
		$this->enqueue( $tab );

		$this->assertFalse( wp_script_is( 'wp-bouncer-map', 'enqueued' ) );
		$this->assertFalse( wp_style_is( 'wp-bouncer-map', 'enqueued' ) );
		$this->assertTrue( wp_script_is( 'wp-bouncer-admin', 'enqueued' ) );
	}

	/** @return array<string, array{0: ?string}> */
	public static function other_tabs(): array {
		return array(
			'dashboard' => array( 'dashboard' ),
			'general'   => array( 'general' ),
			'rules'     => array( 'rules' ),
			'countries' => array( 'countries' ),
			'traffic'   => array( 'traffic' ),
			'tools'     => array( 'tools' ),
			'none'      => array( null ),
			'logx'      => array( 'logx' ),
			'log/..'    => array( 'log/../x' ),
		);
	}

	/** @dataProvider other_hooks */
	public function test_assets_do_not_load_on_other_screens( string $hook ): void {
		$this->enqueue( 'log', $hook );

		$this->assertFalse( wp_script_is( 'wp-bouncer-map', 'enqueued' ) );
		$this->assertFalse( wp_style_is( 'wp-bouncer-map', 'enqueued' ) );
	}

	/** @return array<string, array{0: string}> */
	public static function other_hooks(): array {
		return array(
			'dashboard'       => array( 'index.php' ),
			'network'         => array( 'toplevel_page_wp-bouncer-network' ),
			'other plugin'    => array( 'settings_page_other' ),
			'front end hook'  => array( '' ),
		);
	}

	public function test_nothing_is_hooked_for_the_front_end(): void {
		$this->assertFalse( has_action( 'wp_enqueue_scripts', array( ThreatMapPanel::class, 'flush' ) ) );
		$this->assertFalse( wp_script_is( 'wp-bouncer-map', 'registered' ), 'nothing registered before the admin enqueues it' );
		$this->assertFalse( has_action( 'wp_ajax_wpb_map' ) );
	}

	/* ---------------- permissions ---------------- */

	/** @dataProvider lesser_roles */
	public function test_users_without_the_capability_get_no_map( string $role ): void {
		$this->seed( array() );
		$this->login( $role );
		$source = new FakeThreatSource();

		$html = $this->render( $this->panel( $source ) );

		$this->assertSame( '', $html );
		$this->assertSame( array(), $source->calls );
	}

	/** @return array<string, array{0: string}> */
	public static function lesser_roles(): array {
		return array(
			'editor'     => array( 'editor' ),
			'author'     => array( 'author' ),
			'subscriber' => array( 'subscriber' ),
		);
	}

	public function test_a_visitor_gets_no_map(): void {
		wp_set_current_user( 0 );

		$this->assertSame( '', $this->render() );
	}

	public function test_the_network_admin_gets_no_map(): void {
		set_current_screen( 'dashboard-network' );
		$source = new FakeThreatSource();

		$html = $this->render( $this->panel( $source ) );

		$this->assertSame( '', $html );
		$this->assertSame( array(), $source->calls );
	}

	/* ---------------- multisite ---------------- */

	public function test_a_second_sites_map_excludes_the_first_sites_rows_and_cache(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		global $wpdb;
		$this->use_real_ddl();
		$this->seed( array() ); // Site 1: US.
		$this->assertSame( array( 'US' ), $this->dots( $this->render() ) );
		$wpdb->query( 'COMMIT' );

		$site = self::factory()->blog->create();
		switch_to_blog( $site );
		Installer::activate();
		update_option( Plugin::GEO_META_OPTION, array( 'rows' => 5 ) );
		$this->seed( array( 'country' => 'DE' ) );
		$other = $this->render();
		$this->assertSame( array( 'DE' ), $this->dots( $other ), 'site 2 sees only its own rows, not site 1 cache or rows' );
		restore_current_blog();

		$this->assertSame( array( 'US' ), $this->dots( $this->render() ) );
	}
}
