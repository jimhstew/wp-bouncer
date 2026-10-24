<?php
/**
 * Site Health registration, the capability gate, the notice and the dismissal.
 *
 * Runs in both modes: on a single site the administrator may see the results;
 * on multisite only a super admin may (wpb_manage_firewall).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Environment;

use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\EnvironmentAdmin;
use WPBouncer\Environment\EnvironmentInterface;
use WPBouncer\Environment\EnvironmentReport;
use WPBouncer\Environment\Report;
use WPBouncer\Environment\Severity;
use WPBouncer\Environment\SiteHealth;
use WPBouncer\Environment\SupportPolicy;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Tests\Support\FakeEnvironment;
use WPBouncer\Tests\Support\FrozenClock;

/**
 * @covers \WPBouncer\Environment\EnvironmentAdmin
 * @covers \WPBouncer\Environment\SiteHealth
 * @covers \WPBouncer\Environment\RuntimeEnvironment
 */
final class EnvironmentAdminTest extends IntegrationTestCase {

	/** 2026-10-24 12:00 UTC. */
	private const NOW = 1792843200;

	/** @var FrozenClock */
	private $clock;

	public function set_up() {
		parent::set_up();
		$this->clock = new FrozenClock( self::NOW );
	}

	private function admin_user(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $id );
		return $id;
	}

	private function network_admin(): int {
		$id = $this->admin_user();
		if ( is_multisite() ) {
			grant_super_admin( $id );
			wp_set_current_user( $id );
		}
		return $id;
	}

	private function eol_env(): FakeEnvironment {
		return new FakeEnvironment( php: '8.1.30', db: '10.11.6-MariaDB' );
	}

	private function admin( ?FakeEnvironment $env = null ): EnvironmentAdmin {
		return new EnvironmentAdmin( $this->clock, $env ?? new FakeEnvironment(), new SupportPolicy() );
	}

	private function html( callable $fn ): string {
		ob_start();
		$fn();
		return (string) ob_get_clean();
	}

	/* ---------------- Site Health ---------------- */

	public function test_the_plugin_registers_its_site_health_tests_and_they_work_with_nobody_logged_in(): void {
		( new EnvironmentAdmin() )->register(); // The plugin does this in admin and cron requests.
		wp_set_current_user( 0 );
		$tests = apply_filters(
			'site_status_tests',
			array(
				'direct' => array(),
				'async'  => array(),
			)
		);

		foreach ( array( 'wp_bouncer_php_eol', 'wp_bouncer_db_eol', 'wp_bouncer_php_settings', 'wp_bouncer_wp_hardening' ) as $id ) {
			$this->assertArrayHasKey( $id, $tests['direct'], $id );
			$result = call_user_func( $tests['direct'][ $id ]['test'] );
			$this->assertContains( $result['status'], array( 'good', 'recommended', 'critical' ) );
			$this->assertSame( 'WP Bouncer', $result['badge']['label'] );
			$this->assertSame( $id, $result['test'] );
			$this->assertNotSame( '', $result['label'] );
			$this->assertIsString( $result['description'] );
		}
		$this->assertArrayNotHasKey( 'wp_bouncer_php_eol', $tests['async'], 'direct tests only' );
	}

	/**
	 * @dataProvider status_mapping
	 */
	public function test_site_health_maps_severities( Severity $severity, string $expected ): void {
		$report = new Report( array( new CheckResult( 'wpb_php_version', CheckResult::GROUP_VERSIONS, $severity, 'PHP version', 'PHP 8.x' ) ) );
		$health = new SiteHealth( static fn(): Report => $report );

		$this->assertSame( $expected, $health->result( 'wp_bouncer_php_eol' )['status'] );
	}

	/** @return array<string, array{Severity, string}> */
	public static function status_mapping(): array {
		return array(
			'critical' => array( Severity::Critical, 'critical' ),
			'warning'  => array( Severity::Warning, 'recommended' ),
			'notice'   => array( Severity::Notice, 'recommended' ),
			'info'     => array( Severity::Info, 'good' ),
			'ok'       => array( Severity::Ok, 'good' ),
			'unknown'  => array( Severity::Unknown, 'recommended' ),
		);
	}

	public function test_an_unconfirmed_version_is_recommended_never_good(): void {
		$report = new Report( array( new CheckResult( 'wpb_db_version', CheckResult::GROUP_VERSIONS, Severity::Unknown, 'Database version', 'x' ) ) );
		$result = ( new SiteHealth( static fn(): Report => $report ) )->result( 'wp_bouncer_db_eol' );

		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( 'confirm this version', $result['description'] );
	}

	public function test_a_version_check_that_failed_is_recommended_not_good(): void {
		$boom   = new class() implements CheckInterface {
			public function id(): string {
				return 'wpb_php_version';
			}
			public function run( EnvironmentInterface $env ): CheckResult {
				throw new \RuntimeException( 'boom' );
			}
		};
		$report = ( new EnvironmentReport( array( $boom ) ) )->run( new FakeEnvironment() );
		$health = new SiteHealth( static fn(): Report => $report );

		$this->assertArrayHasKey( 'wp_bouncer_php_eol', $health->add_tests( array() )['direct'], 'a failure still shows the test' );
		$this->assertSame( 'recommended', $health->result( 'wp_bouncer_php_eol' )['status'] );
	}

	public function test_a_test_for_a_check_a_host_removed_is_left_out(): void {
		$report = new Report( array( new CheckResult( 'wpb_db_version', CheckResult::GROUP_VERSIONS, Severity::Ok, 'Database version', 'MariaDB 10.11' ) ) );
		$health = new SiteHealth( static fn(): Report => $report );
		$tests  = $health->add_tests( array( 'direct' => array() ) )['direct'];

		$this->assertArrayNotHasKey( 'wp_bouncer_php_eol', $tests, 'PHP check removed on purpose: no test' );
		$this->assertArrayHasKey( 'wp_bouncer_db_eol', $tests );
		$this->assertArrayHasKey( 'wp_bouncer_php_settings', $tests );
		$this->assertSame( 'recommended', $health->result( 'wp_bouncer_php_eol' )['status'], 'asked directly, a missing result is unconfirmed, never good' );
	}

	public function test_removing_the_version_check_with_the_filter_drops_its_site_health_test(): void {
		add_filter(
			'wp_bouncer_environment_checks',
			static fn( $checks ) => array_values( array_filter( $checks, static fn( $c ) => 'wpb_php_version' !== $c->id() ) )
		);
		$admin = new EnvironmentAdmin();
		$admin->register();
		$tests = apply_filters( 'site_status_tests', array( 'direct' => array() ) )['direct'];

		$this->assertArrayNotHasKey( 'wp_bouncer_php_eol', $tests );
		$this->assertArrayHasKey( 'wp_bouncer_db_eol', $tests );
	}

	public function test_the_info_rows_need_the_capability_and_third_party_values_are_private(): void {
		add_filter(
			'wp_bouncer_environment_checks',
			static function ( $checks ) {
				$checks[] = new class() implements CheckInterface {
					public function id(): string {
						return 'acme_value';
					}
					public function run( EnvironmentInterface $env ): CheckResult {
						return new CheckResult( 'acme_value', 'php', Severity::Info, 'Acme', 'internal detail', '', '', false );
					}
				};
				return $checks;
			}
		);
		$admin = new EnvironmentAdmin();
		$admin->register();

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );
		$this->assertArrayNotHasKey( 'wp-bouncer-environment', apply_filters( 'debug_information', array() ), 'rows only for those who may see them' );

		$this->network_admin();
		$fields = apply_filters( 'debug_information', array() )['wp-bouncer-environment']['fields'];
		$this->assertTrue( $fields['acme_value']['private'] );
	}

	public function test_dashboard_only_results_stay_out_of_site_health(): void {
		$report = new Report( array( new CheckResult( 'wpb_debug_display', CheckResult::GROUP_WORDPRESS, Severity::Warning, 'WP_DEBUG_DISPLAY', 'x', '', '', false, true ) ) );
		$this->assertSame( 'good', ( new SiteHealth( static fn(): Report => $report ) )->result( 'wp_bouncer_wp_hardening' )['status'] );
	}

	public function test_the_info_tab_marks_path_like_fields_private(): void {
		$this->network_admin();
		( new EnvironmentAdmin() )->register();
		$info   = apply_filters( 'debug_information', array() );
		$fields = $info['wp-bouncer-environment']['fields'];

		foreach ( array( 'wpb_open_basedir', 'wpb_disable_functions', 'wpb_auto_prepend', 'wpb_error_log_location', 'wpb_debug_log' ) as $id ) {
			$this->assertArrayHasKey( $id, $fields );
			$this->assertTrue( $fields[ $id ]['private'], $id );
		}
		$this->assertFalse( $fields['wpb_php_version']['private'] );
		foreach ( $fields as $field ) {
			$this->assertStringNotContainsString( ABSPATH, (string) $field['value'] );
		}
	}

	/* ---------------- Dashboard section and the gate ---------------- */

	public function test_the_dashboard_section_is_shown_to_those_who_may_manage_the_firewall_only(): void {
		$this->network_admin();
		$shown = $this->html( array( $this->admin(), 'render_dashboard_section' ) );
		$this->assertStringContainsString( 'wpb-environment', $shown );
		$this->assertStringContainsString( 'checks WP Bouncer runs', $shown );
		$this->assertStringNotContainsString( 'is secure', $shown );
		$this->assertStringNotContainsString( 'Secure site', $shown );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );
		$this->assertSame( '', $this->html( array( $this->admin(), 'render_dashboard_section' ) ) );

		wp_set_current_user( 0 );
		$this->assertSame( '', $this->html( array( $this->admin(), 'render_dashboard_section' ) ) );
	}

	public function test_a_multisite_site_admin_sees_nothing(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$this->admin_user();
		$admin = $this->admin( $this->eol_env() );

		$this->assertFalse( $admin->can_view() );
		$this->assertSame( '', $this->html( array( $admin, 'render_dashboard_section' ) ) );
		$this->assertSame( '', $this->html( array( $admin, 'notice' ) ) );
	}

	public function test_the_rendered_section_never_contains_server_paths(): void {
		$this->network_admin();
		$html = $this->html( array( new EnvironmentAdmin(), 'render_dashboard_section' ) );

		$this->assertStringNotContainsString( rtrim( ABSPATH, '/' ), $html );
		$this->assertStringNotContainsString( WP_CONTENT_DIR, $html );
	}

	public function test_rendering_writes_no_options_or_transients(): void {
		global $wpdb;
		$this->network_admin();
		$count  = static fn(): int => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '%wpb\\_%' OR option_name LIKE '%wp\\_bouncer\\_%'" ); // phpcs:ignore WordPress.DB
		$before = $count();

		$this->html( array( new EnvironmentAdmin(), 'render_dashboard_section' ) );
		apply_filters( 'debug_information', array() );

		$this->assertSame( $before, $count() );
	}

	public function test_a_third_party_check_is_escaped_and_cannot_break_the_page(): void {
		$this->network_admin();
		add_filter(
			'wp_bouncer_environment_checks',
			static function ( $checks ) {
				$checks[] = new class() implements CheckInterface {
					public function id(): string {
						return 'acme_evil';
					}
					public function run( EnvironmentInterface $env ): CheckResult {
						return new CheckResult( 'acme_evil', 'php', Severity::Warning, '<script>alert(1)</script>', '<img src=x onerror=alert(2)>', '<script>alert(3)</script><b>why</b>', '<a href="javascript:alert(4)">fix</a>' );
					}
				};
				$checks[] = new class() implements CheckInterface {
					public function id(): string {
						return 'acme_boom';
					}
					public function run( EnvironmentInterface $env ): CheckResult {
						throw new \RuntimeException( ABSPATH );
					}
				};
				return $checks;
			}
		);

		$html = $this->html( array( $this->admin(), 'render_dashboard_section' ) );

		$this->assertStringNotContainsString( '<script>alert', $html );
		$this->assertStringNotContainsString( '<img src=x', $html );
		$this->assertStringContainsString( '&lt;script&gt;alert(1)&lt;/script&gt;', $html );
		$this->assertStringContainsString( '<b>why</b>', $html );
		$this->assertStringNotContainsString( 'javascript:', $html );
		$this->assertStringNotContainsString( rtrim( ABSPATH, '/' ), $html, 'a throwing check leaks nothing' );
	}

	public function test_a_filter_returning_junk_falls_back_to_the_built_ins(): void {
		$this->network_admin();
		add_filter( 'wp_bouncer_environment_checks', static fn() => 'nope' );
		$this->assertGreaterThan( 10, $this->admin()->report()->check_count() );
	}

	public function test_a_host_can_remove_a_built_in_check(): void {
		$this->network_admin();
		add_filter(
			'wp_bouncer_environment_checks',
			static fn( $checks ) => array_values( array_filter( $checks, static fn( $c ) => 'wpb_expose_php' !== $c->id() ) )
		);
		$ids = array_map( static fn( CheckResult $r ) => $r->id, $this->admin()->report()->results() );
		$this->assertNotContains( 'wpb_expose_php', $ids );
		$this->assertContains( 'wpb_php_version', $ids );
	}

	/* ---------------- the notice and the dismissal ---------------- */

	public function test_the_notice_names_the_version_and_only_shows_for_past_end_of_life(): void {
		$this->network_admin();
		$html = $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) );
		$this->assertStringContainsString( 'PHP 8.1 no longer receives security fixes', $html );
		$this->assertStringContainsString( 'site-health.php', $html );
		$this->assertStringContainsString( 'wp_bouncer_env_dismiss', $html );

		$this->assertSame( '', $this->html( array( $this->admin( new FakeEnvironment( php: '8.4.1', db: '8.4.2' ) ), 'notice' ) ) );
		$this->assertSame( '', $this->html( array( $this->admin( new FakeEnvironment( php: '8.2.20', db: '10.11.6-MariaDB' ) ), 'notice' ) ), 'ending soon is not past the end' );
		$this->assertSame( '', $this->html( array( $this->admin( new FakeEnvironment( php: '9.9.9', db: 'garbage' ) ), 'notice' ) ), 'unknown is not a warning' );
	}

	public function test_a_dismissal_dated_in_the_future_does_not_count(): void {
		$uid = $this->network_admin();
		update_user_meta(
			$uid,
			EnvironmentAdmin::DISMISS_META,
			array(
				'at'    => self::NOW + 86400,
				'state' => 'php:8.1',
			)
		);
		$this->assertNotSame( '', $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) ) );
	}

	public function test_the_notice_honours_a_host_removing_the_version_checks(): void {
		$this->network_admin();
		add_filter(
			'wp_bouncer_environment_checks',
			static fn( $checks ) => array_values( array_filter( $checks, static fn( $c ) => 'wpb_php_version' !== $c->id() ) )
		);
		$this->assertSame( '', $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) ) );
	}

	public function test_the_dashboard_reuses_the_registered_instance(): void {
		$admin = new EnvironmentAdmin();
		$admin->register();
		$this->assertSame( $admin, EnvironmentAdmin::shared() );
	}

	public function test_the_notice_is_not_shown_on_the_plugins_own_dashboard_tab(): void {
		$this->network_admin();
		$_GET = array( 'page' => 'wp-bouncer' );
		$this->assertSame( '', $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) ) );
		$_GET = array(
			'page' => 'wp-bouncer',
			'tab'  => 'rules',
		);
		$this->assertNotSame( '', $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) ) );
		$_GET = array();
	}

	public function test_dismiss_needs_the_capability_and_a_nonce(): void {
		$_POST = array();
		$this->admin_user();
		$denied = $this->admin( $this->eol_env() );
		if ( is_multisite() ) {
			$e = $this->die_of( array( $denied, 'handle_dismiss' ) );
			$this->assertSame( 403, $e->getCode() );
		}

		$this->network_admin();
		unset( $_REQUEST['_wpnonce'] );
		$this->die_of( array( $this->admin( $this->eol_env() ), 'handle_dismiss' ) );
		$this->assertSame( '', (string) get_user_meta( get_current_user_id(), EnvironmentAdmin::DISMISS_META, true ) );
	}

	public function test_dismiss_stores_server_time_and_state_and_ignores_the_request(): void {
		$uid                  = $this->network_admin();
		$_REQUEST['_wpnonce'] = wp_create_nonce( EnvironmentAdmin::DISMISS_ACTION );
		$_POST['at']          = '9999999999';
		$_POST['state']       = 'evil';
		$_REQUEST['at']       = '9999999999';

		$this->redirect_of( array( $this->admin( $this->eol_env() ), 'handle_dismiss' ) );

		$meta = get_user_meta( $uid, EnvironmentAdmin::DISMISS_META, true );
		$this->assertSame( self::NOW, $meta['at'] );
		$this->assertSame( 'php:8.1', $meta['state'] );
		$_REQUEST = array();
		$_POST    = array();
	}

	public function test_a_dismissed_notice_stays_hidden_30_days_and_returns_when_the_state_changes(): void {
		$uid = $this->network_admin();
		update_user_meta(
			$uid,
			EnvironmentAdmin::DISMISS_META,
			array(
				'at'    => self::NOW,
				'state' => 'php:8.1',
			)
		);

		$this->assertSame( '', $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) ) );

		$this->clock->advance( 29 * 86400 );
		$this->assertSame( '', $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) ) );

		$this->clock->advance( 2 * 86400 );
		$this->assertNotSame( '', $this->html( array( $this->admin( $this->eol_env() ), 'notice' ) ), 'after 30 days' );

		$this->clock = new FrozenClock( self::NOW );
		$changed     = new FakeEnvironment( php: '8.1.30', db: '10.5.9-MariaDB' );
		$this->assertStringContainsString( 'MariaDB 10.5', $this->html( array( $this->admin( $changed ), 'notice' ) ), 'a new end-of-life state shows it again' );
	}

	public function test_the_notice_hooks_the_network_admin_on_multisite_and_the_site_admin_otherwise(): void {
		$admin = new EnvironmentAdmin();
		$admin->register();
		$hook = is_multisite() ? 'network_admin_notices' : 'admin_notices';
		$this->assertNotFalse( has_action( $hook, array( $admin, 'notice' ) ) );
		$this->assertNotFalse( has_action( 'admin_post_wp_bouncer_env_dismiss', array( $admin, 'handle_dismiss' ) ) );
		$this->assertFalse( has_action( 'admin_post_nopriv_wp_bouncer_env_dismiss' ) );
	}

	public function test_register_adds_the_site_health_filters(): void {
		( new EnvironmentAdmin() )->register();
		$this->assertNotFalse( has_filter( 'site_status_tests' ) );
		$this->assertNotFalse( has_filter( 'debug_information' ) );
	}

	public function test_nothing_is_added_to_rest_or_ajax(): void {
		$routes = rest_get_server()->get_routes();
		foreach ( array_keys( $routes ) as $route ) {
			$this->assertStringNotContainsString( 'environment', (string) $route );
		}
		$this->assertFalse( has_action( 'wp_ajax_wp_bouncer_environment' ) );
	}

	public function test_the_real_environment_reads_without_sql_and_without_error(): void {
		$report = ( new EnvironmentAdmin() )->report();
		$this->assertGreaterThan( 10, $report->check_count() );
		$this->assertInstanceOf( EnvironmentReport::class, new EnvironmentReport( array() ) );
	}
}
