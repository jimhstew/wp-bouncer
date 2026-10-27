<?php
/**
 * WPB-13 on a network: each site records with its own settings, log, budget and history.
 *
 * Needs WP_MULTISITE=1; every test is skipped on a single site.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\AdminLogins;

use WPBouncer\AdminLogins\AdminLoginRecorder;
use WPBouncer\AdminLogins\LoginHistoryRepository;
use WPBouncer\Installer;
use WPBouncer\Plugin;
use WPBouncer\Settings;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Tests\Support\FakeGeo;

/**
 * @covers \WPBouncer\AdminLogins\AdminLoginRecorder
 * @covers \WPBouncer\Plugin::run_on_site
 */
final class AdminLoginMultisiteTest extends IntegrationTestCase {

	private const IP_A = '203.0.113.9';
	private const IP_B = '198.51.100.20';

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$this->use_real_ddl();
		$this->plugin->alerts()->flush();
		$this->clear_mail();
	}

	public function tear_down() {
		remove_all_filters( 'wp_bouncer_admin_login_is_admin' );
		remove_all_actions( 'wp_bouncer_admin_login_recorded' );
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/** A real site with the plugin's tables and its own settings. */
	private function site( array $settings = array(), bool $tables = true, bool $active = true ): int {
		$site = (int) self::factory()->blog->create();
		switch_to_blog( $site );
		if ( $tables ) {
			Installer::activate();
		}
		if ( $active ) {
			update_option( 'active_plugins', array( plugin_basename( $this->plugin->file() ) ) );
		}
		$values = Settings::sanitize( array_replace_recursive( Settings::defaults(), $settings ) );
		$this->without_settings_audit(
			static function () use ( $values ): void {
				update_option( Settings::OPTION, $values, true );
			}
		);
		restore_current_blog();
		return $site;
	}

	private function user_on( array $sites, string $role = 'administrator' ): \WP_User {
		$id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		foreach ( $sites as $site ) {
			add_user_to_blog( $site, $id, $role );
		}
		$this->plugin->alerts()->flush();
		$this->clear_mail();
		return get_user_by( 'id', $id );
	}

	private function request( string $ip, string $uri = '/wp-login.php' ): void {
		$this->fake_request(
			array(
				'REMOTE_ADDR' => $ip,
				'REQUEST_URI' => $uri,
			)
		);
		( new \ReflectionProperty( Plugin::class, 'geo' ) )->setValue( $this->plugin, new FakeGeo( array( $ip => 'DE' ) ) );
	}

	private function login( \WP_User $user, string $ip = self::IP_A ): void {
		$this->request( $ip );
		( new AdminLoginRecorder( $this->plugin ) )->on_wp_login( $user->user_login, $user );
	}

	/** @return array<int, array<string, string>> */
	private function rows_on( int $site ): array {
		global $wpdb;
		switch_to_blog( $site );
		$rows = (array) $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}bouncer_log WHERE rule = 'admin_login' ORDER BY id", ARRAY_A ); // phpcs:ignore WordPress.DB
		restore_current_blog();
		return $rows;
	}

	private function history_on( int $site, \WP_User $user ): mixed {
		switch_to_blog( $site );
		$h = get_user_option( LoginHistoryRepository::META, $user->ID );
		restore_current_blog();
		return $h;
	}

	/** The cached services run_on_site() swaps. @return array<string, mixed> */
	private function services(): array {
		$out = array();
		foreach ( array( 'settings', 'log', 'log_writer', 'write_budget', 'guard', 'resolver', 'client_ip' ) as $name ) {
			$out[ $name ] = ( new \ReflectionProperty( Plugin::class, $name ) )->getValue( $this->plugin );
		}
		return $out;
	}

	private function seed_history( int $site, \WP_User $user, string $range = '203.0.113.0/24' ): void {
		switch_to_blog( $site );
		( new LoginHistoryRepository() )->save(
			$user->ID,
			\WPBouncer\AdminLogins\LocationHistory::from_meta(
				array(
					'since' => time() - 1000,
					'e'     => array(
						array(
							'r' => $range,
							'c' => 'DE',
							't' => time() - 500,
						),
					),
				)
			)
		);
		restore_current_blog();
	}

	/* ---------------- per-site settings (design 3, 4, 9) ---------------- */

	public function test_each_site_follows_its_own_record_setting_and_the_origin_is_restored(): void {
		$off  = $this->site( array( 'alerts' => array( 'record_admin_logins' => false ) ) );
		$on   = $this->site();
		$user = $this->user_on( array( $off, $on ) );
		$this->seed_history( $off, $user );
		$this->seed_history( $on, $user );
		$this->plugin->alerts()->flush();

		$this->request( self::IP_B );
		$this->plugin->client_ip();
		$before = $this->services();
		( new AdminLoginRecorder( $this->plugin ) )->on_wp_login( $user->user_login, $user );

		$this->assertSame( array(), $this->rows_on( $off ), 'recording off on that site: no row' );
		$this->assertCount( 1, $this->history_on( $off, $user )['e'], 'seeded history untouched' );
		$this->assertCount( 1, $this->rows_on( $on ), 'recording on: one row' );
		$this->assertCount( 2, $this->history_on( $on, $user )['e'], 'history saved on the site that records' );
		$this->assertSame( array(), $this->rows_on( 1 ), 'the origin has no admin role for this user' );

		$this->assertSame( 1, get_current_blog_id() );
		$after = $this->services();
		foreach ( $before as $name => $value ) {
			$this->assertSame( $value, $after[ $name ], "$name restored on the origin site" );
		}
	}

	public function test_alerts_follow_each_sites_own_settings(): void {
		$silent = $this->site( array( 'alerts' => array( 'admin_login_location' => false ) ) );
		$loud   = $this->site();
		update_blog_option( $loud, 'admin_email', 'loud@example.org' );
		$user = $this->user_on( array( $silent, $loud ) );
		$this->seed_history( $silent, $user );
		$this->seed_history( $loud, $user );
		$this->plugin->alerts()->flush();
		$this->clear_mail();

		$this->login( $user, self::IP_B );
		$this->assertCount( 1, $this->rows_on( $silent ), 'the row is still written' );
		$this->assertCount( 1, $this->rows_on( $loud ) );
		$this->plugin->alerts()->flush();
		$to = array();
		foreach ( $this->sent_mail() as $mail ) {
			$to[] = $mail['to'][0][0];
		}
		$this->assertSame( array( 'loud@example.org' ), $to, 'one alert, to the site that has them on' );
	}

	public function test_a_different_ip_source_on_another_site_does_not_change_what_is_recorded(): void {
		$proxy = $this->site(
			array(
				'ip_source'       => 'x_forwarded_for',
				'trusted_proxies' => array( '192.0.2.1' ),
			)
		);
		$plain = $this->site();
		$user  = $this->user_on( array( $proxy, $plain ) );

		$this->login( $user, self::IP_A );
		// The client is resolved once, on the site where the login happened.
		$this->assertSame( self::IP_A, $this->rows_on( $proxy )[0]['ip'] );
		$this->assertSame( self::IP_A, $this->rows_on( $plain )[0]['ip'] );
		$this->assertStringContainsString( 'first recorded login', $this->rows_on( $proxy )[0]['reason'] );
		$this->assertSame( 'remote_addr', $this->plugin->settings()->get( 'ip_source' ), 'origin settings untouched' );
		$this->assertSame( array(), $this->plugin->settings()->get( 'trusted_proxies' ) );
	}

	public function test_the_origin_is_restored_when_a_recording_on_another_site_throws(): void {
		$one  = $this->site();
		$two  = $this->site();
		$user = $this->user_on( array( $one, $two ) );
		$this->request( self::IP_A );
		$this->plugin->client_ip();
		$before = $this->services();

		add_action(
			'wp_bouncer_admin_login_recorded',
			static function () {
				throw new \RuntimeException( 'listener failed' );
			}
		);
		( new AdminLoginRecorder( $this->plugin ) )->on_wp_login( $user->user_login, $user );

		$this->assertSame( 1, get_current_blog_id(), 'back on the origin site' );
		$after = $this->services();
		foreach ( $before as $name => $value ) {
			$this->assertSame( $value, $after[ $name ], "$name restored after a throw" );
		}
		// The row for the site that threw was written before the listener ran.
		$this->assertCount( 1, $this->rows_on( $one ) );
	}

	public function test_run_on_site_restores_everything_when_the_callback_throws(): void {
		$one = $this->site( array( 'mode' => 'monitor' ) );
		$this->request( self::IP_A );
		$this->plugin->log_writer();
		$this->plugin->write_budget();
		$before = $this->services();
		$seen   = null;
		try {
			$this->plugin->run_on_site(
				$one,
				function () use ( &$seen, $one ): void {
					$seen = array( get_current_blog_id(), $this->plugin->settings()->get( 'mode' ) );
					throw new \LogicException( 'boom' );
				}
			);
			$this->fail( 'The exception must propagate.' );
		} catch ( \LogicException $e ) {
			$this->assertSame( 'boom', $e->getMessage() );
		}
		$this->assertSame( array( $one, 'monitor' ), $seen, 'ran as the other site' );
		$this->assertSame( 1, get_current_blog_id() );
		foreach ( $before as $name => $value ) {
			$this->assertSame( $value, $this->services()[ $name ], "$name restored" );
		}
	}

	public function test_a_user_who_is_admin_on_several_sites_gets_one_row_per_site_and_history_per_site(): void {
		$two   = $this->site();
		$three = $this->site();
		$user  = $this->user_on( array( 1, $two, $three ) );

		$rec = new AdminLoginRecorder( $this->plugin );
		$this->request( self::IP_A );
		$rec->on_wp_login( $user->user_login, $user );
		foreach ( array( 1, $two, $three ) as $site ) {
			$this->assertCount( 1, $this->rows_on( $site ), "site $site: one row" );
			$this->assertIsArray( $this->history_on( $site, $user ), "site $site: own history" );
		}
		// The same request again records nothing more (one login per user and request).
		$rec->on_wp_login( $user->user_login, $user );
		$this->assertCount( 1, $this->rows_on( $two ) );
	}

	public function test_archived_spam_and_deleted_sites_are_skipped(): void {
		$ok       = $this->site();
		$archived = $this->site();
		$spam     = $this->site();
		$user     = $this->user_on( array( $ok, $archived, $spam ) );
		update_blog_status( $archived, 'archived', 1 );
		update_blog_status( $spam, 'spam', 1 );

		$this->login( $user );
		$this->assertCount( 1, $this->rows_on( $ok ) );
		$this->assertSame( array(), $this->rows_on( $archived ) );
		$this->assertSame( array(), $this->rows_on( $spam ) );
	}

	/* ---------------- REST application password ---------------- */

	public function test_a_rest_application_password_login_records_once_on_every_admin_site_without_recursion(): void {
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
		$two   = $this->site();
		$three = $this->site();
		$user  = $this->user_on( array( 1, $two, $three ) );

		$created = \WP_Application_Passwords::create_new_application_password( $user->ID, array( 'name' => 'ci' ) );
		$this->request( self::IP_A, '/wp-json/wp/v2/posts' );

		$checks = 0;
		add_filter(
			'wp_bouncer_admin_login_is_admin',
			static function ( $is ) use ( &$checks ) {
				++$checks;
				return $is;
			}
		);
		$fired = 0;
		add_action(
			'wp_bouncer_admin_login_recorded',
			static function () use ( &$fired ) {
				++$fired;
			}
		);
		$result = wp_authenticate_application_password( null, $user->user_login, $created[0] );

		$this->assertInstanceOf( \WP_User::class, $result, 'the request authenticates' );
		$this->assertSame( 3, $checks, 'one admin check per site: no recursion' );
		$this->assertSame( 3, $fired );
		foreach ( array( 1, $two, $three ) as $site ) {
			$rows = $this->rows_on( $site );
			$this->assertCount( 1, $rows, "site $site: one row" );
			$this->assertStringContainsString( 'application password (REST)', $rows[0]['reason'] );
		}
		$this->assertSame( 1, get_current_blog_id() );
	}

	/* ---------------- the cap ---------------- */

	/**
	 * Uses 101 real sites (real, with the plugin's tables; creating them takes about a second in all);
	 * counts how often a recording ran, and on which site first.
	 */
	public function test_a_user_is_recorded_on_at_most_100_sites_origin_first(): void {
		$sites = array();
		for ( $i = 0; $i < 101; $i++ ) {
			$sites[] = $this->site();
		}
		$user = $this->user_on( array_merge( array( 1 ), $sites ) );

		$order = array();
		add_action(
			'wp_bouncer_admin_login_recorded',
			static function () use ( &$order ) {
				$order[] = get_current_blog_id();
			}
		);
		$this->login( $user );

		$this->assertCount( AdminLoginRecorder::MAX_SITES, $order );
		$this->assertSame( 1, $order[0], 'the origin site comes first' );
		$this->assertSame( count( $order ), count( array_unique( $order ) ), 'no site twice' );
		$this->assertSame( 1, get_current_blog_id() );
	}

	/* ---------------- Two Factor ---------------- */

	public function test_two_factor_defers_on_every_site_and_records_once_after_the_second_factor(): void {
		require_once dirname( __DIR__, 2 ) . '/Support/Two_Factor_Core.php';
		$two  = $this->site();
		$user = $this->user_on( array( 1, $two ) );
		\Two_Factor_Core::$users[] = $user->ID;
		add_action( 'wp_login', array( 'Two_Factor_Core', 'wp_login' ), 30, 2 );
		try {
			$this->login( $user );
			$this->assertSame( array(), $this->rows_on( 1 ), 'password step: nothing' );
			$this->assertSame( array(), $this->rows_on( $two ) );
			$this->assertFalse( $this->history_on( $two, $user ) );

			$this->request( self::IP_A );
			do_action( 'two_factor_user_authenticated', $user );
			do_action( 'wp_bouncer_record_admin_login', $user );
			$this->assertCount( 1, $this->rows_on( 1 ), 'recorded once, not twice' );
			$this->assertCount( 1, $this->rows_on( $two ) );
		} finally {
			remove_action( 'wp_login', array( 'Two_Factor_Core', 'wp_login' ), 30 );
			\Two_Factor_Core::$users = array();
		}
	}

	/* ---------------- round 3 ---------------- */

	/** @return int Number of switch_to_blog() calls while $fn runs. */
	private function count_switches( callable $fn ): int {
		$n  = 0;
		$cb = static function () use ( &$n ): void {
			++$n;
		};
		add_action( 'switch_blog', $cb );
		try {
			$fn();
		} finally {
			remove_action( 'switch_blog', $cb );
		}
		return $n;
	}

	private function app_login( \WP_User $user, string $ip = self::IP_A ): void {
		$this->request( $ip, '/wp-json/wp/v2/posts' );
		( new AdminLoginRecorder( $this->plugin ) )->on_application_password( $user, array() );
	}

	/** RT-08. */
	public function test_a_site_without_the_plugin_gets_no_history_row_or_mail(): void {
		$with    = $this->site();
		$without = $this->site( array(), true, false );
		$nodata  = $this->site();
		update_blog_option( $without, 'active_plugins', array() );
		switch_to_blog( $nodata );
		delete_option( Settings::OPTION );
		restore_current_blog();
		update_blog_option( $with, 'admin_email', 'with@example.org' );
		$user = $this->user_on( array( $with, $without, $nodata ) );
		$this->seed_history( $with, $user );
		$this->seed_history( $without, $user );
		$this->seed_history( $nodata, $user );
		$this->plugin->alerts()->flush();
		$this->clear_mail();

		$this->login( $user, self::IP_B );
		$this->assertCount( 1, $this->rows_on( $with ) );
		$this->assertSame( array(), $this->rows_on( $without ), 'plugin not active there: no row' );
		$this->assertCount( 1, $this->history_on( $without, $user )['e'], 'no history written' );
		$this->assertSame( array(), $this->rows_on( $nodata ), 'no saved settings: no row' );
		$this->plugin->alerts()->flush();
		$this->assertCount( 1, $this->sent_mail(), 'one mail, for the site that runs the plugin' );
	}

	/** RT-08: network activation counts. */
	public function test_a_network_active_plugin_counts_on_every_site_with_saved_settings(): void {
		$other = $this->site( array(), true, false );
		$user  = $this->user_on( array( $other ) );
		update_site_option( 'active_sitewide_plugins', array( plugin_basename( $this->plugin->file() ) => time() ) );
		try {
			$this->login( $user );
		} finally {
			delete_site_option( 'active_sitewide_plugins' );
		}
		$this->assertCount( 1, $this->rows_on( $other ) );
	}

	/** RT-10. */
	public function test_an_app_password_request_by_a_subscriber_switches_no_site(): void {
		$sites = array( $this->site(), $this->site(), $this->site() );
		$user  = $this->user_on( $sites, 'subscriber' );
		$this->assertSame( 0, $this->count_switches( fn() => $this->app_login( $user ) ) );
		foreach ( $sites as $site ) {
			$this->assertSame( array(), $this->rows_on( $site ) );
		}
	}

	/** RT-10, CR2-6. */
	public function test_a_repeated_admin_api_request_within_the_hour_switches_no_site(): void {
		$two  = $this->site();
		$user = $this->user_on( array( $two ) );
		$this->assertGreaterThan( 0, $this->count_switches( fn() => $this->app_login( $user ) ) );
		$this->assertCount( 1, $this->rows_on( $two ) );
		$this->assertSame( 0, $this->count_switches( fn() => $this->app_login( $user ) ), 'network-wide dedupe before any site is touched' );
		$this->assertCount( 1, $this->rows_on( $two ) );
	}

	/** RT-16: a deduped XML-RPC app-password call adds no "password (XML-RPC)" row on a network. */
	public function test_a_deduped_xmlrpc_app_password_call_adds_no_password_row_on_a_network(): void {
		$two  = $this->site();
		$user = $this->user_on( array( 1, $two ) );
		foreach ( array( 1, 2 ) as $call ) {
			$this->request( self::IP_A, '/xmlrpc.php' );
			$rec = new AdminLoginRecorder( $this->plugin );
			$rec->on_application_password( $user, array() );
			$rec->note_xmlrpc_authentication( $user );
			wp_set_current_user( $user->ID );
			$rec->flush_pending();
			$rec->on_xmlrpc_call();
			$this->assertCount( 1, $this->rows_on( 1 ), "call $call, site 1" );
			$this->assertCount( 1, $this->rows_on( $two ), "call $call, site 2" );
		}
	}

	/** RT-17: a site granted within the hour is not hidden by the earlier network-wide dedupe key. */
	public function test_a_newly_granted_site_is_recorded_within_the_hour(): void {
		$two  = $this->site();
		$user = $this->user_on( array( 1 ) );
		wp_set_current_user( $user->ID );
		$this->app_login( $user );
		$this->assertCount( 1, $this->rows_on( 1 ) );
		add_user_to_blog( $two, $user->ID, 'administrator' );
		$user = get_user_by( 'id', $user->ID );
		$this->plugin->run_on_site( $two, fn() => $this->app_login( $user ) );
		$this->assertCount( 1, $this->rows_on( $two ), 'site 2 is recorded' );
		$this->assertSame( 0, $this->count_switches( fn() => $this->app_login( $user ) ), 'a repeat with an unchanged site set switches nothing' );
	}

	/** RT-14: a super admin is recorded only on the origin site, so the dedupe key names it. */
	public function test_a_super_admin_api_login_on_one_site_does_not_suppress_another_site(): void {
		$two  = $this->site();
		$user = $this->user_on( array() );
		grant_super_admin( $user->ID );
		$this->plugin->run_on_site( $two, fn() => $this->app_login( $user ) );
		$this->assertCount( 1, $this->rows_on( $two ) );
		$this->assertSame( array(), $this->rows_on( 1 ) );

		$this->app_login( $user );
		$this->assertCount( 1, $this->rows_on( 1 ), 'site 1 is recorded' );
		$this->assertNotFalse( $this->history_on( 1, $user ), 'site 1 history assessed' );
		$this->assertSame( 0, $this->count_switches( fn() => $this->app_login( $user ) ), 'a repeat on the same site is still deduped' );
		revoke_super_admin( $user->ID );
	}

	/** RT-15, CR3-1: a queued login is recorded at rest_pre_dispatch, with no shutdown, and not twice. */
	public function test_a_queued_login_is_recorded_when_rest_pre_dispatch_fires_without_shutdown(): void {
		$two  = $this->site();
		$user = $this->user_on( array( 1, $two ) );
		$this->request( self::IP_A, '/wp-json/wp/v2/posts' );
		$rec = new AdminLoginRecorder( $this->plugin );
		add_filter( 'rest_pre_dispatch', array( $rec, 'flush_pending_filter' ), 0, 1 );
		$queue = static fn() => $rec->on_application_password( $user, array() ) ?? false;
		add_filter( 'determine_current_user', $queue, 5 );
		apply_filters( 'determine_current_user', false );
		remove_filter( 'determine_current_user', $queue, 5 );
		$this->assertSame( array(), $this->rows_on( $two ), 'queued, not recorded yet' );

		$this->assertSame( 'x', apply_filters( 'rest_pre_dispatch', 'x', null, null ) );
		remove_filter( 'rest_pre_dispatch', array( $rec, 'flush_pending_filter' ), 0 );
		$this->assertCount( 1, $this->rows_on( 1 ) );
		$this->assertCount( 1, $this->rows_on( $two ) );
		$rec->flush_pending();
		$this->assertCount( 1, $this->rows_on( $two ), 'idempotent' );
	}

	/** RT-10: the main site's key (wp_capabilities and wp_1_capabilities) is not visited twice. */
	public function test_a_site_listed_twice_in_the_meta_is_recorded_once(): void {
		$two  = $this->site();
		$user = $this->user_on( array( 1, $two ) );
		global $wpdb;
		update_user_meta( $user->ID, $wpdb->base_prefix . '1_capabilities', array( 'administrator' => true ) );
		update_user_meta( $user->ID, $wpdb->base_prefix . 'capabilities', array( 'administrator' => true ) );
		$order = array();
		add_action(
			'wp_bouncer_admin_login_recorded',
			static function () use ( &$order ) {
				$order[] = get_current_blog_id();
			}
		);
		$this->login( $user );
		$this->assertSame( array( 1, $two ), $order );
	}

	/** CR2-6: a failed recording must not suppress the retry. */
	public function test_a_failed_recording_does_not_set_the_dedupe_key(): void {
		$two  = $this->site();
		$user = $this->user_on( array( $two ) );
		add_action(
			'wp_bouncer_admin_login_recorded',
			static function () {
				throw new \RuntimeException( 'listener failed' );
			}
		);
		$this->app_login( $user );
		remove_all_actions( 'wp_bouncer_admin_login_recorded' );
		$this->app_login( $user );
		$this->assertCount( 2, $this->rows_on( $two ), 'the second request was not deduplicated' );
	}

	/** CR2-3. */
	public function test_one_sites_failure_does_not_skip_the_others(): void {
		$one   = $this->site();
		$two   = $this->site();
		$user  = $this->user_on( array( $one, $two ) );
		$calls = 0;
		add_action(
			'wp_bouncer_admin_login_recorded',
			static function () use ( &$calls ) {
				if ( 1 === ++$calls ) {
					throw new \RuntimeException( 'first site failed' );
				}
			}
		);
		$this->login( $user );
		$this->assertCount( 1, $this->rows_on( $one ) );
		$this->assertCount( 1, $this->rows_on( $two ), 'the next site still recorded' );
		$this->assertSame( 1, get_current_blog_id() );
	}

	/** RT-13. */
	public function test_a_rest_application_password_login_is_recorded_after_authentication_not_during_it(): void {
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
		$two     = $this->site();
		$user    = $this->user_on( array( 1, $two ) );
		$created = \WP_Application_Passwords::create_new_application_password( $user->ID, array( 'name' => 'ci' ) );
		$this->request( self::IP_A, '/wp-json/wp/v2/posts' );

		$fired = 0;
		add_action(
			'application_password_did_authenticate',
			static function () use ( &$fired ) {
				++$fired;
			},
			5
		);
		add_filter(
			'determine_current_user',
			static fn() => wp_authenticate_application_password( null, $user->user_login, $created[0] )->ID,
			5
		);
		$switches = $this->count_switches( fn() => apply_filters( 'determine_current_user', false ) );
		$this->assertSame( 0, $switches, 'no site switch during determine_current_user' );
		$this->assertSame( 1, $fired );
		$this->assertSame( array(), $this->rows_on( $two ), 'nothing recorded yet' );

		$this->run_shutdown_recorder();
		$this->assertCount( 1, $this->rows_on( 1 ) );
		$this->assertCount( 1, $this->rows_on( $two ) );
		remove_all_filters( 'determine_current_user' );
	}

	/** Call the plugin's own AdminLoginRecorder shutdown callback (not the whole shutdown action). */
	private function run_shutdown_recorder(): void {
		global $wp_filter;
		foreach ( $wp_filter['shutdown']->callbacks[0] ?? array() as $cb ) {
			if ( is_array( $cb['function'] ) && $cb['function'][0] instanceof AdminLoginRecorder ) {
				$cb['function'][0]->flush_pending();
			}
		}
	}

	/** RT-11. */
	public function test_the_fallback_alert_row_goes_to_the_log_of_the_site_it_is_about(): void {
		$two  = $this->site();
		$user = $this->user_on( array( $two ) );
		$this->seed_history( $two, $user );
		$this->plugin->alerts()->flush();
		$this->clear_mail();

		// The login row of site 2 was dropped by its write budget: the event says it was not logged.
		$this->request( self::IP_B );
		$event = new \WPBouncer\AdminLogins\LoginEvent( $user->ID, $user->user_login, self::IP_B, '198.51.100.0/24', 'DE', \WPBouncer\AdminLogins\LoginEvent::METHOD_INTERACTIVE, time() );
		$a     = ( new \WPBouncer\AdminLogins\LoginLocationPolicy( 90 * DAY_IN_SECONDS ) )->assess( \WPBouncer\AdminLogins\LocationHistory::from_meta( array( 'since' => time() - 1000, 'e' => array( array( 'r' => '203.0.113.0/24', 'c' => 'DE', 't' => time() - 500 ) ) ) ), '198.51.100.0/24', 'DE', time() );
		$this->plugin->run_on_site( $two, fn() => $this->plugin->alerts()->on_admin_login( $event, $a, false ) );
		$this->plugin->alerts()->flush();

		global $wpdb;
		$count = static function ( int $site ) use ( $wpdb ): int {
			switch_to_blog( $site );
			$n = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log WHERE rule = 'alerts' AND reason LIKE '%Administrator login from a new location%'" ); // phpcs:ignore WordPress.DB
			restore_current_blog();
			return $n;
		};
		$this->assertSame( 1, $count( $two ), 'in the log of site 2' );
		$this->assertSame( 0, $count( 1 ), 'not in the log of the site that was current' );
	}

	/** RT-12. */
	public function test_removing_and_re_adding_an_admin_does_not_restart_a_silent_history(): void {
		$two  = $this->site();
		update_blog_option( $two, 'admin_email', 'two@example.org' );
		$user = $this->user_on( array( $two ) );
		$this->login( $user );
		$this->assertIsArray( $this->history_on( $two, $user ) );

		remove_user_from_blog( $user->ID, $two );
		add_user_to_blog( $two, $user->ID, 'administrator' );
		$this->assertSame( array(), $this->history_on( $two, $user )['e'] ?? null, 'a tombstone, not "never recorded"' );
		$this->plugin->alerts()->flush();
		$this->clear_mail();

		$this->login( get_user_by( 'id', $user->ID ) );
		$this->plugin->alerts()->flush();
		$this->assertCount( 1, $this->sent_mail(), 'same range again after re-adding: alert' );
	}

	/** RT-12: a network delete removes the history. */
	public function test_a_network_delete_removes_the_history_but_a_site_delete_keeps_a_tombstone(): void {
		$two  = $this->site();
		$user = $this->user_on( array( $two ) );
		$this->login( $user );
		switch_to_blog( $two );
		do_action( 'delete_user', $user->ID );
		$kept = get_user_option( LoginHistoryRepository::META, $user->ID );
		restore_current_blog();
		$this->assertIsArray( $kept );
		$this->assertSame( array(), $kept['e'] );
		switch_to_blog( $two );
		do_action( 'wpmu_delete_user', $user->ID );
		restore_current_blog();
		$this->assertFalse( $this->history_on( $two, $user ) );
	}
}
