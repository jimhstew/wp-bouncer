<?php
/**
 * WPB-13 personal-data exporter, eraser, policy text, history pruning and uninstall.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\AdminLogins;

use WPBouncer\AdminLogins\LocationHistory;
use WPBouncer\AdminLogins\LoginHistoryRepository;
use WPBouncer\Privacy\AdminLoginPrivacy;
use WPBouncer\Privacy\PrivacyTools;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Privacy\AdminLoginPrivacy
 * @covers \WPBouncer\AdminLogins\LoginHistoryRepository
 * @covers \WPBouncer\Privacy\PrivacyTools::policy_html
 */
final class AdminLoginPrivacyTest extends IntegrationTestCase {

	/** @var int A user whose ID starts with the other user's ID (1 and 12). */
	private const OTHER_ID = 12;

	private string $email_1  = '';
	private string $email_12 = '';

	public function set_up() {
		parent::set_up();
		global $wpdb;
		$this->assertFalse( get_userdata( self::OTHER_ID ), 'fixture: user 12 must not exist yet' );
		$wpdb->insert( // phpcs:ignore WordPress.DB
			$wpdb->users,
			array(
				'ID'                  => self::OTHER_ID,
				'user_login'          => 'twelve',
				'user_pass'           => 'x',
				'user_nicename'       => 'twelve',
				'user_email'          => 'twelve@example.org',
				'user_registered'     => '2026-01-01 00:00:00',
				'user_activation_key' => '',
				'display_name'        => 'Twelve',
			)
		);
		clean_user_cache( self::OTHER_ID );
		( new \WP_User( self::OTHER_ID ) )->set_role( 'administrator' );
		$this->email_1  = (string) get_userdata( 1 )->user_email;
		$this->email_12 = 'twelve@example.org';
		$this->assertSame( self::OTHER_ID, (int) get_user_by( 'email', $this->email_12 )->ID );
	}

	private function row( int $user, string $rule = 'admin_login', string $action = 'login', string $reason = '', int $n = 1 ): void {
		global $wpdb;
		for ( $i = 0; $i < $n; $i++ ) {
			$wpdb->insert( // phpcs:ignore WordPress.DB
				$wpdb->prefix . 'bouncer_log',
				array(
					'created_at' => gmdate( 'Y-m-d H:i:s' ),
					'ip'         => '203.0.113.9',
					'country'    => 'DE',
					'rule'       => $rule,
					'action'     => $action,
					'reason'     => '' !== $reason ? $reason : 'User ID ' . $user . ': u — interactive password',
					'method'     => 'POST',
					'uri'        => '/wp-login.php',
					'user_agent' => 'UA',
				)
			);
		}
	}

	/** @return string[] reasons of every remaining row. */
	private function remaining(): array {
		global $wpdb;
		return array_map( 'strval', (array) $wpdb->get_col( "SELECT reason FROM {$wpdb->prefix}bouncer_log ORDER BY id" ) ); // phpcs:ignore WordPress.DB
	}

	private function history( int $user ): void {
		( new LoginHistoryRepository() )->save( $user, LocationHistory::start( time() - 1000 )->with_login( '203.0.113.0/24', 'DE', time() - 500, 90 * DAY_IN_SECONDS, 20 ) );
	}

	/* ---------------- registration ---------------- */

	public function test_the_exporter_and_eraser_are_registered_with_core(): void {
		$exporters = apply_filters( 'wp_privacy_personal_data_exporters', array() );
		$erasers   = apply_filters( 'wp_privacy_personal_data_erasers', array() );
		$this->assertArrayHasKey( AdminLoginPrivacy::ID, $exporters );
		$this->assertArrayHasKey( AdminLoginPrivacy::ID, $erasers );
		$this->assertSame( 'Site security: administrator logins', $exporters[ AdminLoginPrivacy::ID ]['exporter_friendly_name'] );
		$this->assertIsCallable( $exporters[ AdminLoginPrivacy::ID ]['callback'] );
		$this->assertIsCallable( $erasers[ AdminLoginPrivacy::ID ]['callback'] );
	}

	/* ---------------- eraser ---------------- */

	public function test_the_eraser_matches_user_id_12_but_not_1_or_120(): void {
		$this->row( 1, 'admin_login', 'login', '', 2 );
		$this->row( self::OTHER_ID, 'admin_login', 'login', '', 3 );
		$this->row( 120 );
		$this->row( 112 );
		$this->history( 1 );
		$this->history( self::OTHER_ID );

		$result = ( new AdminLoginPrivacy() )->erase( $this->email_12, 1 );

		$this->assertSame( 3, $result['items_removed'] );
		$this->assertTrue( $result['done'] );
		$this->assertFalse( $result['items_retained'] );
		$reasons = $this->remaining();
		$this->assertCount( 4, $reasons );
		foreach ( $reasons as $r ) {
			$this->assertStringStartsNotWith( 'User ID 12:', $r );
		}
		$tomb = get_user_option( LoginHistoryRepository::META, self::OTHER_ID );
		$this->assertSame( array(), $tomb['e'], 'history erased: a tombstone with no ranges, not "never recorded"' );
		$this->assertGreaterThan( 0, $tomb['since'] );
		$this->assertIsArray( get_user_option( LoginHistoryRepository::META, 1 ), 'the other history stays' );
	}

	public function test_erasing_user_1_leaves_user_12s_rows(): void {
		$this->row( 1, 'admin_login', 'login', '', 2 );
		$this->row( self::OTHER_ID, 'admin_login', 'login', '', 2 );
		$result = ( new AdminLoginPrivacy() )->erase( $this->email_1, 1 );
		$this->assertSame( 2, $result['items_removed'] );
		$this->assertSame( array( 'User ID 12: u — interactive password', 'User ID 12: u — interactive password' ), $this->remaining() );
	}

	public function test_the_eraser_never_touches_other_rules_or_actions(): void {
		$this->row( self::OTHER_ID, 'alerts', 'alert' );
		$this->row( self::OTHER_ID, 'waf', 'blocked' );
		$this->row( self::OTHER_ID, 'admin_login', 'blocked' );
		$this->row( self::OTHER_ID, 'admin_login', 'login', 'a note: User ID 12: not at position zero' );
		$this->row( self::OTHER_ID, 'admin_login', 'login', 'User ID 5: User ID 12: forged by a login name' );
		$result = ( new AdminLoginPrivacy() )->erase( $this->email_12, 1 );
		$this->assertSame( 0, $result['items_removed'] );
		$this->assertCount( 5, $this->remaining() );
	}

	public function test_the_eraser_pages_by_500(): void {
		$this->row( self::OTHER_ID, 'admin_login', 'login', '', 501 );
		$privacy = new AdminLoginPrivacy();
		$first   = $privacy->erase( $this->email_12, 1 );
		$this->assertSame( 500, $first['items_removed'] );
		$this->assertFalse( $first['done'] );
		$second = $privacy->erase( $this->email_12, 2 );
		$this->assertSame( 1, $second['items_removed'] );
		$this->assertTrue( $second['done'] );
		$this->assertSame( array(), $this->remaining() );
	}

	public function test_an_unknown_email_removes_nothing_and_is_done(): void {
		$this->row( 1 );
		$result = ( new AdminLoginPrivacy() )->erase( 'nobody@example.org', 1 );
		$this->assertSame( 0, $result['items_removed'] );
		$this->assertTrue( $result['done'] );
		$this->assertCount( 1, $this->remaining() );
	}

	public function test_a_like_wildcard_in_the_id_cannot_widen_the_match(): void {
		$this->row( 1 );
		$this->row( self::OTHER_ID, 'admin_login', 'login', 'User ID %: wildcard' );
		( new AdminLoginPrivacy() )->erase( $this->email_12, 1 );
		$this->assertCount( 2, $this->remaining() );
	}

	/* ---------------- exporter ---------------- */

	public function test_the_exporter_lists_history_and_only_this_users_rows(): void {
		$this->row( 1, 'admin_login', 'login', '', 2 );
		$this->row( self::OTHER_ID, 'admin_login', 'login', 'User ID 12: twelve — application password (REST) — new location: IP range 1.2.3.0/24' );
		$this->row( 120 );
		$this->history( self::OTHER_ID );

		$out = ( new AdminLoginPrivacy() )->export( $this->email_12, 1 );

		$this->assertTrue( $out['done'] );
		$this->assertCount( 3, $out['data'], 'since + 1 range + 1 row' );
		$names = array();
		foreach ( $out['data'] as $item ) {
			foreach ( $item['data'] as $d ) {
				$names[ $d['name'] ] = $d['value'];
			}
		}
		$this->assertSame( '203.0.113.0/24', $names['IP range'] );
		$this->assertSame( 'application password (REST)', $names['Login method'] );
		$this->assertSame( '203.0.113.9', $names['IP address'] );
		$this->assertSame( 'UA', $names['Browser (User-Agent)'] );
		$this->assertArrayHasKey( 'Login history kept since (UTC)', $names );
	}

	public function test_the_exporter_pages_by_500_and_history_is_on_page_one_only(): void {
		$this->row( self::OTHER_ID, 'admin_login', 'login', '', 501 );
		$this->history( self::OTHER_ID );
		$privacy = new AdminLoginPrivacy();
		$p1      = $privacy->export( $this->email_12, 1 );
		$this->assertFalse( $p1['done'] );
		$this->assertCount( 502, $p1['data'], '500 rows + since + 1 range' );
		$p2 = $privacy->export( $this->email_12, 2 );
		$this->assertTrue( $p2['done'] );
		$this->assertCount( 1, $p2['data'] );
		$ids = array_merge( array_column( $p1['data'], 'item_id' ), array_column( $p2['data'], 'item_id' ) );
		$this->assertSame( count( $ids ), count( array_unique( $ids ) ), 'no row is exported twice' );
	}

	public function test_the_exporter_for_an_unknown_email_is_empty_and_done(): void {
		$out = ( new AdminLoginPrivacy() )->export( 'nobody@example.org', 1 );
		$this->assertSame( array(), $out['data'] );
		$this->assertTrue( $out['done'] );
	}

	public function test_a_user_with_no_data_exports_nothing(): void {
		$out = ( new AdminLoginPrivacy() )->export( $this->email_12, 1 );
		$this->assertSame( array(), $out['data'] );
		$this->assertTrue( $out['done'] );
	}

	/** @dataProvider reasons */
	public function test_method_from_reason( string $reason, string $method ): void {
		$this->assertSame( $method, AdminLoginPrivacy::method_from_reason( $reason ) );
	}

	public static function reasons(): array {
		return array(
			array( 'User ID 1: a — interactive password', 'interactive password' ),
			array( 'User ID 1: a — interactive password + two-factor — new location', 'interactive password + two-factor' ),
			array( 'User ID 1: a — application password (XML-RPC)', 'application password (XML-RPC)' ),
			array( 'User ID 1: a — password (XML-RPC) — x', 'password (XML-RPC)' ),
			array( 'User ID 1: a', '' ),
		);
	}

	/* ---------------- policy text ---------------- */

	public function test_policy_text_and_settings_screen_use_the_history_window_not_a_fixed_90(): void {
		$tools = new PrivacyTools( $this->plugin );
		$this->set_settings( array( 'alerts' => array( 'record_admin_logins' => true ), 'log_retention_days' => 45 ) );
		add_filter( 'wp_bouncer_admin_login_window_days', static fn() => 120 );
		$html = $tools->policy_html();
		remove_all_filters( 'wp_bouncer_admin_login_window_days' );
		$this->assertStringContainsString( 'kept for 45 days', $html );
		$this->assertStringContainsString( 'used in the last 120 days', $html );
		$this->assertStringNotContainsString( '90 days', $html );
	}

	public function test_policy_text_mentions_admin_logins_only_when_recording_is_on(): void {
		$tools = new PrivacyTools( $this->plugin );
		$this->set_settings( array( 'alerts' => array( 'record_admin_logins' => true ), 'log_retention_days' => 30 ) );
		$on = $tools->policy_html();
		$this->assertStringContainsString( 'When an administrator logs in, we record', $on );
		$this->assertStringContainsString( 'kept for 30 days', $on );
		$this->assertStringContainsString( '90 days', $on );
		$this->set_settings( array( 'alerts' => array( 'record_admin_logins' => false ) ) );
		$this->assertStringNotContainsString( 'When an administrator logs in', $tools->policy_html() );
	}

	/* ---------------- pruning the histories (SB13-15) ---------------- */

	private function expired_history( int $user ): void {
		$h = array(
			'since' => time() - 200 * DAY_IN_SECONDS,
			'e'     => array( array( 'r' => '203.0.113.0/24', 'c' => 'DE', 't' => time() - 100 * DAY_IN_SECONDS ) ),
		);
		update_user_option( $user, LoginHistoryRepository::META, $h );
	}

	public function test_prune_removes_expired_entries_keeps_since_and_leaves_fresh_ones(): void {
		$this->expired_history( 1 );
		$this->history( self::OTHER_ID );
		( new LoginHistoryRepository() )->prune_expired( 90 * DAY_IN_SECONDS );
		$one = get_user_option( LoginHistoryRepository::META, 1 );
		$this->assertSame( array(), $one['e'] );
		$this->assertGreaterThan( 0, $one['since'] );
		$this->assertCount( 1, get_user_option( LoginHistoryRepository::META, self::OTHER_ID )['e'] );
		$this->assertSame( 0, (int) get_option( LoginHistoryRepository::CURSOR_OPTION ) );
	}

	public function test_prune_resumes_from_its_cursor_in_batches(): void {
		// 1 and 12, plus 10 more administrators: 12 histories, batch 2 x 5 batches = 10 per run.
		$ids = array( 1, self::OTHER_ID );
		for ( $i = 0; $i < 10; $i++ ) {
			$ids[] = self::factory()->user->create( array( 'role' => 'administrator' ) );
		}
		foreach ( $ids as $id ) {
			$this->expired_history( $id );
		}
		$repo = new LoginHistoryRepository();

		$repo->prune_expired( 90 * DAY_IN_SECONDS, 2 );
		$cursor = (int) get_option( LoginHistoryRepository::CURSOR_OPTION );
		$this->assertGreaterThan( 0, $cursor, 'the run stopped early and kept a cursor' );
		$done = 0;
		foreach ( $ids as $id ) {
			$done += array() === get_user_option( LoginHistoryRepository::META, $id )['e'] ? 1 : 0;
		}
		$this->assertSame( 10, $done );

		$repo->prune_expired( 90 * DAY_IN_SECONDS, 2 );
		foreach ( $ids as $id ) {
			$this->assertSame( array(), get_user_option( LoginHistoryRepository::META, $id )['e'], "user $id" );
		}
		$this->assertSame( 0, (int) get_option( LoginHistoryRepository::CURSOR_OPTION ), 'the cursor wraps to the start' );
	}

	public function test_prune_matches_the_exact_meta_key_only(): void {
		$this->expired_history( 1 );
		$other = $GLOBALS['wpdb']->get_blog_prefix() . 'x_wpb_login_seen';
		update_user_meta(
			1,
			$other,
			array(
				'since' => 5,
				'e'     => array( array( 'r' => '203.0.113.0/24', 'c' => 'DE', 't' => 6 ) ),
			)
		);
		( new LoginHistoryRepository() )->prune_expired( 90 * DAY_IN_SECONDS );
		$this->assertCount( 1, get_user_meta( 1, $other, true )['e'], 'another key is untouched' );
	}

	public function test_prune_ignores_junk_meta_and_an_empty_table(): void {
		( new LoginHistoryRepository() )->prune_expired( 90 * DAY_IN_SECONDS );
		update_user_option( 1, LoginHistoryRepository::META, 'junk' );
		( new LoginHistoryRepository() )->prune_expired( 90 * DAY_IN_SECONDS );
		$this->assertSame( 'junk', get_user_option( LoginHistoryRepository::META, 1 ) );
	}
}
