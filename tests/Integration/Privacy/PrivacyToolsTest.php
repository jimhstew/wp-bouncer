<?php
/**
 * Personal-data exporter, eraser and policy text through core's registries.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Privacy;

use WPBouncer\Privacy\PrivacyTools;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Traffic\TrafficLog;

/**
 * @covers \WPBouncer\Privacy\PrivacyTools
 */
final class PrivacyToolsTest extends IntegrationTestCase {

	/** @var int */
	private $alice;

	/** @var int */
	private $bob;

	public function set_up() {
		parent::set_up();
		$this->alice = self::factory()->user->create( array( 'user_login' => 'alice', 'user_email' => 'alice@example.org' ) );
		$this->bob   = self::factory()->user->create( array( 'user_login' => 'bob', 'user_email' => 'bob@example.org' ) );
	}

	/** @return array<string, mixed> */
	private function exporter(): array {
		$all = apply_filters( 'wp_privacy_personal_data_exporters', array() );
		$this->assertArrayHasKey( 'wp-bouncer-traffic', $all );
		return $all['wp-bouncer-traffic'];
	}

	/** @return array<string, mixed> */
	private function eraser( string $id ): array {
		$all = apply_filters( 'wp_privacy_personal_data_erasers', array() );
		$this->assertArrayHasKey( $id, $all );
		return $all[ $id ];
	}

	private function traffic( int $user_id, int $count ): void {
		global $wpdb;
		$log = new TrafficLog( $wpdb );
		for ( $i = 0; $i < $count; $i++ ) {
			$log->record( array( 'ip' => '198.51.100.7', 'method' => 'GET', 'uri' => '/p' . $i, 'status' => 200, 'user_id' => $user_id ) );
		}
	}

	private function traffic_count( int $user_id ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_traffic WHERE user_id = %d", $user_id ) ); // phpcs:ignore WordPress.DB
	}

	private function log_row( string $reason, string $uri = '/wp-login.php?x=1', string $rule = 'test', string $ip = '203.0.113.9' ): int {
		global $wpdb;
		$wpdb->insert(
			$wpdb->prefix . 'bouncer_log',
			array(
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
				'ip'         => $ip,
				'rule'       => $rule,
				'action'     => 'blocked',
				'reason'     => $reason,
				'uri'        => $uri,
			)
		);
		return (int) $wpdb->insert_id;
	}

	/** @return array<string, string> */
	private function log_get( int $id ): array {
		global $wpdb;
		return (array) $wpdb->get_row( $wpdb->prepare( "SELECT reason, uri FROM {$wpdb->prefix}bouncer_log WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB
	}

	/** Run every page of the log eraser; returns the combined result. */
	private function erase_log_fully( string $email ): array {
		$cb    = $this->eraser( 'wp-bouncer-log' )['callback'];
		$out   = array( 'items_removed' => 0, 'messages' => array(), 'items_retained' => false );
		for ( $page = 1; $page < 50; $page++ ) {
			$r                    = $cb( $email, $page );
			$out['items_removed'] += $r['items_removed'];
			$out['messages']       = array_merge( $out['messages'], $r['messages'] );
			$out['items_retained'] = $out['items_retained'] || $r['items_retained'];
			if ( $r['done'] ) {
				break;
			}
		}
		return $out;
	}

	public function test_exporter_pages_through_a_users_traffic_rows(): void {
		$this->traffic( $this->alice, 1200 );
		$this->traffic( $this->bob, 3 );
		$callback = $this->exporter()['callback'];

		$one   = $callback( 'alice@example.org', 1 );
		$two   = $callback( 'alice@example.org', 2 );
		$three = $callback( 'alice@example.org', 3 );

		$this->assertCount( 500, $one['data'] );
		$this->assertFalse( $one['done'] );
		$this->assertCount( 500, $two['data'] );
		$this->assertFalse( $two['done'] );
		$this->assertCount( 200, $three['data'] );
		$this->assertTrue( $three['done'] );
		$this->assertSame( 'wp-bouncer', $one['data'][0]['group_id'] );
	}

	public function test_exporter_returns_nothing_for_no_rows_or_no_account(): void {
		$callback = $this->exporter()['callback'];
		$none     = $callback( 'alice@example.org', 1 );
		$this->assertSame( array(), $none['data'] );
		$this->assertTrue( $none['done'] );
		$stranger = $callback( 'nobody@example.org', 1 );
		$this->assertSame( array(), $stranger['data'] );
		$this->assertTrue( $stranger['done'] );
	}

	public function test_traffic_eraser_removes_only_that_users_rows_in_batches(): void {
		$this->traffic( $this->alice, 1100 );
		$this->traffic( $this->bob, 4 );
		$this->traffic( 0, 5 );
		$callback = $this->eraser( 'wp-bouncer-traffic' )['callback'];

		$total = 0;
		for ( $page = 1; $page < 10; $page++ ) {
			$r      = $callback( 'alice@example.org', $page );
			$total += $r['items_removed'];
			$this->assertFalse( $r['items_retained'] );
			if ( $r['done'] ) {
				break;
			}
		}
		$this->assertSame( 1100, $total );
		$this->assertSame( 0, $this->traffic_count( $this->alice ) );
		$this->assertSame( 4, $this->traffic_count( $this->bob ) );
		$this->assertSame( 5, $this->traffic_count( 0 ) );
	}

	public function test_log_eraser_replaces_only_the_login_token_and_keeps_every_row(): void {
		global $wpdb;
		$lockout = $this->log_row( '5 failed logins (last username "Alice")', '/wp-login.php?x=1', 'login_lockout' );
		$banned  = $this->log_row( 'Tried banned username "alice"', '/wp-login.php', 'login_lockout' );
		$audit   = $this->log_row( 'New administrator — Username: alice, user ID ' . $this->alice . ' — by bob (user ID ' . $this->bob . ')', '/wp-admin/user-new.php', 'alerts' );
		$actor   = $this->log_row( 'Plugin activated — hello — by ALICE (user ID ' . $this->alice . ')', '/wp-admin/plugins.php', 'alerts' );
		$other   = $this->log_row( '5 failed logins (last username "bob")' );
		$before  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB

		$r = $this->erase_log_fully( 'alice@example.org' );

		$this->assertSame( 4, $r['items_removed'] );
		$this->assertTrue( $r['items_retained'] );
		$this->assertCount( 1, $r['messages'], 'the message is given once' );
		$this->assertStringContainsString( 'IP address, country, browser and time', $r['messages'][0] );
		$this->assertSame( array( 'reason' => '5 failed logins (last username "[erased]")', 'uri' => '' ), $this->log_get( $lockout ) );
		$this->assertSame( array( 'reason' => 'Tried banned username "[erased]"', 'uri' => '' ), $this->log_get( $banned ) );
		$this->assertSame( array( 'reason' => 'New administrator — Username: [erased], user ID ' . $this->alice . ' — by bob (user ID ' . $this->bob . ')', 'uri' => '/wp-admin/user-new.php' ), $this->log_get( $audit ), 'audit rows keep title, IDs, actor and URL' );
		$this->assertSame( array( 'reason' => 'Plugin activated — hello — by [erased] (user ID ' . $this->alice . ')', 'uri' => '/wp-admin/plugins.php' ), $this->log_get( $actor ) );
		$this->assertSame( '5 failed logins (last username "bob")', $this->log_get( $other )['reason'] );
		$this->assertSame( '/wp-login.php?x=1', $this->log_get( $other )['uri'] );
		$this->assertSame( $before + 1, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" ), 'rows are kept; one audit row is added' ); // phpcs:ignore WordPress.DB
		$last = (array) $wpdb->get_row( "SELECT rule, action, reason FROM {$wpdb->prefix}bouncer_log ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB
		$this->assertSame( 'alerts', $last['rule'] );
		$this->assertSame( 'alert', $last['action'] );
		$this->assertSame( 'Personal data erased for user ID ' . $this->alice . ' (request by unknown, user ID 0)', $last['reason'] );
	}

	/**
	 * @dataProvider short_logins
	 */
	public function test_unrelated_rows_survive_a_user_with_a_short_or_common_login( string $login ): void {
		$uid = wp_insert_user( array( 'user_login' => $login, 'user_email' => $login . '@example.net', 'user_pass' => 'x' ) );
		if ( is_wp_error( $uid ) ) { // The test install already has an "admin".
			$uid = (int) get_user_by( 'login', $login )->ID;
			wp_update_user( array( 'ID' => $uid, 'user_email' => $login . '@example.net' ) );
		}
		$waf = $this->log_row( 'Param "id" looked like SQL injection (union select)', '/?id=1', 'waf', '198.51.100.1' );
		$ua  = $this->log_row( 'User-Agent matched "sqlmap"', '/', 'user_agent', '198.51.100.2' );
		$ban = $this->log_row( 'Tried banned username "root"', '/wp-login.php', 'login_lockout', '198.51.100.3' );
		$num = $this->log_row( '3 failed logins (last username "5x")', '/wp-login.php', 'login_lockout', '198.51.100.4' );
		$own = $this->log_row( 'Tried banned username "' . $login . '"', '/wp-login.php', 'login_lockout', '198.51.100.5' );
		$ids = array( $waf, $ua, $ban, $num );
		$was = array_map( array( $this, 'log_get' ), $ids );

		$r = $this->erase_log_fully( $login . '@example.net' );

		foreach ( $ids as $i => $id ) {
			$this->assertSame( $was[ $i ], $this->log_get( $id ), "row $id is not this user's" );
		}
		$this->assertSame( 'Tried banned username "[erased]"', $this->log_get( $own )['reason'] );
		$this->assertSame( 1, $r['items_removed'] );
		$this->assertGreaterThan( 0, $uid );
	}

	/** @return array<string, array{string}> */
	public static function short_logins(): array {
		return array(
			'id'     => array( 'id' ),
			'sqlmap' => array( 'sqlmap' ),
			'admin'  => array( 'admin' ),
			'five'   => array( '5' ),
		);
	}

	public function test_wildcard_characters_in_a_login_or_email_match_literally(): void {
		$uid    = self::factory()->user->create( array( 'user_login' => 'a_b', 'user_email' => 'w%x_y@example.net' ) );
		$mine   = $this->log_row( 'Tried banned username "a_b"', '/wp-login.php', 'login_lockout' );
		$decoy1 = $this->log_row( 'Tried banned username "axb"', '/wp-login.php', 'login_lockout' );
		$mail   = $this->log_row( 'New administrator — Username: q, email: w%x_y@example.net, user ID 99', '/wp-admin/', 'alerts' );
		$decoy2 = $this->log_row( 'New administrator — Username: q, email: wQxzy@example.net, user ID 99', '/wp-admin/', 'alerts' );

		$this->erase_log_fully( 'w%x_y@example.net' );

		$this->assertSame( 'Tried banned username "[erased]"', $this->log_get( $mine )['reason'] );
		$this->assertSame( 'Tried banned username "axb"', $this->log_get( $decoy1 )['reason'] );
		$this->assertSame( 'New administrator — Username: q, email: [erased], user ID 99', $this->log_get( $mail )['reason'] );
		$this->assertSame( 'New administrator — Username: q, email: wQxzy@example.net, user ID 99', $this->log_get( $decoy2 )['reason'] );
		$this->assertGreaterThan( 0, $uid );
	}

	public function test_log_eraser_windows_cover_a_large_log_without_state(): void {
		$first = $this->log_row( 'Tried banned username "alice"', '/wp-login.php', 'login_lockout' );
		for ( $i = 0; $i < PrivacyTools::LOG_BATCH + 50; $i++ ) {
			$this->log_row( 'unrelated ' . $i );
		}
		$last = $this->log_row( 'Tried banned username "alice"', '/wp-login.php', 'login_lockout' );
		$cb   = $this->eraser( 'wp-bouncer-log' )['callback'];

		$one = $cb( 'alice@example.org', 1 );
		$this->assertFalse( $one['done'] );
		$this->assertSame( 1, $one['items_removed'] );
		$this->assertSame( array(), $one['messages'] );
		$two = $cb( 'alice@example.org', 2 );
		$this->assertTrue( $two['done'] );
		$this->assertSame( 1, $two['items_removed'] );
		$this->assertSame( 'Tried banned username "[erased]"', $this->log_get( $first )['reason'] );
		$this->assertSame( 'Tried banned username "[erased]"', $this->log_get( $last )['reason'] );
	}

	public function test_username_forms_apply_only_to_their_own_rule_and_uri_is_emptied_only_on_lockout_rows(): void {
		$waf_form   = $this->log_row( 'Tried banned username "alice"', '/x', 'waf' );
		$lock_alert = $this->log_row( 'Username: alice, user ID ' . $this->alice, '/y', 'login_lockout' );
		$alert_form = $this->log_row( 'Tried banned username "alice"', '/z', 'alerts' );
		$alert_ok   = $this->log_row( 'New administrator — Username: alice, user ID ' . $this->alice, '/wp-admin/user-new.php', 'alerts' );
		$lock_ok    = $this->log_row( 'Tried banned username "alice"', '/wp-login.php', 'login_lockout' );

		$r = $this->erase_log_fully( 'alice@example.org' );

		$this->assertSame( 2, $r['items_removed'] );
		$this->assertSame( array( 'reason' => 'Tried banned username "alice"', 'uri' => '/x' ), $this->log_get( $waf_form ) );
		$this->assertSame( 'Username: alice, user ID ' . $this->alice, $this->log_get( $lock_alert )['reason'] );
		$this->assertSame( 'Tried banned username "alice"', $this->log_get( $alert_form )['reason'] );
		$this->assertSame( array( 'reason' => 'New administrator — Username: [erased], user ID ' . $this->alice, 'uri' => '/wp-admin/user-new.php' ), $this->log_get( $alert_ok ) );
		$this->assertSame( array( 'reason' => 'Tried banned username "[erased]"', 'uri' => '' ), $this->log_get( $lock_ok ) );
	}

	public function test_the_erasure_audit_row_names_the_requester_and_is_itself_erasable(): void {
		global $wpdb;
		wp_set_current_user( $this->alice );
		$this->erase_log_fully( 'bob@example.org' );
		$audit_id = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB
		$this->assertSame( 'Personal data erased for user ID ' . $this->bob . ' (request by alice, user ID ' . $this->alice . ')', $this->log_get( $audit_id )['reason'] );

		// A different user's ID in that slot is not alice's row.
		$this->assertNull( PrivacyTools::redact_reason( 'Personal data erased for user ID 9 (request by alice, user ID 999)', 'alice', 'a@b.c', $this->alice, 'alerts' ) );

		wp_set_current_user( 0 );
		$this->erase_log_fully( 'alice@example.org' );
		$this->assertSame( 'Personal data erased for user ID ' . $this->bob . ' (request by [erased], user ID ' . $this->alice . ')', $this->log_get( $audit_id )['reason'] );
	}

	public function test_the_id_range_is_fixed_on_page_one_so_purges_and_floods_cannot_skip_rows_or_postpone_done(): void {
		global $wpdb;
		$first = $this->log_row( 'Tried banned username "alice"', '/wp-login.php', 'login_lockout' );
		for ( $i = 0; $i < PrivacyTools::LOG_BATCH + 20; $i++ ) {
			$this->log_row( 'unrelated ' . $i );
		}
		$last = $this->log_row( 'Tried banned username "alice"', '/wp-login.php', 'login_lockout' );
		$cb   = $this->eraser( 'wp-bouncer-log' )['callback'];

		$one = $cb( 'alice@example.org', 1 );
		$this->assertFalse( $one['done'] );
		// Meanwhile the purge removes old rows and a flood adds new ones.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}bouncer_log WHERE id < %d", $first + 500 ) ); // phpcs:ignore WordPress.DB
		for ( $i = 0; $i < 30; $i++ ) {
			$this->log_row( 'flood ' . $i );
		}
		$two = $cb( 'alice@example.org', 2 );

		$this->assertTrue( $two['done'], 'rows added after page 1 do not postpone done' );
		$this->assertSame( 'Tried banned username "[erased]"', $this->log_get( $last )['reason'], 'the purge did not shift the window past the last row' );
	}

	public function test_a_missing_range_on_a_later_page_is_recomputed(): void {
		$this->log_row( 'unrelated' );
		$r = $this->eraser( 'wp-bouncer-log' )['callback']( 'alice@example.org', 3 );
		$this->assertTrue( $r['done'] );
	}

	public function test_invalid_utf8_is_still_redacted_on_the_raw_bytes(): void {
		$out = PrivacyTools::redact_reason( "Tried banned username \"alice\" \xff\xfe", 'alice', 'a@b.c', 1, 'login_lockout' );
		$this->assertSame( "Tried banned username \"[erased]\" \xff\xfe", $out );
	}

	public function test_a_row_that_cannot_be_processed_is_reported_not_skipped(): void {
		// The JIT ignores pcre.backtrack_limit, so turn it off. The login is unique to this test so no
		// pattern compiled (with the JIT) by an earlier test is reused from the regex cache.
		$old_jit = ini_set( 'pcre.jit', '0' );
		$old     = ini_set( 'pcre.backtrack_limit', '1' );
		try {
			$out = PrivacyTools::redact_reason( 'Tried banned username "pcrefail" and a lot more text to scan through', 'pcrefail', 'p@b.c', 1, 'login_lockout' );
		} finally {
			ini_set( 'pcre.backtrack_limit', (string) $old );
			ini_set( 'pcre.jit', (string) $old_jit );
		}
		$this->assertFalse( $out );
	}

	public function test_a_long_reason_is_trimmed_in_the_middle_and_keeps_the_user_id_tail(): void {
		$title  = str_repeat( 'x', 255 - strlen( ' — Username: 5, user ID 7 — by 5 (user ID 7)' ) );
		$reason = $title . ' — Username: 5, user ID 7 — by 5 (user ID 7)';
		$this->assertSame( 255, strlen( $reason ) );

		$out = PrivacyTools::redact_reason( $reason, '5', 'a@b.c', 7, 'alerts' );

		$this->assertLessThanOrEqual( 255, mb_strlen( $out ) );
		$this->assertStringEndsWith( ' (user ID 7)', $out );
		$this->assertStringContainsString( '…', $out );
	}

	public function test_log_eraser_does_nothing_for_unknown_emails(): void {
		$r = $this->eraser( 'wp-bouncer-log' )['callback']( 'nobody@example.org', 1 );
		$this->assertTrue( $r['done'] );
		$this->assertFalse( $r['items_retained'] );
		$this->assertSame( 0, $r['items_removed'] );
	}

	public function test_redact_reason_is_case_insensitive_and_position_bound(): void {
		$this->assertSame( 'Tried banned username "[erased]"', PrivacyTools::redact_reason( 'Tried banned username "ALICE"', 'alice', 'a@b.c', 1, 'login_lockout' ) );
		$this->assertNull( PrivacyTools::redact_reason( 'Param "alice" looked bad', 'alice', 'a@b.c', 1, 'waf' ) );
		$this->assertSame( 'X — Username: [erased], email: [erased], user ID 1', PrivacyTools::redact_reason( 'X — Username: alice, email: A@B.c, user ID 1', 'alice', 'a@b.c', 1 ) );
		$this->assertNull( PrivacyTools::redact_reason( 'X — by alice (user ID 2)', 'alice', 'a@b.c', 1 ), 'another user ID' );
	}

	public function test_exporter_items_have_the_core_shape_and_do_not_leak_across_users(): void {
		$this->traffic( $this->alice, 2 );
		$this->traffic( $this->bob, 2 );
		$r = $this->exporter()['callback']( 'alice@example.org', 1 );

		$this->assertCount( 2, $r['data'] );
		foreach ( $r['data'] as $item ) {
			$this->assertSame( array( 'group_id', 'group_label', 'group_description', 'item_id', 'data' ), array_keys( $item ) );
			foreach ( $item['data'] as $pair ) {
				$this->assertSame( array( 'name', 'value' ), array_keys( $pair ) );
				$this->assertIsString( $pair['value'] );
			}
		}
		$uris = array_map( static fn( $i ) => $i['data'][2]['value'], $r['data'] );
		$this->assertSame( array( 'GET /p0', 'GET /p1' ), $uris );
		$this->assertCount( 2, $this->exporter()['callback']( 'bob@example.org', 1 )['data'] );
	}

	public function test_exporter_pages_by_keyset_even_after_rows_are_deleted_between_pages(): void {
		global $wpdb;
		$this->traffic( $this->alice, 600 );
		$callback = $this->exporter()['callback'];
		$one      = $callback( 'alice@example.org', 1 );
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_traffic WHERE id < (SELECT m FROM (SELECT MIN(id) + 10 AS m FROM {$wpdb->prefix}bouncer_traffic) t)" ); // phpcs:ignore WordPress.DB
		$two = $callback( 'alice@example.org', 2 );

		$this->assertCount( 500, $one['data'] );
		$this->assertCount( 100, $two['data'], 'the second page continues after the last exported id' );
		$this->assertTrue( $two['done'] );
	}

	public function test_policy_text_reflects_the_settings(): void {
		$this->set_settings( array( 'log_retention_days' => 90, 'traffic' => array( 'enabled' => false ) ) );
		$tools = new PrivacyTools( $this->plugin );
		$html  = $tools->policy_html();
		$this->assertStringContainsString( '90 days', $html );
		$this->assertStringContainsString( 'activity log', $html );
		$this->assertStringContainsString( 'email address of the affected account', $html );
		$this->assertStringNotContainsString( 'every page request', $html );

		$this->set_settings( array( 'traffic' => array( 'enabled' => true, 'retention_days' => 3 ) ) );
		$this->assertStringContainsString( 'every page request for 3 days', ( new PrivacyTools( $this->plugin ) )->policy_html() );
	}

	public function test_the_exporter_and_erasers_are_registered_by_the_plugin(): void {
		$this->assertArrayHasKey( 'wp-bouncer-traffic', apply_filters( 'wp_privacy_personal_data_exporters', array() ) );
		$erasers = apply_filters( 'wp_privacy_personal_data_erasers', array() );
		$this->assertArrayHasKey( 'wp-bouncer-traffic', $erasers );
		$this->assertArrayHasKey( 'wp-bouncer-log', $erasers );
	}
}
