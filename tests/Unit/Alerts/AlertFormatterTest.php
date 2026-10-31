<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Alerts;

use PHPUnit\Framework\TestCase;
use WPBouncer\Alerts\AlertFormatter;

/**
 * @covers \WPBouncer\Alerts\AlertFormatter
 */
final class AlertFormatterTest extends TestCase {

	/** @return array<string, string> */
	private function context(): array {
		return array(
			'site_name'    => 'My Blog',
			'site_url'     => 'https://example.org/',
			'time'         => '2026-10-20 12:00:00 UTC',
			'actor'        => 'alice (user ID 1)',
			'ip'           => '203.0.113.10',
			'country'      => 'NL',
			'user_agent'   => 'Mozilla/5.0',
			'settings_url' => 'https://example.org/wp-admin/admin.php?page=wp-bouncer&tab=general',
		);
	}

	public function test_single_event(): void {
		$mail = AlertFormatter::format(
			array(
				array(
					'type'   => 'admin',
					'title'  => 'New administrator account created',
					'detail' => 'Username: eve, email: eve@example.net, user ID 7',
				),
			),
			$this->context()
		);
		$this->assertSame( '[My Blog] WP Bouncer alert: New administrator account created', $mail['subject'] );
		$this->assertStringContainsString( '* New administrator account created', $mail['body'] );
		$this->assertStringContainsString( 'Username: eve', $mail['body'] );
		$this->assertStringContainsString( 'Done by:    alice (user ID 1)', $mail['body'] );
		$this->assertStringContainsString( 'From IP:    203.0.113.10 (NL)', $mail['body'] );
		$this->assertStringContainsString( 'Browser:    Mozilla/5.0', $mail['body'] );
		$this->assertStringContainsString( 'If you made this change', $mail['body'] );
		$this->assertStringContainsString( 'Alert settings: https://example.org/', $mail['body'] );
	}

	public function test_several_events_mention_an_admin(): void {
		$events = array(
			array( 'type' => 'plugin', 'title' => 'Plugin installed: X', 'detail' => '' ),
			array( 'type' => 'admin', 'title' => 'Account promoted to administrator', 'detail' => 'bob' ),
		);
		$mail   = AlertFormatter::format( $events, $this->context() );
		$this->assertSame( '[My Blog] WP Bouncer alert: 2 security events including a new administrator', $mail['subject'] );
		$this->assertStringContainsString( 'these changes', $mail['body'] );

		$events[1]['type'] = 'plugin';
		$this->assertSame( '[My Blog] WP Bouncer alert: 2 security events', AlertFormatter::format( $events, $this->context() )['subject'] );
	}

	public function test_no_header_injection_through_names(): void {
		$mail = AlertFormatter::format(
			array( array( 'type' => 'admin', 'title' => "Evil\r\nBcc: victim@example.com", 'detail' => '' ) ),
			array_merge( $this->context(), array( 'site_name' => "Blog\nX-Spam: 1" ) )
		);
		$this->assertStringNotContainsString( "\n", $mail['subject'] );
		$this->assertStringNotContainsString( "\r", $mail['subject'] );
	}

	public function test_missing_context(): void {
		$mail = AlertFormatter::format(
			array( array( 'type' => 'plugin', 'title' => 'Plugin deleted: x/x.php', 'detail' => '' ) ),
			array(
				'site_name' => '',
				'site_url'  => 'https://example.org/',
				'actor'     => 'no logged-in user',
			)
		);
		$this->assertStringStartsWith( '[https://example.org/]', $mail['subject'] );
		$this->assertStringContainsString( 'From IP:    unknown', $mail['body'] );
		$this->assertStringNotContainsString( 'Browser:', $mail['body'] );
		$this->assertStringNotContainsString( 'Alert settings:', $mail['body'] );
	}

	public function test_clean_caps_length(): void {
		$this->assertSame( 300, strlen( AlertFormatter::clean( str_repeat( 'a', 1000 ) ) ) );
		$this->assertSame( 'a b', AlertFormatter::clean( "a\x00\tb" ) );
	}

	public function test_dedupe_carries_the_log_detail(): void {
		$out = AlertFormatter::dedupe(
			array( array( 'type' => 'admin', 'title' => 'T', 'detail' => 'with email', 'key' => 'k', 'log_detail' => 'without' ) )
		);
		$this->assertSame( 'without', $out[0]['log_detail'] );
		$this->assertSame( 'with email', $out[0]['detail'] );
	}

	public function test_dedupe_keeps_the_drift_flag(): void {
		$out = AlertFormatter::dedupe(
			array( array( 'type' => 'settings', 'title' => 'T', 'detail' => 'd', 'drift' => true ) )
		);
		$this->assertTrue( $out[0]['drift'] );
	}

	public function test_dedupe_by_key_and_content(): void {
		$events = array(
			array( 'type' => 'admin', 'title' => 'New administrator account created', 'detail' => 'eve', 'key' => 'admin|7' ),
			array( 'type' => 'admin', 'title' => 'Account promoted to administrator', 'detail' => 'eve', 'key' => 'admin|7' ),
			array( 'type' => 'plugin', 'title' => 'Plugin activated: X', 'detail' => 'x/x.php' ),
			array( 'type' => 'plugin', 'title' => 'Plugin activated: X', 'detail' => 'x/x.php' ),
		);
		$out    = AlertFormatter::dedupe( $events );
		$this->assertCount( 2, $out );
		$this->assertSame( 'New administrator account created', $out[0]['title'], 'first one wins' );
		$this->assertArrayNotHasKey( 'key', $out[0] );
	}

	public function test_firewall_event_lists_the_changed_keys_and_who_did_it(): void {
		$mail = AlertFormatter::format(
			array( array( 'type' => 'firewall', 'title' => 'Firewall settings changed', 'detail' => 'Risky: allowlist, mode' ) ),
			$this->context()
		);

		$this->assertStringContainsString( 'Firewall settings changed', $mail['subject'] );
		$this->assertStringContainsString( 'Risky: allowlist, mode', $mail['body'] );
		$this->assertStringContainsString( 'Done by:    alice (user ID 1)', $mail['body'] );
	}

	public function test_several_events_with_a_firewall_change_say_so_in_the_subject(): void {
		$mail = AlertFormatter::format(
			array(
				array( 'type' => 'plugin', 'title' => 'Plugin activated: X', 'detail' => '' ),
				array( 'type' => 'firewall', 'title' => 'Firewall settings changed', 'detail' => 'Risky: mode' ),
			),
			$this->context()
		);

		$this->assertStringContainsString( '2 security events including firewall changes', $mail['subject'] );
	}

	public function test_dedupe_keeps_the_critical_logged_and_recipient_fields(): void {
		$out = AlertFormatter::dedupe(
			array( array( 'type' => 'firewall', 'title' => 'T', 'detail' => 'D', 'critical' => true, 'logged' => true, 'recipients' => array( 'a@example.org' ) ) )
		);

		$this->assertTrue( $out[0]['critical'] );
		$this->assertTrue( $out[0]['logged'] );
		$this->assertSame( array( 'a@example.org' ), $out[0]['recipients'] );
	}

	public function test_a_login_only_mail_has_the_login_closing_text(): void {
		$mail = AlertFormatter::format(
			array( array( 'type' => 'login', 'title' => 'Administrator login from a new location', 'detail' => 'User: jim (user ID 12). Method: interactive password. New: IP range 203.0.113.0/24.' ) ),
			$this->context()
		);
		$this->assertSame( '[My Blog] WP Bouncer alert: Administrator login from a new location', $mail['subject'] );
		$this->assertStringContainsString( 'If this was you, there is nothing to do. If not, change this account\'s password, revoke its application passwords and log out its other sessions', $mail['body'] );
		$this->assertStringNotContainsString( 'If you made', $mail['body'] );
	}

	public function test_two_login_events_are_still_login_only(): void {
		$events = array(
			array( 'type' => 'login', 'title' => 'Administrator login from a new location', 'detail' => 'a' ),
			array( 'type' => 'login', 'title' => 'Administrator login from a new location', 'detail' => 'b' ),
		);
		$mail   = AlertFormatter::format( $events, $this->context() );
		$this->assertStringContainsString( 'If this was you', $mail['body'] );
		$this->assertStringContainsString( 'including an administrator login from a new location', $mail['subject'] );
	}

	public function test_a_mixed_mail_keeps_the_generic_closing_and_names_the_login_in_the_subject(): void {
		$events = array(
			array( 'type' => 'plugin', 'title' => 'Plugin installed: X', 'detail' => '' ),
			array( 'type' => 'login', 'title' => 'Administrator login from a new location', 'detail' => 'd' ),
		);
		$mail   = AlertFormatter::format( $events, $this->context() );
		$this->assertSame( '[My Blog] WP Bouncer alert: 2 security events including an administrator login from a new location', $mail['subject'] );
		$this->assertStringContainsString( 'these changes', $mail['body'] );
		$this->assertStringNotContainsString( 'If this was you', $mail['body'] );

		$events[0]['type'] = 'admin';
		$this->assertStringContainsString( 'including a new administrator', AlertFormatter::format( $events, $this->context() )['subject'], 'an admin event wins the subject' );
	}

	public function test_dedupe_keeps_the_capped_flag(): void {
		$out = AlertFormatter::dedupe(
			array(
				array( 'type' => 'login', 'title' => 't', 'detail' => 'd', 'key' => 'login|3', 'capped' => true ),
				array( 'type' => 'login', 'title' => 't', 'detail' => 'd', 'key' => 'login|3' ),
			)
		);
		$this->assertCount( 1, $out );
		$this->assertTrue( $out[0]['capped'] );
	}
}
