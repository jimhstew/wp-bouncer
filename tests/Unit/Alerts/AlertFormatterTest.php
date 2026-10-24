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
}
