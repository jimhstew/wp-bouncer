<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Traffic;

use PHPUnit\Framework\TestCase;
use WPBouncer\Traffic\TrafficEntry;
use WPBouncer\Traffic\TrafficRecorder;

/**
 * @covers \WPBouncer\Traffic\TrafficEntry
 * @covers \WPBouncer\Traffic\TrafficRecorder::is_background
 */
final class TrafficEntryTest extends TestCase {

	public function test_builds_a_row(): void {
		$row = TrafficEntry::build(
			array(
				'ip'         => '203.0.113.10',
				'method'     => 'get',
				'uri'        => '/hello-world/?utm_source=x',
				'status'     => 200,
				'referrer'   => 'https://www.google.com/',
				'user_agent' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0',
				'user_id'    => 3,
			)
		);
		$this->assertSame(
			array(
				'ip'         => '203.0.113.10',
				'method'     => 'GET',
				'uri'        => '/hello-world/?utm_source=x',
				'referrer'   => 'https://www.google.com/',
				'user_agent' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0',
				'client'     => 'browser',
				'status'     => 200,
				'user_id'    => 3,
			),
			$row
		);
	}

	public function test_missing_and_bad_values(): void {
		$row = TrafficEntry::build( array( 'status' => 999, 'user_id' => -4, 'uri' => array( 'x' ) ) );
		$this->assertSame( 0, $row['status'] );
		$this->assertSame( 0, $row['user_id'] );
		$this->assertSame( '', $row['uri'] );
		$this->assertSame( 'unknown', $row['client'] );
	}

	public function test_lengths_are_capped_and_control_characters_removed(): void {
		$row = TrafficEntry::build(
			array(
				'uri'        => '/' . str_repeat( 'a', 5000 ),
				'referrer'   => "https://evil.example/\r\nX-Injected: 1",
				'user_agent' => str_repeat( 'b', 900 ),
			)
		);
		$this->assertSame( 2048, strlen( $row['uri'] ) );
		$this->assertSame( 512, strlen( $row['user_agent'] ) );
		$this->assertStringNotContainsString( "\n", $row['referrer'] );
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function urls(): array {
		return array(
			'password reset key' => array( '/wp-login.php?action=rp&key=AbC123secret&login=jane', '/wp-login.php?action=rp&key=[removed]&login=jane' ),
			'access token'       => array( '/wp-json/x?access_token=eyJhb.xyz&page=2', '/wp-json/x?access_token=[removed]&page=2' ),
			'password field'     => array( '/login?user=a&user_password=hunter2', '/login?user=[removed]&user_password=[removed]' ),
			'nonce'              => array( '/wp-admin/post.php?post=5&action=trash&_wpnonce=abc123', '/wp-admin/post.php?post=5&action=trash&_wpnonce=[removed]' ),
			'case and arrays'    => array( '/x?PASS[0]=a&Token=b', '/x?PASS[0]=[removed]&Token=[removed]' ),
			'encoded name'       => array( '/x?pass%77ord=a', '/x?pass%77ord=[removed]' ),
			'fragment kept'      => array( 'https://example.org/p?key=s#section', 'https://example.org/p?key=[removed]#section' ),
			'no query'           => array( '/about-us/', '/about-us/' ),
			'harmless params'    => array( '/?s=keyboard&monkey=1&p=7', '/?s=keyboard&monkey=1&p=7' ),
			'empty value'        => array( '/x?key=&a=1', '/x?key=&a=1' ),
			'flag without value' => array( '/x?token&a=1', '/x?token&a=1' ),
		);
	}

	/** @dataProvider urls */
	public function test_redacts_secrets( string $in, string $out ): void {
		$this->assertSame( $out, TrafficEntry::redact_url( $in ) );
	}

	public function test_referrer_is_redacted_too(): void {
		$row = TrafficEntry::build( array( 'referrer' => 'https://example.org/wp-login.php?action=rp&key=secret' ) );
		$this->assertStringNotContainsString( 'secret', $row['referrer'] );
	}

	public function test_status_ranges(): void {
		$this->assertSame( array( 400, 499 ), TrafficEntry::status_range( '4xx' ) );
		$this->assertSame( array( 200, 299 ), TrafficEntry::status_range( '2xx' ) );
		$this->assertNull( TrafficEntry::status_range( '6xx' ) );
		$this->assertNull( TrafficEntry::status_range( '404' ) );
		$this->assertNull( TrafficEntry::status_range( '' ) );
	}

	public function test_background_requests(): void {
		$this->assertTrue( TrafficRecorder::is_background( '/wp-cron.php', array() ) );
		$this->assertTrue( TrafficRecorder::is_background( '/wp-admin/admin-ajax.php', array( 'action' => 'heartbeat' ) ) );
		$this->assertFalse( TrafficRecorder::is_background( '/wp-admin/admin-ajax.php', array( 'action' => 'save_form' ) ) );
		$this->assertFalse( TrafficRecorder::is_background( '/', array() ) );
	}
}
