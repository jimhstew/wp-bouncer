<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\MessageCodes;

/**
 * @covers \WPBouncer\Admin\MessageCodes
 */
final class MessageCodesTest extends \WP_UnitTestCase {

	public function test_unknown_codes_give_null(): void {
		$this->assertNull( MessageCodes::text( 'Settings saved.' ) );
		$this->assertNull( MessageCodes::text( '<script>' ) );
		$this->assertNull( MessageCodes::text( '' ) );
	}

	public function test_every_code_is_handled(): void {
		$args = array(
			'ip'     => '198.51.100.1',
			'rule'   => 'waf',
			'result' => 'protected',
			'detail' => 'x',
		);
		foreach ( MessageCodes::CODES as $code ) {
			$this->assertNotNull( MessageCodes::text( $code, $args ), $code );
		}
	}

	public function test_detail_codes_show_nothing_without_a_detail(): void {
		foreach ( array( 'test_sent', 'test_failed', 'geo_download_failed' ) as $code ) {
			$this->assertNull( MessageCodes::text( $code ), $code );
			$this->assertNull( MessageCodes::text( $code, array( 'detail' => '' ) ), $code );
		}
		$this->assertStringContainsString( 'ops@example.org', (string) MessageCodes::text( 'test_sent', array( 'detail' => 'ops@example.org' ) ) );
	}

	public function test_the_block_reason_is_shown_when_given_as_detail(): void {
		$this->assertStringContainsString( '(IP blocklist)', (string) MessageCodes::text( 'shared_refusal', array( 'detail' => 'IP blocklist' ) ) );
		$this->assertStringContainsString( '(IP blocklist)', (string) MessageCodes::text( 'saved', array( 'allow' => '198.51.100.1', 'detail' => 'IP blocklist' ) ) );
	}

	public function test_arguments_are_validated(): void {
		$this->assertNull( MessageCodes::text( 'ip_blocked', array( 'ip' => '192.0.2.0/24' ) ), 'ranges are not single IPs' );
		$this->assertNull( MessageCodes::text( 'ip_unlocked', array( 'ip' => 'evil text' ) ) );
		$this->assertNull( MessageCodes::text( 'probe_result', array( 'result' => 'Pwned' ) ) );
		$this->assertNull( MessageCodes::text( 'rule_toggled', array( 'rule' => 'not_a_rule', 'state' => 'on' ) ) );
		$this->assertStringContainsString( '198.51.100.1', (string) MessageCodes::text( 'ip_blocked', array( 'ip' => '198.51.100.1' ) ) );
		$this->assertStringContainsString( '7 ranges loaded, 0 lines skipped', (string) MessageCodes::text( 'geo_done', array( 'n' => '7' ) ) );
		$this->assertStringContainsString( '0 ranges loaded', (string) MessageCodes::text( 'geo_done', array( 'n' => '-5' ) ) );
	}

	public function test_saved_adds_only_validated_extras(): void {
		$text = (string) MessageCodes::text( 'saved', array( 'dropped' => '0.0.0.0/0,<b>x</b>,::/0', 'allow' => 'not an ip', 'noproxy' => 1 ) );

		$this->assertStringContainsString( '0.0.0.0/0, ::/0', $text );
		$this->assertStringNotContainsString( '<b>', $text );
		$this->assertStringNotContainsString( 'allowlist', $text );
		$this->assertStringContainsString( 'no trusted proxies', $text );
	}

	public function test_query_round_trip_and_flash(): void {
		$query = MessageCodes::to_query( 'ip_blocked', array( 'ip' => '2001:db8::1', 'detail' => 'secret' ) );
		$this->assertArrayNotHasKey( 'wpb_detail', $query );
		list( $code, $args ) = MessageCodes::from_query( array_map( 'rawurldecode', $query ) );
		$this->assertSame( 'ip_blocked', $code );
		$this->assertSame( '2001:db8::1', $args['ip'] );

		wp_set_current_user( 1 );
		MessageCodes::flash( 'boom' );
		$this->assertSame( 'boom', MessageCodes::take_flash() );
		$this->assertSame( '', MessageCodes::take_flash() );
	}

	public function test_from_query_ignores_arrays_and_unknown_arguments(): void {
		list( $code, $args ) = MessageCodes::from_query( array( 'wpb_msg' => array( 'x' ), 'wpb_ip' => '198.51.100.1' ) );
		$this->assertSame( '', $code );
		$this->assertSame( array(), $args );
		list( , $args ) = MessageCodes::from_query( array( 'wpb_msg' => 'saved', 'wpb_detail' => 'text', 'wpb_ip' => array( 'a' ) ) );
		$this->assertSame( array(), $args );
	}
}
