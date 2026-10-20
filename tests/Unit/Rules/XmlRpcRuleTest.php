<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\XmlRpcRule;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\XmlRpcRule
 */
final class XmlRpcRuleTest extends TestCase {

	private static function payload( string $method ): string {
		return '<?xml version="1.0"?><methodCall><methodName>' . $method . '</methodName><params></params></methodCall>';
	}

	private function rule( string $mode ): XmlRpcRule {
		return new XmlRpcRule(
			array(
				'enabled' => true,
				'mode'    => $mode,
			)
		);
	}

	public function test_block_all_refuses_any_xmlrpc_request(): void {
		$rule = $this->rule( 'block_all' );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'uri' => '/xmlrpc.php' ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'uri' => '/XMLRPC.PHP?rsd' ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'uri' => '/blog/xmlrpc.php', 'method' => 'POST', 'body' => self::payload( 'wp.getUsersBlogs' ) ) ) ) );
	}

	public function test_other_urls_are_ignored(): void {
		$this->assertNull( $this->rule( 'block_all' )->inspect( Requests::make( array( 'uri' => '/' ) ) ) );
		$this->assertNull( $this->rule( 'block_all' )->inspect( Requests::make( array( 'uri' => '/xmlrpc.php.html' ) ) ) );
	}

	public function test_block_abuse_refuses_multicall_and_pingbacks(): void {
		$rule = $this->rule( 'block_abuse' );
		foreach ( array( 'system.multicall', 'pingback.ping', 'System.MultiCall' ) as $method ) {
			$verdict = $rule->inspect( Requests::make( array( 'uri' => '/xmlrpc.php', 'method' => 'POST', 'body' => self::payload( $method ) ) ) );
			$this->assertNotNull( $verdict, $method );
			$this->assertStringContainsString( $method, $verdict->reason() );
		}
	}

	public function test_block_abuse_allows_normal_methods(): void {
		$rule = $this->rule( 'block_abuse' );
		$this->assertNull( $rule->inspect( Requests::make( array( 'uri' => '/xmlrpc.php', 'method' => 'POST', 'body' => self::payload( 'wp.getPosts' ) ) ) ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'uri' => '/xmlrpc.php' ) ) ) );
	}

	public function test_method_name_parsing(): void {
		$this->assertSame( 'system.multicall', XmlRpcRule::method_name( "<methodCall>\n <methodName>\n system.multicall \n</methodName>" ) );
		$this->assertNull( XmlRpcRule::method_name( 'not xml' ) );
	}
}
