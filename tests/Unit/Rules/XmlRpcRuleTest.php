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

	/** @dataProvider formatted_multicalls */
	public function test_multicall_is_refused_whatever_the_xml_formatting( string $body ): void {
		$verdict = $this->rule( 'block_abuse' )->inspect( Requests::make( array( 'uri' => '/xmlrpc.php', 'method' => 'POST', 'body' => $body ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'system.multicall', $verdict->reason() );
	}

	public static function formatted_multicalls(): array {
		$head = '<?xml version="1.0"?><methodCall>';
		return array(
			'whitespace'       => array( $head . "<methodName>\n\t system.multicall \n</methodName></methodCall>" ),
			'comment inside'   => array( $head . '<methodName>system.<!-- x -->multicall</methodName></methodCall>' ),
			'cdata'            => array( $head . '<methodName><![CDATA[system.multicall]]></methodName></methodCall>' ),
			'char reference'   => array( $head . '<methodName>system&#46;multicall</methodName></methodCall>' ),
			'attributes'       => array( $head . '<methodName x="1" >system.multicall</methodName></methodCall>' ),
			'self-closing mix' => array( $head . '<methodName/><methodName>system.multicall</methodName></methodCall>' ),
			'second methodName' => array( $head . '<methodName>wp.getPosts</methodName><params><param><value><struct><member><methodName>system.multicall</methodName></member></struct></value></param></params></methodCall>' ),
			'leading newline'  => array( "\n  <?xml version=\"1.0\"?>\n<methodCall><methodName>system.multicall</methodName></methodCall>" ),
			'tag inside name resets text' => array( $head . '<methodName>foo<x/>system.multicall</methodName></methodCall>' ),
			'declaration inside first 100 bytes' => array( '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><methodCall><methodName>system.multicall</methodName></methodCall>' ),
		);
	}

	/** @dataProvider legitimate_calls */
	public function test_legitimate_calls_pass_in_block_abuse_mode( string $body ): void {
		$this->assertNull( $this->rule( 'block_abuse' )->inspect( Requests::make( array( 'uri' => '/xmlrpc.php', 'method' => 'POST', 'body' => $body ) ) ) );
	}

	public static function legitimate_calls(): array {
		$call = static function ( string $method, string $params = '' ): string {
			return "<?xml version=\"1.0\"?>\n<methodCall>\n  <methodName>{$method}</methodName>\n  <params>{$params}</params>\n</methodCall>";
		};
		return array(
			'getUsersBlogs'   => array( $call( 'wp.getUsersBlogs', '<param><value><string>user</string></value></param>' ) ),
			'newPost (jetpack-like)' => array( $call( 'wp.newPost', '<param><value><struct><member><name>post_content</name><value><string>system.multicall is a method</string></value></member></struct></value></param>' ) ),
			'metaWeblog'      => array( $call( 'metaWeblog.newPost' ) ),
			'empty body'      => array( '' ),
			'cdata content'   => array( $call( 'wp.getPosts', '<param><value><string><![CDATA[<methodName>x</methodName>]]></string></value></param>' ) ),
		);
	}

	/** @dataProvider refused_bodies */
	public function test_unparseable_or_entity_bodies_are_refused_in_block_abuse_mode( string $body ): void {
		$this->assertNotNull( $this->rule( 'block_abuse' )->inspect( Requests::make( array( 'uri' => '/xmlrpc.php', 'method' => 'POST', 'body' => $body ) ) ) );
		$this->assertNull( XmlRpcRule::method_names( $body ) );
	}

	public static function refused_bodies(): array {
		return array(
			'truncated xml' => array( '<methodCall><methodName>system.multicall</methodName><params>' ),
			'not xml'       => array( 'not xml' ),
			'doctype'       => array( '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "system.multicall">]><methodCall><methodName>&a;</methodName></methodCall>' ),
			'doctype only'  => array( '<!doctype html><methodCall><methodName>wp.getPosts</methodName></methodCall>' ),
			'entity'        => array( '<methodCall><!ENTITY a "b"><methodName>wp.getPosts</methodName></methodCall>' ),
			'utf-16 no bom' => array( mb_convert_encoding( '<?xml version="1.0" encoding="UTF-16"?><methodCall><methodName>system.multicall</methodName></methodCall>', 'UTF-16BE', 'UTF-8' ) ),
		);
	}

	public function test_empty_body_is_not_refused_in_block_abuse_mode(): void {
		$this->assertSame( array(), XmlRpcRule::method_names( '' ) );
		$this->assertSame( array(), XmlRpcRule::method_names( " \n " ) );
	}

	public function test_path_info_does_not_bypass_the_rule(): void {
		$this->assertNotNull( $this->rule( 'block_all' )->inspect( Requests::make( array( 'uri' => '/xmlrpc.php/x' ) ) ) );
		$this->assertNotNull( $this->rule( 'block_abuse' )->inspect( Requests::make( array( 'uri' => '/xmlrpc.php/x', 'method' => 'POST', 'body' => self::payload( 'system.multicall' ) ) ) ) );
	}

	public function test_method_names_lists_every_method(): void {
		$this->assertSame( array( 'a', 'b' ), XmlRpcRule::method_names( '<methodCall><methodName>a</methodName><x><methodName>b</methodName></x></methodCall>' ) );
		$this->assertNull( XmlRpcRule::method_names( 'not xml' ) );
	}
}
