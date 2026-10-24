<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Firewall;

use PHPUnit\Framework\TestCase;
use WPBouncer\Firewall\Request;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Firewall\Request
 */
final class RequestTest extends TestCase {

	/** @dataProvider paths */
	public function test_normalize_path( string $uri, string $expected ): void {
		$this->assertSame( $expected, Request::normalize_path( $uri ) );
	}

	public static function paths(): array {
		return array(
			'root'             => array( '/', '/' ),
			'query stripped'   => array( '/a/b?c=d', '/a/b' ),
			'lowercased'       => array( '/XMLRPC.php', '/xmlrpc.php' ),
			'double slashes'   => array( '//wp-login.php', '/wp-login.php' ),
			'encoded'          => array( '/%78mlrpc.php', '/xmlrpc.php' ),
			'backslashes'      => array( '/foo\\bar', '/foo/bar' ),
			'empty'            => array( '', '/' ),
		);
	}

	public function test_endpoint_detection(): void {
		$this->assertTrue( Requests::make( array( 'uri' => '/wp-login.php?action=login' ) )->is_login() );
		$this->assertTrue( Requests::make( array( 'uri' => '/blog/wp-login.php' ) )->is_login() );
		$this->assertFalse( Requests::make( array( 'uri' => '/wp-login.php.bak' ) )->is_login() );
		$this->assertTrue( Requests::make( array( 'uri' => '/wp-login.php/x' ) )->is_login() );
		$this->assertTrue( Requests::make( array( 'uri' => '/blog/xmlrpc.php/a/b' ) )->is_xmlrpc() );
		$this->assertTrue( Requests::make( array( 'uri' => '/xmlrpc.php.bak/xmlrpc.php/x' ) )->is_xmlrpc() );
		$this->assertFalse( Requests::make( array( 'uri' => '/xmlrpc.php.bak/x' ) )->is_xmlrpc() );
		$this->assertFalse( Requests::make( array( 'uri' => '/my-xmlrpc.php/x' ) )->is_xmlrpc() );

		$this->assertTrue( Requests::make( array( 'uri' => '/xmlrpc.php' ) )->is_xmlrpc() );
		$this->assertTrue( Requests::make( array( 'uri' => '//XmlRpc.php' ) )->is_xmlrpc() );

		$this->assertTrue( Requests::make( array( 'uri' => '/wp-admin/admin-ajax.php' ) )->is_admin_area() );
		$this->assertTrue( Requests::make( array( 'uri' => '/wp-admin' ) )->is_admin_area() );
		$this->assertFalse( Requests::make( array( 'uri' => '/wp-administrator-guide/' ) )->is_admin_area() );
	}

	public function test_rest_route(): void {
		$this->assertSame( '/wp/v2/users', Requests::make( array( 'uri' => '/wp-json/wp/v2/users' ) )->rest_route() );
		$this->assertSame( '/wp/v2/users', Requests::make( array( 'query' => array( 'rest_route' => '/wp/v2/users' ) ) )->rest_route() );
		$this->assertSame( '/wp/v2/users/1', Requests::make( array( 'query' => array( 'rest_route' => 'wp/v2/USERS/1' ) ) )->rest_route() );
		$this->assertSame( '', Requests::make( array( 'uri' => '/about/' ) )->rest_route() );
	}

	public function test_headers(): void {
		$r = Requests::make(
			array(
				'server' => array(
					'HTTP_CF_IPCOUNTRY'  => 'DE',
					'GEOIP_COUNTRY_CODE' => 'FR',
				),
			)
		);
		$this->assertSame( 'DE', $r->header( 'CF-IPCountry' ) );
		$this->assertSame( 'FR', $r->header( 'GEOIP_COUNTRY_CODE' ) );
		$this->assertSame( '', $r->header( 'X-Missing' ) );
	}

	public function test_lazy_resolvers_are_called_once(): void {
		$calls = 0;
		$r     = new Request(
			array(
				'logged_in' => static function () use ( &$calls ) {
					++$calls;
					return true;
				},
			)
		);
		$this->assertSame( 0, $calls, 'resolver must not run until asked' );
		$this->assertTrue( $r->is_logged_in() );
		$this->assertTrue( $r->is_logged_in() );
		$this->assertSame( 1, $calls );
	}

	public function test_method_is_uppercased(): void {
		$this->assertSame( 'POST', Requests::make( array( 'method' => 'post' ) )->method() );
	}

	public function test_key_ip_is_the_ip_unless_a_subject_is_given(): void {
		$this->assertSame( '203.0.113.5', Requests::make( array( 'ip' => '203.0.113.5' ) )->key_ip() );
		$this->assertSame( 'rejected:127.0.0.1', Requests::make( array( 'ip' => '127.0.0.1', 'subject' => 'rejected:127.0.0.1' ) )->key_ip() );
		$this->assertSame( '127.0.0.1', Requests::make( array( 'ip' => '127.0.0.1', 'subject' => 'rejected:127.0.0.1' ) )->ip() );
	}

	public function test_admin_area_is_a_path_prefix(): void {
		$this->assertTrue( Requests::make( array( 'uri' => '/wp-admin/' ) )->is_admin_area() );
		$this->assertTrue( Requests::make( array( 'uri' => '/wp-admin' ) )->is_admin_area() );
		$this->assertTrue( Requests::make( array( 'uri' => '/wp-admin/admin-ajax.php' ) )->is_admin_area() );
		$this->assertFalse( Requests::make( array( 'uri' => '/index.php/wp-admin/' ) )->is_admin_area() );
		$this->assertFalse( Requests::make( array( 'uri' => '/blog/index.php/wp-admin/' ) )->is_admin_area() );
		$this->assertFalse( Requests::make( array( 'uri' => '/wp-admin-x/' ) )->is_admin_area() );
	}

	public function test_admin_area_in_a_subdirectory_install_uses_script_name(): void {
		$server = array( 'SCRIPT_NAME' => '/blog/wp-admin/edit.php' );
		$this->assertTrue( Requests::make( array( 'uri' => '/blog/wp-admin/edit.php?author=1', 'server' => $server ) )->is_admin_area() );
		$this->assertFalse( Requests::make( array( 'uri' => '/blog/wp-admin/edit.php', 'server' => array( 'SCRIPT_NAME' => '/blog/index.php' ) ) )->is_admin_area() );
		$this->assertFalse( Requests::make( array( 'uri' => '/other/wp-admin/edit.php', 'server' => $server ) )->is_admin_area() );
	}

	public function test_rest_route_can_come_from_the_post_body(): void {
		$this->assertSame( '/wp/v2/users', Requests::make( array( 'method' => 'POST', 'post' => array( 'rest_route' => '/wp/v2/users' ) ) )->rest_route() );
	}

	public function test_header_prefers_the_real_server_variable_for_names_without_a_hyphen(): void {
		$server = array( 'GEOIP_COUNTRY_CODE' => 'DE', 'HTTP_GEOIP_COUNTRY_CODE' => 'US', 'HTTP_X_FOO' => 'a' );
		$req    = Requests::make( array( 'server' => $server ) );
		$this->assertSame( 'DE', $req->header( 'GEOIP_COUNTRY_CODE' ) );
		$this->assertSame( 'a', $req->header( 'X-Foo' ) );
	}

	/** @dataProvider api_paths */
	public function test_core_authenticates_application_passwords_only_on_api_requests( array $args, bool $api ): void {
		$this->assertSame( $api, Requests::make( $args )->is_api_auth_request() );
	}

	public static function api_paths(): array {
		return array(
			'wp-json'                 => array( array( 'uri' => '/wp-json/wp/v2/posts' ), true ),
			'index.php/wp-json'       => array( array( 'uri' => '/index.php/wp-json/wp/v2/posts' ), true ),
			'front page rest_route'   => array( array( 'uri' => '/?rest_route=/wp/v2/posts', 'query' => array( 'rest_route' => '/wp/v2/posts' ) ), true ),
			'index.php rest_route'    => array( array( 'uri' => '/index.php?rest_route=/x', 'query' => array( 'rest_route' => '/x' ) ), true ),
			'pretty page rest_route'  => array( array( 'uri' => '/about/?rest_route=/x', 'query' => array( 'rest_route' => '/x' ) ), true ),
			'xmlrpc'                  => array( array( 'uri' => '/xmlrpc.php' ), true ),
			'admin-ajax rest_route'   => array( array( 'uri' => '/wp-admin/admin-ajax.php?rest_route=/x', 'query' => array( 'rest_route' => '/x' ) ), false ),
			'admin-post rest_route'   => array( array( 'uri' => '/wp-admin/admin-post.php?rest_route=/x', 'query' => array( 'rest_route' => '/x' ) ), false ),
			'wp-login rest_route'     => array( array( 'uri' => '/wp-login.php?rest_route=/x', 'query' => array( 'rest_route' => '/x' ) ), false ),
			'plain front-end path'    => array( array( 'uri' => '/contact-us/' ), false ),
			'admin-ajax'              => array( array( 'uri' => '/wp-admin/admin-ajax.php' ), false ),
		);
	}
}
