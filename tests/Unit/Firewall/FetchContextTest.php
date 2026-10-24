<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Firewall;

use PHPUnit\Framework\TestCase;
use WPBouncer\Firewall\FetchContext;

/**
 * @covers \WPBouncer\Firewall\FetchContext
 */
final class FetchContextTest extends TestCase {

	private const OWN = array( 'shop.example', 'www.shop.example' );

	/** @dataProvider cases */
	public function test_from_server( array $server, string $expected ): void {
		$this->assertSame( $expected, FetchContext::from_server( $server, self::OWN ) );
	}

	public static function cases(): array {
		return array(
			'no headers'                     => array( array(), 'unknown' ),
			'cross-site'                     => array( array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ), 'cross-site' ),
			'same-site'                      => array( array( 'HTTP_SEC_FETCH_SITE' => 'same-site' ), 'same-site' ),
			'same-origin'                    => array( array( 'HTTP_SEC_FETCH_SITE' => 'same-origin' ), 'same-origin' ),
			'none'                           => array( array( 'HTTP_SEC_FETCH_SITE' => 'none' ), 'none' ),
			'upper case'                     => array( array( 'HTTP_SEC_FETCH_SITE' => 'Cross-Site' ), 'cross-site' ),
			'garbage value'                  => array( array( 'HTTP_SEC_FETCH_SITE' => 'sideways' ), 'unknown' ),
			'sec-fetch wins'                 => array(
				array(
					'HTTP_SEC_FETCH_SITE' => 'same-origin',
					'HTTP_ORIGIN'         => 'https://evil.example',
				),
				'same-origin',
			),
			'origin: own host'               => array( array( 'HTTP_ORIGIN' => 'https://shop.example' ), 'same-origin' ),
			'origin: own host, other port'   => array( array( 'HTTP_ORIGIN' => 'https://SHOP.example:8443' ), 'cross-site' ),
			'origin: own host, default port' => array( array( 'HTTP_ORIGIN' => 'https://SHOP.example:443' ), 'same-origin' ),
			'origin: own www'                => array( array( 'HTTP_ORIGIN' => 'http://www.shop.example' ), 'same-origin' ),
			'origin: other host'             => array( array( 'HTTP_ORIGIN' => 'https://evil.example' ), 'cross-site' ),
			'origin: look-alike'             => array( array( 'HTTP_ORIGIN' => 'https://shop.example.evil.example' ), 'cross-site' ),
			'origin: null'                   => array( array( 'HTTP_ORIGIN' => 'null' ), 'unknown' ),
			'origin: empty'                  => array( array( 'HTTP_ORIGIN' => '' ), 'unknown' ),
			'origin: not a url'              => array( array( 'HTTP_ORIGIN' => '://' ), 'unknown' ),
		);
	}

	public function test_without_own_hosts_an_origin_is_cross_site(): void {
		$this->assertSame( 'cross-site', FetchContext::from_server( array( 'HTTP_ORIGIN' => 'https://shop.example' ), array() ) );
	}

	public function test_an_own_origin_overrules_cross_site_and_same_site(): void {
		foreach ( array( 'cross-site', 'same-site' ) as $site ) {
			$server = array(
				'HTTP_SEC_FETCH_SITE' => $site,
				'HTTP_ORIGIN'         => 'https://shop.example',
			);
			$this->assertSame( 'same-origin', FetchContext::from_server( $server, self::OWN ), $site );
		}
		$sso = array(
			'HTTP_SEC_FETCH_SITE' => 'cross-site',
			'HTTP_ORIGIN'         => 'https://sso.example',
		);
		$this->assertSame( 'cross-site', FetchContext::from_server( $sso, self::OWN ) );
		$this->assertSame( 'same-origin', FetchContext::from_server( $sso, array( 'sso.example' ) ), 'allowed origin' );
	}

	public function test_a_sibling_subdomain_stays_same_site_unless_its_origin_is_listed(): void {
		$server = array(
			'HTTP_SEC_FETCH_SITE' => 'same-site',
			'HTTP_ORIGIN'         => 'https://blog.shop.example',
		);
		$this->assertSame( 'same-site', FetchContext::from_server( $server, self::OWN ) );
		$this->assertSame( 'same-origin', FetchContext::from_server( $server, array( 'blog.shop.example' ) ) );
	}

	public function test_the_host_header_is_not_trusted(): void {
		$server = array(
			'HTTP_SEC_FETCH_SITE' => 'cross-site',
			'HTTP_ORIGIN'         => 'https://other-name.example',
			'HTTP_HOST'           => 'other-name.example',
		);
		$this->assertSame( 'cross-site', FetchContext::from_server( $server, self::OWN ) );
		unset( $server['HTTP_SEC_FETCH_SITE'] );
		$this->assertSame( 'cross-site', FetchContext::from_server( $server, self::OWN ) );
	}

	public function test_scheme_and_port_must_match_for_full_origins(): void {
		$own   = array( 'https://shop.example', 'http://localhost:8080' );
		$cases = array(
			'https://shop.example'      => 'same-origin',
			'https://shop.example:443'  => 'same-origin',
			'http://shop.example'       => 'cross-site',
			'https://shop.example:8443' => 'cross-site',
			'http://localhost:8080'     => 'same-origin',
			'http://localhost:9090'     => 'cross-site',
			'http://localhost'          => 'cross-site',
			'https://localhost:8080'    => 'cross-site',
		);
		foreach ( $cases as $origin => $expected ) {
			$this->assertSame( $expected, FetchContext::from_server( array( 'HTTP_ORIGIN' => $origin ), $own ), $origin );
		}
	}

	public function test_a_bare_host_entry_matches_both_schemes_on_default_ports_only(): void {
		$this->assertSame( 'same-origin', FetchContext::from_server( array( 'HTTP_ORIGIN' => 'http://sso.example' ), array( 'sso.example' ) ) );
		$this->assertSame( 'same-origin', FetchContext::from_server( array( 'HTTP_ORIGIN' => 'https://sso.example' ), array( 'sso.example' ) ) );
		$this->assertSame( 'cross-site', FetchContext::from_server( array( 'HTTP_ORIGIN' => 'https://sso.example:8443' ), array( 'sso.example' ) ) );
		$this->assertSame( 'same-origin', FetchContext::from_server( array( 'HTTP_ORIGIN' => 'https://sso.example:8443' ), array( 'sso.example:8443' ) ) );
	}

	public function test_is_navigation(): void {
		$this->assertTrue(
			FetchContext::is_navigation(
				array(
					'HTTP_SEC_FETCH_MODE' => 'navigate',
					'HTTP_SEC_FETCH_DEST' => 'document',
				)
			)
		);
		$this->assertFalse(
			FetchContext::is_navigation(
				array(
					'HTTP_SEC_FETCH_MODE' => 'no-cors',
					'HTTP_SEC_FETCH_DEST' => 'image',
				)
			)
		);
		$this->assertFalse(
			FetchContext::is_navigation(
				array(
					'HTTP_SEC_FETCH_MODE' => 'navigate',
					'HTTP_SEC_FETCH_DEST' => 'iframe',
				)
			)
		);
		$this->assertFalse( FetchContext::is_navigation( array() ) );
	}

	public function test_a_null_origin_is_cross_site_only_on_a_post(): void {
		$this->assertSame(
			'unknown',
			FetchContext::from_server(
				array(
					'HTTP_ORIGIN'    => 'null',
					'REQUEST_METHOD' => 'GET',
				),
				self::OWN
			)
		);
		$this->assertSame(
			'cross-site',
			FetchContext::from_server(
				array(
					'HTTP_ORIGIN'    => 'null',
					'REQUEST_METHOD' => 'POST',
				),
				self::OWN
			)
		);
	}

	public function test_the_referer_is_the_last_resort_for_a_get(): void {
		$get = array( 'REQUEST_METHOD' => 'GET' );
		$this->assertSame( 'cross-site', FetchContext::from_server( $get + array( 'HTTP_REFERER' => 'https://blog.example/post' ), self::OWN ) );
		$this->assertSame( 'same-origin', FetchContext::from_server( $get + array( 'HTTP_REFERER' => 'https://shop.example/x' ), self::OWN ) );
		$this->assertSame( 'unknown', FetchContext::from_server( $get, self::OWN ) );
		$this->assertSame(
			'unknown',
			FetchContext::from_server(
				array(
					'REQUEST_METHOD' => 'POST',
					'HTTP_REFERER'   => 'https://blog.example/',
				),
				self::OWN
			),
			'not for a POST'
		);
		$this->assertSame(
			'same-origin',
			FetchContext::from_server(
				$get + array(
					'HTTP_SEC_FETCH_SITE' => 'same-origin',
					'HTTP_REFERER'        => 'https://blog.example/',
				),
				self::OWN
			),
			'Sec-Fetch-Site wins'
		);
	}

	/** @dataProvider destinations */
	public function test_is_subresource_needs_a_matching_extension( string $dest, string $path, bool $expected ): void {
		$this->assertSame( $expected, FetchContext::is_subresource( array( 'HTTP_SEC_FETCH_DEST' => $dest ), $path ), "{$dest} {$path}" );
	}

	public static function destinations(): array {
		return array(
			array( 'image', '/a/logo.png', true ),
			array( 'image', '/a/logo.SVG', true ),
			array( 'script', '/a/app.js', true ),
			array( 'style', '/a/app.css', true ),
			array( 'font', '/a/f.woff2', true ),
			array( 'audio', '/a/s.mp3', true ),
			array( 'video', '/a/s.mp4', true ),
			array( 'track', '/a/s.vtt', true ),
			array( 'IMAGE', '/a/logo.png', true ),
			array( 'image', '/.env', false ),
			array( 'image', '/backup.zip', false ),
			array( 'script', '/vendor/phpunit/x/eval-stdin.php', false ),
			array( 'style', '/db.sql', false ),
			array( 'image', '/a/logo.png.php', false ),
			array( 'document', '/a/logo.png', false ),
			array( 'iframe', '/a/app.js', false ),
			array( '', '/a/app.js', false ),
		);
	}

	public function test_is_subresource_load_ignores_the_path(): void {
		$this->assertTrue( FetchContext::is_subresource_load( array( 'HTTP_SEC_FETCH_DEST' => 'image' ) ) );
		$this->assertFalse( FetchContext::is_subresource_load( array( 'HTTP_SEC_FETCH_DEST' => 'document' ) ) );
		$this->assertFalse( FetchContext::is_subresource_load( array() ) );
	}
}
