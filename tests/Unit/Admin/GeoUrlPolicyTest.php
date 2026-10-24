<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;
use WPBouncer\Admin\GeoUrlPolicy;

/**
 * @covers \WPBouncer\Admin\GeoUrlPolicy
 */
final class GeoUrlPolicyTest extends TestCase {

	private const HOSTS = array( 'download.db-ip.com', 'download.ip2location.com' );

	/**
	 * @dataProvider allowed_urls
	 */
	public function test_allowed( string $url ): void {
		$this->assertTrue( GeoUrlPolicy::allowed( $url, self::HOSTS ), $url );
	}

	/** @return array<string, array{string}> */
	public static function allowed_urls(): array {
		return array(
			'db-ip'        => array( 'https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz' ),
			'upper case'   => array( 'https://DOWNLOAD.DB-IP.COM/x.csv' ),
			'trailing dot' => array( 'https://download.ip2location.com./x.csv' ),
			'port'         => array( 'https://download.db-ip.com:443/x.csv' ),
		);
	}

	/**
	 * @dataProvider refused_urls
	 */
	public function test_refused( string $url ): void {
		$this->assertFalse( GeoUrlPolicy::allowed( $url, self::HOSTS ), $url );
	}

	/** @return array<string, array{string}> */
	public static function refused_urls(): array {
		return array(
			'http'             => array( 'http://download.db-ip.com/x.csv' ),
			'other host'       => array( 'https://example.com/x.csv' ),
			'subdomain'        => array( 'https://evil.download.db-ip.com/x.csv' ),
			'suffix trick'     => array( 'https://download.db-ip.com.evil.example/x.csv' ),
			'userinfo trick'   => array( 'https://download.db-ip.com@evil.example/x.csv' ),
			'internal address' => array( 'https://169.254.169.254/latest/meta-data' ),
			'no scheme'        => array( 'download.db-ip.com/x.csv' ),
			'junk'             => array( 'not a url' ),
			'empty'            => array( '' ),
		);
	}

	public function test_http_needs_the_explicit_opt_in_and_the_host_must_still_match(): void {
		$this->assertTrue( GeoUrlPolicy::allowed( 'http://127.0.0.1:8899/x.csv', array( '127.0.0.1' ), true ) );
		$this->assertFalse( GeoUrlPolicy::allowed( 'http://127.0.0.1:8899/x.csv', array( '127.0.0.1' ), false ) );
		$this->assertFalse( GeoUrlPolicy::allowed( 'http://10.0.0.1/x.csv', array( '127.0.0.1' ), true ) );
	}

	public function test_an_empty_list_refuses_everything(): void {
		$this->assertFalse( GeoUrlPolicy::allowed( 'https://download.db-ip.com/x.csv', array() ) );
	}

	/**
	 * @dataProvider redirects
	 */
	public function test_redirect_target( string $current, string $location, ?string $expected ): void {
		$this->assertSame( $expected, GeoUrlPolicy::redirect_target( $current, $location, self::HOSTS ) );
	}

	/** @return array<string, array{string, string, ?string}> */
	public static function redirects(): array {
		$cur = 'https://download.db-ip.com/free/a.csv.gz';
		return array(
			'absolute, listed'          => array( $cur, 'https://download.ip2location.com/b.csv', 'https://download.ip2location.com/b.csv' ),
			'absolute path'             => array( $cur, '/other/b.csv', 'https://download.db-ip.com/other/b.csv' ),
			'relative'                  => array( $cur, 'b.csv', 'https://download.db-ip.com/free/b.csv' ),
			'scheme-relative, listed'   => array( $cur, '//download.ip2location.com/b.csv', 'https://download.ip2location.com/b.csv' ),
			'unlisted host'             => array( $cur, 'https://evil.example/b.csv', null ),
			'scheme-relative, unlisted' => array( $cur, '//evil.example/b.csv', null ),
			'downgrade to http'         => array( $cur, 'http://download.db-ip.com/b.csv', null ),
			'internal address'          => array( $cur, 'https://169.254.169.254/latest', null ),
			'userinfo trick'            => array( $cur, 'https://download.db-ip.com@evil.example/', null ),
			'other scheme'              => array( $cur, 'ftp://download.db-ip.com/b', null ),
			'empty'                     => array( $cur, '', null ),
		);
	}

	public function test_a_downgrade_is_allowed_only_when_http_is_allowed_at_all(): void {
		$this->assertNull( GeoUrlPolicy::redirect_target( 'https://127.0.0.1/a', 'http://127.0.0.1/b', array( '127.0.0.1' ), false ) );
		$this->assertSame( 'http://127.0.0.1/b', GeoUrlPolicy::redirect_target( 'https://127.0.0.1/a', 'http://127.0.0.1/b', array( '127.0.0.1' ), true ) );
	}
}
