<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use WPBouncer\Support\UrlRedactor;

/**
 * @covers \WPBouncer\Support\UrlRedactor
 */
final class UrlRedactorTest extends TestCase {

	/** @return array<string, array{0: string, 1: string}> */
	public static function urls(): array {
		return array(
			'reset key'            => array( '/wp-login.php?action=rp&key=AbC123&login=jane', '/wp-login.php?action=rp&key=[removed]&login=jane' ),
			'token'                => array( '/x?token=a&access_token=b&refresh_token=c', '/x?token=[removed]&access_token=[removed]&refresh_token=[removed]' ),
			'password'             => array( '/x?pwd=a&password=b&user_pass=c', '/x?pwd=[removed]&password=[removed]&user_pass=[removed]' ),
			'nonce'                => array( '/x?_wpnonce=a&my_nonce=b', '/x?_wpnonce=[removed]&my_nonce=[removed]' ),
			'api and licence keys' => array( '/x?api_key=a&license_key=b&apikey=c&stripe-key=d', '/x?api_key=[removed]&license_key=[removed]&apikey=[removed]&stripe-key=[removed]' ),
			'email by name'        => array( '/x?email=a%40b.example&user_email=z', '/x?email=[removed]&user_email=[removed]' ),
			'email by value'       => array( '/x?q=jane%40example.org&r=jane@example.org', '/x?q=[removed]&r=[removed]' ),
			'secret and signature' => array( '/x?client_secret=a&sig=b&jwt=c&otp=1', '/x?client_secret=[removed]&sig=[removed]&jwt=[removed]&otp=[removed]' ),
			'array names'          => array( '/x?PASS[0]=a&Token=b', '/x?PASS[0]=[removed]&Token=[removed]' ),
			'encoded key name'     => array( '/x?pass%77ord=a&%6bey=b', '/x?pass%77ord=[removed]&%6bey=[removed]' ),
			'bracketed names'      => array( '/x?user[password]=a&data[token]=b&form[email]=c&api[key]=d&ok[x]=1', '/x?user[password]=[removed]&data[token]=[removed]&form[email]=[removed]&api[key]=[removed]&ok[x]=1' ),
			'mangled names'        => array( '/x?api.key=a&api+key=b&api%5Bkey=c&user%5Bpwd%5D=d', '/x?api.key=[removed]&api+key=[removed]&api%5Bkey=[removed]&user%5Bpwd%5D=[removed]' ),
			'login GET params'     => array( '/wp-login.php?log=bob&pwd=hunter2&user_login=bob&username=bob&user=bob&x=1', '/wp-login.php?log=[removed]&pwd=[removed]&user_login=[removed]&username=[removed]&user=[removed]&x=1' ),
			'pass is word-ish'     => array( '/x?bypass=1&compass=2&passphrase=z&my_pass=y&pass-code=q', '/x?bypass=1&compass=2&passphrase=[removed]&my_pass=[removed]&pass-code=[removed]' ),
			'nested redirect_to'   => array( '/wp-login.php?redirect_to=https%3A%2F%2Fa.example%2Fx%3Fkey%3Dabc%26ok%3D1&b=2', '/wp-login.php?redirect_to=https%3A%2F%2Fa.example%2Fx%3Fkey%3D[removed]%26ok%3D1&b=2' ),
			'nested twice'         => array( '/x?r=%2Fa%3Fr2%3D%252Fb%253Ftoken%253Dzzz', '/x?r=%2Fa%3Fr2%3D%252Fb%253Ftoken%253D[removed]' ),
			'export file hash'     => array( '/wp-content/uploads/wp-personal-data-file-AbC123xyz.zip', '/wp-content/uploads/wp-personal-data-file-[removed].zip' ),
			'jsessionid'           => array( '/app;jsessionid=ABC123?a=1', '/app;jsessionid=[removed]?a=1' ),
			'user info'            => array( 'https://bob:hunter2@example.org/p?a=1', 'https://[removed]@example.org/p?a=1' ),
			'fragment kept'        => array( 'https://example.org/p?key=s#section', 'https://example.org/p?key=[removed]#section' ),
			'fragment token'       => array( 'https://example.org/cb#access_token=abc&state=1', 'https://example.org/cb#access_token=[removed]&state=1' ),
			'non-secret untouched' => array( '/?s=keyboard&monkey=1&p=7&page=2&login=jane&q=a@b', '/?s=keyboard&monkey=1&p=7&page=2&login=jane&q=a@b' ),
			'no query'             => array( '/about-us/', '/about-us/' ),
			'empty'                => array( '', '' ),
			'empty value'          => array( '/x?key=&a=1', '/x?key=&a=1' ),
			'flag without value'   => array( '/x?token&a=1', '/x?token&a=1' ),
			'malformed'            => array( '/x?&&=&=a&key==b&?token=z', '/x?&&=&=a&key=[removed]&?token=[removed]' ),
			'only a question mark' => array( '?', '?' ),
			'scheme only'          => array( 'http://', 'http://' ),
		);
	}

	/** @dataProvider urls */
	public function test_redact( string $in, string $out ): void {
		$this->assertSame( $out, UrlRedactor::redact( $in ) );
	}

	public function test_very_long_url_is_handled(): void {
		$url = '/x?' . str_repeat( 'a=1&', 50000 ) . 'key=secretvalue';
		$out = UrlRedactor::redact( $url );
		$this->assertStringEndsWith( 'key=[removed]', $out );
		$this->assertStringNotContainsString( 'secretvalue', $out );

		$long_value = '/x?b=' . str_repeat( 'a', 200000 ) . '&token=zzz';
		$this->assertStringEndsWith( 'token=[removed]', UrlRedactor::redact( $long_value ) );
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function labels(): array {
		return array(
			'plain url'        => array( 'https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz', 'download.db-ip.com/…/dbip-country-lite-2026-10.csv.gz' ),
			'user info + key'  => array( 'https://bob:hunter2@geo.example.org/a/b/db.csv?license_key=SECRET#frag', 'geo.example.org/…/db.csv' ),
			'host only'        => array( 'https://geo.example.org/', 'geo.example.org' ),
			'file name'        => array( 'dbip.csv.gz', 'dbip.csv.gz' ),
			'file with query'  => array( 'dbip.csv?x=1', 'dbip.csv' ),
			'empty'            => array( '', '' ),
			'licence key path' => array( 'https://geo.example.org/dl/ABCD-1234-SECRET', 'geo.example.org/…/[removed]' ),
		);
	}

	/** @dataProvider labels */
	public function test_label( string $in, string $out ): void {
		$label = UrlRedactor::label( $in );
		$this->assertSame( $out, $label );
		$this->assertStringNotContainsString( 'SECRET', $label );
		$this->assertStringNotContainsString( 'hunter2', $label );
	}
}
