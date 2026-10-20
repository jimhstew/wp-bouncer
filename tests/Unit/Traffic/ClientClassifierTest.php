<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Traffic;

use PHPUnit\Framework\TestCase;
use WPBouncer\Traffic\ClientClassifier;

/**
 * @covers \WPBouncer\Traffic\ClientClassifier
 */
final class ClientClassifierTest extends TestCase {

	/** @return array<string, array{0: string, 1: string}> */
	public static function agents(): array {
		return array(
			'Firefox desktop'  => array( 'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0', 'browser' ),
			'Chrome Windows'   => array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36', 'browser' ),
			'Safari iPhone'    => array( 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', 'mobile' ),
			'Chrome Android'   => array( 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36', 'mobile' ),
			'Googlebot'        => array( 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'search_engine' ),
			'Bingbot'          => array( 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 'search_engine' ),
			'AhrefsBot'        => array( 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)', 'bot' ),
			'GPTBot'           => array( 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)', 'bot' ),
			'Facebook preview' => array( 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)', 'bot' ),
			'UptimeRobot'      => array( 'Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)', 'monitor' ),
			'Feedly'           => array( 'Feedly/1.0 (+http://www.feedly.com/fetcher.html; 3 subscribers)', 'feed' ),
			'WordPress cron'   => array( 'WordPress/6.6; https://example.org', 'wordpress' ),
			'curl'             => array( 'curl/8.4.0', 'tool' ),
			'python-requests'  => array( 'python-requests/2.31.0', 'tool' ),
			'Go'               => array( 'Go-http-client/1.1', 'tool' ),
			'sqlmap'           => array( 'sqlmap/1.7.2#stable (https://sqlmap.org)', 'scanner' ),
			'WPScan'           => array( 'WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)', 'scanner' ),
			'empty'            => array( '', 'unknown' ),
			'spaces'           => array( '   ', 'unknown' ),
			'odd'              => array( 'SomethingElse/1.0', 'other' ),
		);
	}

	/** @dataProvider agents */
	public function test_classify( string $ua, string $expected ): void {
		$this->assertSame( $expected, ClientClassifier::classify( $ua ), $ua );
	}

	public function test_types_are_unique_and_fit_the_column(): void {
		$types = ClientClassifier::types();
		$this->assertSame( $types, array_values( array_unique( $types ) ) );
		foreach ( $types as $type ) {
			$this->assertLessThanOrEqual( 16, strlen( $type ), $type );
		}
		$this->assertCount( 11, $types );
	}
}
