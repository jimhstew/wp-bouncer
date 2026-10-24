<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\UserAgentRule;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\UserAgentRule
 */
final class UserAgentRuleTest extends TestCase {

	private function rule( array $patterns = UserAgentRule::DEFAULT_PATTERNS, bool $block_empty = true ): UserAgentRule {
		return new UserAgentRule(
			array(
				'enabled'     => true,
				'block_empty' => $block_empty,
				'patterns'    => $patterns,
			)
		);
	}

	/** @dataProvider scanners */
	public function test_default_patterns_block_scanners( string $ua ): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'ua' => $ua ) ) ) );
	}

	public static function scanners(): array {
		return array(
			array( 'sqlmap/1.7.2#stable (https://sqlmap.org)' ),
			array( 'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000003)' ),
			array( 'WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)' ),
			array( 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' ),
			array( 'Mozilla/5.0 zgrab/0.x' ),
			array( 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)' ),
		);
	}

	/** @dataProvider browsers */
	public function test_default_patterns_allow_real_clients( string $ua ): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'ua' => $ua ) ) ) );
	}

	public static function browsers(): array {
		return array(
			array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36' ),
			array( 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1' ),
			array( 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' ),
			array( 'WordPress/6.6; https://example.com' ),
			array( 'Jetpack by WordPress.com' ),
		);
	}

	public function test_empty_user_agent(): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'ua' => '' ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'ua' => '   ' ) ) ) );
		$this->assertNull( $this->rule( array(), false )->inspect( Requests::make( array( 'ua' => '' ) ) ) );
	}

	public function test_substring_match_is_case_insensitive(): void {
		$this->assertNotNull( $this->rule( array( 'BadBot' ) )->inspect( Requests::make( array( 'ua' => 'my-badbot/1.0' ) ) ) );
	}

	public function test_regex_patterns(): void {
		$rule = $this->rule( array( '/^curl\//i' ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ua' => 'curl/8.4.0' ) ) ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ua' => 'Mozilla curl/8.4.0' ) ) ) );
	}

	public function test_is_regex(): void {
		$this->assertTrue( UserAgentRule::is_regex( '/foo/' ) );
		$this->assertTrue( UserAgentRule::is_regex( '/foo/i' ) );
		$this->assertFalse( UserAgentRule::is_regex( 'foo' ) );
		$this->assertFalse( UserAgentRule::is_regex( '/' ) );
		$this->assertFalse( UserAgentRule::is_regex( '/usr/bin/php' ) );
	}

	public function test_reason_names_the_pattern(): void {
		$verdict = $this->rule( array( 'evil' ) )->inspect( Requests::make( array( 'ua' => 'evil' ) ) );
		$this->assertStringContainsString( '"evil"', $verdict->reason() );
	}

	public function test_catastrophic_pattern_returns_quickly_without_a_warning_and_is_recorded(): void {
		UserAgentRule::reset_errors();
		$rule  = $this->rule( array( '/^(a+)+$/' ) );
		$start = microtime( true );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ua' => str_repeat( 'a', 500 ) . 'b' ) ) ) );
		$this->assertLessThan( 1.0, microtime( true ) - $start );
		$this->assertArrayHasKey( '/^(a+)+$/', UserAgentRule::last_errors() );
	}

	public function test_a_failing_pattern_does_not_block_visitors_or_hide_later_patterns(): void {
		UserAgentRule::reset_errors();
		$rule = $this->rule( array( '/(unclosed/', 'badbot' ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ua' => 'Mozilla/5.0' ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ua' => 'badbot/1.0' ) ) ) );
	}

	public function test_only_the_first_100_patterns_are_used(): void {
		$patterns   = array_map( static fn( $i ) => "pat{$i}x", range( 1, 100 ) );
		$patterns[] = 'late';
		$rule       = $this->rule( $patterns );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ua' => 'pat100x' ) ) ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ua' => 'late' ) ) ) );
	}
}
