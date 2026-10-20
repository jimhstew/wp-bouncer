<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\IpBlocklistRule;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\IpBlocklistRule
 * @covers \WPBouncer\Rules\AbstractRule
 */
final class IpBlocklistRuleTest extends TestCase {

	private function rule( array $ips, bool $enabled = true ): IpBlocklistRule {
		return new IpBlocklistRule(
			array(
				'enabled' => $enabled,
				'ips'     => $ips,
			)
		);
	}

	public function test_blocks_exact_ip(): void {
		$verdict = $this->rule( array( '203.0.113.10' ) )->inspect( Requests::make() );
		$this->assertNotNull( $verdict );
		$this->assertSame( 'ip_blocklist', $verdict->rule() );
		$this->assertSame( 403, $verdict->status() );
		$this->assertStringContainsString( '203.0.113.10', $verdict->reason() );
	}

	public function test_blocks_cidr_ranges(): void {
		$rule = $this->rule( array( '198.51.100.0/24', '2001:db8::/32' ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '198.51.100.99' ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '2001:db8:1::1' ) ) ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '198.51.101.1' ) ) ) );
	}

	public function test_empty_list_allows_everyone(): void {
		$this->assertNull( $this->rule( array() )->inspect( Requests::make() ) );
	}

	public function test_enabled_flag(): void {
		$this->assertTrue( $this->rule( array() )->is_enabled() );
		$this->assertFalse( $this->rule( array(), false )->is_enabled() );
	}
}
