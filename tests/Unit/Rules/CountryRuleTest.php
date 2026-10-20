<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\CountryRule;
use WPBouncer\Tests\Support\FakeGeo;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\CountryRule
 */
final class CountryRuleTest extends TestCase {

	private FakeGeo $geo;

	protected function setUp(): void {
		$this->geo = new FakeGeo(
			array(
				'1.1.1.1' => 'RU',
				'2.2.2.2' => 'US',
				'3.3.3.3' => 'T1',
			)
		);
	}

	private function rule( array $overrides = array() ): CountryRule {
		return new CountryRule(
			array_merge(
				array(
					'enabled'       => true,
					'mode'          => 'block',
					'countries'     => array( 'RU', 'T1' ),
					'block_unknown' => false,
					'scope'         => 'site',
				),
				$overrides
			),
			$this->geo
		);
	}

	public function test_block_mode_blocks_listed_countries(): void {
		$verdict = $this->rule()->inspect( Requests::make( array( 'ip' => '1.1.1.1' ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'RU', $verdict->reason() );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'ip' => '3.3.3.3' ) ) ), 'Tor pseudo-country' );
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'ip' => '2.2.2.2' ) ) ) );
	}

	public function test_allow_mode_blocks_everyone_else(): void {
		$rule = $this->rule(
			array(
				'mode'      => 'allow',
				'countries' => array( 'US' ),
			)
		);
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '2.2.2.2' ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '1.1.1.1' ) ) ) );
	}

	public function test_allow_mode_with_empty_list_is_treated_as_disabled(): void {
		$rule = $this->rule(
			array(
				'mode'      => 'allow',
				'countries' => array(),
			)
		);
		$this->assertFalse( $rule->is_enabled(), 'must not lock out the whole world' );
	}

	public function test_unknown_country(): void {
		$req = Requests::make( array( 'ip' => '9.9.9.9' ) );
		$this->assertNull( $this->rule()->inspect( $req ) );
		$this->assertNotNull( $this->rule( array( 'block_unknown' => true ) )->inspect( $req ) );
		// Unknown counts as "not on the allow list" only when block_unknown is set.
		$this->assertNull(
			$this->rule(
				array(
					'mode'      => 'allow',
					'countries' => array( 'US' ),
				)
			)->inspect( $req )
		);
	}

	public function test_login_scope_ignores_public_pages(): void {
		$rule = $this->rule( array( 'scope' => 'login' ) );

		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '1.1.1.1', 'uri' => '/blog/hello-world/' ) ) ) );
		$this->assertSame( 0, $this->geo->lookups, 'no geo lookup needed for out-of-scope requests' );

		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '1.1.1.1', 'uri' => '/wp-login.php' ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '1.1.1.1', 'uri' => '/xmlrpc.php' ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '1.1.1.1', 'uri' => '/wp-admin/' ) ) ) );
	}
}
