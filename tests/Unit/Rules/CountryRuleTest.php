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

	private function rule( array $overrides = array(), bool $paused = false ): CountryRule {
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
			$this->geo,
			$paused
		);
	}

	public function test_paused_rule_gives_no_verdict_even_with_block_unknown(): void {
		$rule = $this->rule( array( 'block_unknown' => true ), true );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '1.1.1.1' ) ) ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '9.9.9.9' ) ) ) );
	}

	public function test_blocks_country_matches_the_firewall_decision(): void {
		$block = $this->rule();
		$this->assertTrue( $block->blocks_country( 'RU' ) );
		$this->assertTrue( $block->blocks_country( 'T1' ) );
		$this->assertFalse( $block->blocks_country( 'US' ) );

		$allow = $this->rule( array( 'mode' => 'allow', 'countries' => array( 'US' ) ) );
		$this->assertFalse( $allow->blocks_country( 'US' ) );
		$this->assertTrue( $allow->blocks_country( 'RU' ) );

		foreach ( array( '1.1.1.1' => 'RU', '2.2.2.2' => 'US', '3.3.3.3' => 'T1' ) as $ip => $code ) {
			foreach ( array( $block, $allow ) as $rule ) {
				$verdict = $rule->inspect( Requests::make( array( 'ip' => $ip ) ) );
				$this->assertSame( null !== $verdict, $rule->blocks_country( $code ), $code );
			}
		}
	}

	public function test_blocks_country_is_false_when_off_paused_or_an_empty_allow_list(): void {
		$this->assertFalse( $this->rule( array( 'enabled' => false ) )->blocks_country( 'RU' ) );
		$this->assertFalse( $this->rule( array(), true )->blocks_country( 'RU' ) );
		$this->assertFalse( $this->rule( array( 'mode' => 'allow', 'countries' => array() ) )->blocks_country( 'RU' ) );
	}

	public function test_login_only_follows_the_scope(): void {
		$this->assertFalse( $this->rule()->login_only() );
		$this->assertTrue( $this->rule( array( 'scope' => 'login' ) )->login_only() );
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

	/** RT-04: a request from the server itself has no geography; a loopback proxy's visitors do not escape block_unknown. */
	public function test_only_local_requests_skip_the_country_check(): void {
		$rule = $this->rule( array( 'block_unknown' => true ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '127.0.0.1', 'local' => true ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '127.0.0.1' ) ) ), 'loopback IP but not local' );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '9.9.9.9' ) ) ) );
	}

	/** NEW-5: a trusted loopback proxy forwarding a refused header value must not skip the country rule. */
	public function test_a_refused_forwarded_header_still_gets_the_country_decision(): void {
		$resolver = new \WPBouncer\Firewall\IpResolver( 'x_real_ip', array( '127.0.0.1' ) );
		$server   = array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '10.0.0.1' );
		$request  = Requests::make( array( 'ip' => $resolver->resolve( $server ), 'local' => $resolver->is_local_request( $server ), 'server' => $server ) );
		$rule     = $this->rule( array( 'mode' => 'allow', 'countries' => array( 'DE' ), 'block_unknown' => true ) );

		$this->assertNotNull( $rule->inspect( $request ) );
	}
}
