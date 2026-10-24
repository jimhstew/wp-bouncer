<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;
use WPBouncer\Admin\RuleCatalog;
use WPBouncer\Settings;

/**
 * @covers \WPBouncer\Admin\RuleCatalog
 */
final class RuleCatalogTest extends TestCase {

	public function test_every_rule_in_the_defaults_is_in_exactly_one_category(): void {
		$ids = RuleCatalog::builtin_ids();
		$this->assertSame( array_values( array_unique( $ids ) ), $ids, 'no rule is listed twice' );

		$defaults = array_keys( Settings::defaults()['rules'] );
		sort( $defaults );
		$catalog = $ids;
		sort( $catalog );
		$this->assertSame( $defaults, $catalog, 'a new rule needs an entry in RuleCatalog::CATEGORIES (and the reverse)' );
	}

	public function test_slugs_are_in_the_owners_order_with_other_last(): void {
		$this->assertSame(
			array( 'block-lists', 'login-accounts', 'scanners-floods', 'payloads-hardening', 'other' ),
			RuleCatalog::slugs()
		);
		foreach ( RuleCatalog::slugs() as $slug ) {
			$this->assertMatchesRegularExpression( '/^[a-z-]+$/', $slug );
		}
	}

	public function test_category_of_and_is_builtin(): void {
		$this->assertSame( 'block-lists', RuleCatalog::category_of( 'country' ) );
		$this->assertSame( 'payloads-hardening', RuleCatalog::category_of( 'uploads_php' ) );
		$this->assertNull( RuleCatalog::category_of( 'custom' ) );
		$this->assertTrue( RuleCatalog::is_builtin( 'waf' ) );
		$this->assertFalse( RuleCatalog::is_builtin( '../x' ) );
		$this->assertFalse( RuleCatalog::is_builtin( '' ) );
	}

	public function test_the_external_rule_is_a_built_in_one(): void {
		foreach ( array_keys( RuleCatalog::EXTERNAL ) as $id ) {
			$this->assertTrue( RuleCatalog::is_builtin( $id ) );
		}
	}

	public function test_third_party_declarations_are_cleaned(): void {
		$out = RuleCatalog::third_party(
			array(
				'a' => array(
					'category' => 'login-accounts',
					'title'    => "  <script>alert(1)</script><b>Bots</b>\n on REST ",
				),
				'b' => array( 'category' => 'no-such-category' ),
				'c' => array( 'category' => array( 'x' ), 'title' => array( 'y' ) ),
				'd' => 'not an array',
			),
			array( 'a', 'b', 'c', 'd', 'e' )
		);

		$this->assertSame( 'login-accounts', $out['a']['category'] );
		$this->assertSame( 'alert(1)Bots on REST', $out['a']['title'] );
		$this->assertStringNotContainsString( '<', $out['a']['title'] );
		$this->assertSame( array( 'category' => 'other', 'title' => 'b' ), $out['b'] );
		$this->assertSame( array( 'category' => 'other', 'title' => 'c' ), $out['c'] );
		$this->assertSame( array( 'category' => 'other', 'title' => 'd' ), $out['d'] );
		$this->assertSame( array( 'category' => 'other', 'title' => 'e' ), $out['e'], 'no entry: other, titled by its id' );
	}

	public function test_a_title_is_capped_at_80_characters_and_an_empty_one_falls_back_to_the_id(): void {
		$out = RuleCatalog::third_party(
			array(
				'long'  => array( 'title' => str_repeat( 'é', 200 ) ),
				'empty' => array( 'title' => '  <b></b> ' ),
			),
			array( 'long', 'empty' )
		);
		$this->assertSame( 80, mb_strlen( $out['long']['title'] ) );
		$this->assertSame( 'empty', $out['empty']['title'] );
	}

	public function test_built_in_ids_and_ids_outside_the_chain_are_dropped(): void {
		$out = RuleCatalog::third_party(
			array(
				'waf'      => array( 'title' => 'Relabelled' ),
				'ghost'    => array( 'title' => 'Not running' ),
				'in_chain' => array( 'title' => 'Real' ),
			),
			array( 'waf', 'in_chain', 'in_chain', '' )
		);
		$this->assertSame( array( 'in_chain' ), array_keys( $out ) );
	}

	public function test_non_array_input_gives_the_registered_rules_under_other(): void {
		$this->assertSame( array(), RuleCatalog::third_party( 'x', array() ) );
		$this->assertSame( array(), RuleCatalog::third_party( null, array( 'waf' ) ) );
		$this->assertSame( 'other', RuleCatalog::third_party( 42, array( 'x' ) )['x']['category'] );
	}

	public function test_group_without_third_party_rules_has_the_four_categories(): void {
		$groups = RuleCatalog::group( array() );
		$this->assertSame( array( 'block-lists', 'login-accounts', 'scanners-floods', 'payloads-hardening' ), array_keys( $groups ) );
		$this->assertSame( RuleCatalog::CATEGORIES, $groups );
	}

	public function test_a_twelfth_rule_appears_after_the_built_in_ones_with_no_other_change(): void {
		$groups = RuleCatalog::group( array( 'extra' => array( 'category' => 'login-accounts', 'title' => 'Extra' ) ) );

		$this->assertSame( array( 'login_lockout', 'xmlrpc', 'user_enumeration', 'extra' ), $groups['login-accounts'] );
		$this->assertSame( RuleCatalog::CATEGORIES['block-lists'], $groups['block-lists'] );
		$this->assertArrayNotHasKey( 'other', $groups );
	}

	public function test_undeclared_rules_go_to_other_and_other_is_last(): void {
		$groups = RuleCatalog::group(
			array(
				'one' => array( 'category' => 'other', 'title' => 'one' ),
				'two' => array( 'category' => 'made-up', 'title' => 'two' ),
			)
		);
		$this->assertSame( 'other', array_key_last( $groups ) );
		$this->assertSame( array( 'one', 'two' ), $groups['other'] );
	}
}
