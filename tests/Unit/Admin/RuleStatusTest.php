<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;
use WPBouncer\Admin\RuleCatalog;
use WPBouncer\Admin\RuleStatus;
use WPBouncer\Settings;

/**
 * @covers \WPBouncer\Admin\RuleStatus
 */
final class RuleStatusTest extends TestCase {

	/**
	 * Facts for a healthy site, with overrides merged one level deep into the rules.
	 *
	 * @param array<string, mixed> $facts Fact overrides.
	 * @param array<string, mixed> $rules Rule setting overrides, by rule id.
	 * @return array<string, array{on: bool, flag: string|null, reasons: string[]}>
	 */
	private function status( array $facts = array(), array $rules = array() ): array {
		$settings = Settings::defaults()['rules'];
		foreach ( $rules as $id => $over ) {
			$settings[ $id ] = array_merge( $settings[ $id ], $over );
		}
		return RuleStatus::builtin(
			array_merge(
				array(
					'rules'         => $settings,
					'geo_rows'      => 1000,
					'geo_source'    => 'database',
					'disabled'      => false,
					'uploads_state' => array( 'ok' => true ),
					'uploads_probe' => 'protected',
				),
				$facts
			)
		);
	}

	public function test_every_built_in_rule_gets_a_status(): void {
		$this->assertSame( RuleCatalog::builtin_ids(), array_keys( array_intersect_key( array_flip( RuleCatalog::builtin_ids() ), $this->status() ) ) );
		$this->assertCount( count( RuleCatalog::builtin_ids() ), $this->status() );
	}

	public function test_on_is_the_saved_enabled_flag_and_a_healthy_rule_has_no_flag(): void {
		$s = $this->status( array(), array( 'xmlrpc' => array( 'enabled' => false ), 'waf' => array( 'enabled' => true ) ) );
		$this->assertSame( array( 'on' => false, 'flag' => null, 'reasons' => array() ), $s['xmlrpc'] );
		$this->assertSame( array( 'on' => true, 'flag' => null, 'reasons' => array() ), $s['waf'] );
	}

	public function test_country_on_without_a_geo_database_needs_attention(): void {
		$s = $this->status( array( 'geo_rows' => 0 ), array( 'country' => array( 'enabled' => true, 'countries' => array( 'DE' ) ) ) );
		$this->assertSame( RuleStatus::FLAG_ATTENTION, $s['country']['flag'] );
		$this->assertSame( array( RuleStatus::NO_GEO_DB ), $s['country']['reasons'] );
	}

	public function test_country_on_with_a_header_source_is_not_missing_a_database(): void {
		$s = $this->status( array( 'geo_rows' => 0, 'geo_source' => 'header' ), array( 'country' => array( 'enabled' => true, 'countries' => array( 'DE' ) ) ) );
		$this->assertNull( $s['country']['flag'] );
		$this->assertSame( array(), $s['country']['reasons'] );
	}

	public function test_country_with_an_untrusted_geo_header_is_flagged(): void {
		$s = $this->status(
			array( 'geo_rows' => 0, 'geo_source' => 'header', 'geo_header_untrusted' => true ),
			array( 'country' => array( 'enabled' => true, 'countries' => array( 'DE' ) ) )
		);
		$this->assertSame( array( RuleStatus::GEO_HEADER_UNTRUSTED ), $s['country']['reasons'] );
		$this->assertSame( RuleStatus::FLAG_ATTENTION, $s['country']['flag'] );
	}

	public function test_an_untrusted_geo_header_is_ignored_while_the_rule_is_off(): void {
		$s = $this->status( array( 'geo_header_untrusted' => true ), array( 'country' => array( 'enabled' => false ) ) );
		$this->assertNotContains( RuleStatus::GEO_HEADER_UNTRUSTED, $s['country']['reasons'] );
	}

	public function test_country_on_with_no_countries_in_block_mode_does_nothing(): void {
		$s = $this->status( array(), array( 'country' => array( 'enabled' => true, 'mode' => 'block', 'countries' => array() ) ) );
		$this->assertSame( array( RuleStatus::NO_COUNTRIES ), $s['country']['reasons'] );
		$this->assertSame( RuleStatus::FLAG_ATTENTION, $s['country']['flag'] );
	}

	public function test_block_mode_with_no_countries_still_works_when_it_blocks_unknown_ips(): void {
		$s = $this->status( array(), array( 'country' => array( 'enabled' => true, 'mode' => 'block', 'countries' => array(), 'block_unknown' => true ) ) );
		$this->assertSame( array(), $s['country']['reasons'] );
	}

	public function test_country_on_with_no_countries_in_allow_mode_is_not_applied(): void {
		$s = $this->status( array(), array( 'country' => array( 'enabled' => true, 'mode' => 'allow', 'countries' => array() ) ) );
		$this->assertSame( array( RuleStatus::ALLOW_LIST_EMPTY ), $s['country']['reasons'] );
	}

	public function test_country_off_without_a_geo_source_is_a_setup_hint_not_a_warning(): void {
		$s = $this->status( array( 'geo_rows' => 0 ), array( 'country' => array( 'enabled' => false ) ) );
		$this->assertSame( RuleStatus::FLAG_SETUP, $s['country']['flag'] );
		$this->assertSame( array( RuleStatus::SETUP_COUNTRY ), $s['country']['reasons'] );
		$this->assertFalse( $s['country']['on'] );
	}

	public function test_country_off_with_a_database_has_no_flag(): void {
		$s = $this->status( array(), array( 'country' => array( 'enabled' => false ) ) );
		$this->assertNull( $s['country']['flag'] );
	}

	public function test_uploads_removed_block_needs_attention(): void {
		$s = $this->status( array( 'uploads_state' => array( 'ok' => true, 'broken' => true ) ), array( 'uploads_php' => array( 'enabled' => true, 'htaccess' => true ) ) );
		$this->assertSame( array( RuleStatus::UPLOADS_BROKEN ), $s['uploads_php']['reasons'] );
		$this->assertSame( RuleStatus::FLAG_ATTENTION, $s['uploads_php']['flag'] );
	}

	public function test_uploads_failed_write_needs_attention(): void {
		$s = $this->status( array( 'uploads_state' => array( 'ok' => false ) ), array( 'uploads_php' => array( 'enabled' => true, 'htaccess' => true ) ) );
		$this->assertSame( array( RuleStatus::UPLOADS_WRITE_FAILED ), $s['uploads_php']['reasons'] );
	}

	public function test_no_uploads_reason_when_the_server_block_is_not_wanted(): void {
		$broken = array( 'ok' => false, 'broken' => true );
		$off    = $this->status( array( 'uploads_state' => $broken ), array( 'uploads_php' => array( 'enabled' => false, 'htaccess' => true ) ) );
		$nohtac = $this->status( array( 'uploads_state' => $broken ), array( 'uploads_php' => array( 'enabled' => true, 'htaccess' => false ) ) );
		$killed = $this->status( array( 'uploads_state' => $broken, 'disabled' => true ), array( 'uploads_php' => array( 'enabled' => true, 'htaccess' => true ) ) );
		$this->assertSame( array(), $off['uploads_php']['reasons'] );
		$this->assertSame( array(), $nohtac['uploads_php']['reasons'] );
		$this->assertSame( array(), $killed['uploads_php']['reasons'], 'WP_BOUNCER_DISABLE removes the wish for a block' );
	}

	public function test_no_uploads_state_yet_is_not_a_failure(): void {
		$s = $this->status( array( 'uploads_state' => null ), array( 'uploads_php' => array( 'enabled' => true, 'htaccess' => true ) ) );
		$this->assertSame( array(), $s['uploads_php']['reasons'] );
	}

	public function test_an_unprotected_test_result_needs_attention_only_while_the_rule_is_on(): void {
		$on  = $this->status( array( 'uploads_probe' => 'unprotected' ), array( 'uploads_php' => array( 'enabled' => true ) ) );
		$off = $this->status( array( 'uploads_probe' => 'unprotected' ), array( 'uploads_php' => array( 'enabled' => false ) ) );
		$ok  = $this->status( array( 'uploads_probe' => 'protected' ), array( 'uploads_php' => array( 'enabled' => true ) ) );
		$this->assertSame( array( RuleStatus::UPLOADS_UNPROTECTED ), $on['uploads_php']['reasons'] );
		$this->assertSame( array(), $off['uploads_php']['reasons'] );
		$this->assertSame( array(), $ok['uploads_php']['reasons'] );
	}

	public function test_rate_limiting_off_is_a_setup_hint_and_on_is_clean(): void {
		$off = $this->status( array(), array( 'rate_limit' => array( 'enabled' => false ) ) );
		$on  = $this->status( array(), array( 'rate_limit' => array( 'enabled' => true ) ) );
		$this->assertSame( RuleStatus::FLAG_SETUP, $off['rate_limit']['flag'] );
		$this->assertSame( array( RuleStatus::SETUP_RATE_LIMIT ), $off['rate_limit']['reasons'] );
		$this->assertNull( $on['rate_limit']['flag'] );
	}

	public function test_summarise_counts_on_total_and_attention_but_not_setup_hints(): void {
		$statuses = $this->status(
			array( 'geo_rows' => 0 ),
			array(
				'country'    => array( 'enabled' => true, 'countries' => array( 'DE' ) ),
				'rate_limit' => array( 'enabled' => false ),
			)
		);
		$sum = RuleStatus::summarise( RuleCatalog::group( array() ), $statuses );

		$this->assertSame( 3, $sum['block-lists']['total'] );
		$this->assertSame( 1, $sum['block-lists']['attention'], 'country: no geo database' );
		$this->assertSame( 0, $sum['scanners-floods']['attention'], 'rate limiting is a setup hint' );
		$this->assertSame( 2, $sum['scanners-floods']['on'] );
	}

	public function test_summarise_includes_third_party_rules_and_skips_unknown_ids(): void {
		$groups   = array( 'other' => array( 'mine', 'gone' ) );
		$statuses = array( 'mine' => array( 'on' => true, 'flag' => null ) );
		$this->assertSame( array( 'other' => array( 'on' => 1, 'total' => 1, 'attention' => 0 ) ), RuleStatus::summarise( $groups, $statuses ) );
	}

	public function test_totals_add_up_the_categories(): void {
		$statuses = $this->status( array(), array( 'xmlrpc' => array( 'enabled' => false ) ) );
		$totals   = RuleStatus::totals( RuleCatalog::group( array() ), $statuses );
		$on       = count( array_filter( array_column( $statuses, 'on' ) ) );
		$this->assertSame( array( 'on' => $on, 'total' => 11, 'attention' => 0 ), $totals );
	}
}
