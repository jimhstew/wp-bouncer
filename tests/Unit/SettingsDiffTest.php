<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPBouncer\Settings;
use WPBouncer\SettingsDiff;

/**
 * @covers \WPBouncer\SettingsDiff
 */
final class SettingsDiffTest extends TestCase {

	/** @return array<string, mixed> */
	private function base(): array {
		return Settings::defaults();
	}

	public function test_identical_settings_have_no_changes(): void {
		$this->assertSame( array(), SettingsDiff::changes( $this->base(), $this->base() ) );
	}

	public function test_a_nested_change_is_a_dotted_path(): void {
		$new                                      = $this->base();
		$new['rules']['login_lockout']['enabled'] = false;

		$this->assertSame( array( 'rules.login_lockout.enabled' ), SettingsDiff::changes( $this->base(), $new ) );
	}

	public function test_several_changes_are_sorted_and_unique(): void {
		$new                                      = $this->base();
		$new['mode']                              = 'monitor';
		$new['rules']['xmlrpc']['mode']           = 'pingback_only';
		$new['rules']['login_lockout']['enabled'] = false;

		$this->assertSame(
			array( 'mode', 'rules.login_lockout.enabled', 'rules.xmlrpc.mode' ),
			SettingsDiff::changes( $this->base(), $new )
		);
	}

	public function test_a_list_counts_as_one_path_and_values_are_not_named(): void {
		$new                    = $this->base();
		$new['allowlist']       = array( '198.51.100.1', '198.51.100.2' );
		$new['trusted_proxies'] = array( '10.0.0.1' );
		$old                    = $this->base();
		$old['allowlist']       = array( '203.0.113.5' );

		$changes = SettingsDiff::changes( $old, $new );

		$this->assertSame( array( 'allowlist', 'trusted_proxies' ), $changes );
		$this->assertStringNotContainsString( '198.51', implode( ',', $changes ) );
	}

	public function test_a_list_that_only_changes_order_is_a_change(): void {
		$old              = $this->base();
		$old['allowlist'] = array( '198.51.100.1', '198.51.100.2' );
		$new              = $old;
		$new['allowlist'] = array( '198.51.100.2', '198.51.100.1' );

		$this->assertSame( array( 'allowlist' ), SettingsDiff::changes( $old, $new ) );
	}

	public function test_a_nested_list_is_one_path(): void {
		$new                                 = $this->base();
		$new['rules']['ip_blocklist']['ips'] = array( '198.51.100.9', '198.51.100.10' );

		$this->assertSame( array( 'rules.ip_blocklist.ips' ), SettingsDiff::changes( $this->base(), $new ) );
	}

	public function test_a_key_added_or_removed_is_a_change(): void {
		$new                  = $this->base();
		$new['alerts']['new'] = true;

		$this->assertSame( array( 'alerts.new' ), SettingsDiff::changes( $this->base(), $new ) );
		$this->assertSame( array( 'alerts.new' ), SettingsDiff::changes( $new, $this->base() ) );
	}

	public function test_a_type_change_is_a_change(): void {
		$old = array( 'a' => 1 );
		$new = array( 'a' => '1' );

		$this->assertSame( array( 'a' ), SettingsDiff::changes( $old, $new ) );
	}

	/** @param array<string, mixed> $after */
	private function risky_of( array $after, ?array $before = null ): array {
		$before = $before ?? $this->base();
		return SettingsDiff::risky( SettingsDiff::changes( $before, $after ), $before, $after );
	}

	public function test_risky_keeps_the_top_level_security_settings(): void {
		$new                    = $this->base();
		$new['ip_source']       = 'x_real_ip';
		$new['allowlist']       = array( '198.51.100.1' );
		$new['trusted_proxies'] = array( '10.0.0.1' );
		$new['geo_source']      = 'header';
		$new['geo_header']      = 'X-Country';
		$new['block_message']   = 'Go away';

		$this->assertSame( array( 'allowlist', 'geo_header', 'geo_source', 'ip_source', 'trusted_proxies' ), $this->risky_of( $new ) );
	}

	public function test_mode_is_risky_only_when_it_leaves_enforce(): void {
		$monitor         = $this->base();
		$monitor['mode'] = 'monitor';

		$this->assertSame( array( 'mode' ), $this->risky_of( $monitor ) );
		$this->assertSame( array(), $this->risky_of( $this->base(), $monitor ), 'back to enforce is fine' );
	}

	public function test_alert_settings_are_risky(): void {
		$new                               = $this->base();
		$new['alerts']['enabled']          = false;
		$new['alerts']['firewall_changes'] = false;
		$new['alerts']['recipients']       = array( 'x@example.org' );
		$new['alerts']['plugin_updates']   = true;

		$this->assertSame( array( 'alerts.enabled', 'alerts.firewall_changes', 'alerts.recipients' ), $this->risky_of( $new ) );
	}

	public function test_any_rule_boolean_going_true_to_false_is_risky_but_not_false_to_true(): void {
		$off                                      = $this->base();
		$off['rules']['login_lockout']['enabled'] = false;
		$off['rules']['waf']['sqli']              = false;
		$this->assertSame( array( 'rules.login_lockout.enabled', 'rules.waf.sqli' ), $this->risky_of( $off ) );

		$this->assertSame( array(), $this->risky_of( $this->base(), $off ), 'switching on is not risky' );
	}

	public function test_country_changes_are_risky(): void {
		$new                                  = $this->base();
		$new['rules']['country']['mode']      = 'allow';
		$new['rules']['country']['countries'] = array( 'NL' );

		$this->assertSame( array( 'rules.country.countries', 'rules.country.mode' ), $this->risky_of( $new ) );
	}

	public function test_xmlrpc_mode_is_risky(): void {
		$new                            = $this->base();
		$new['rules']['xmlrpc']['mode'] = 'pingback_only';

		$this->assertSame( array( 'rules.xmlrpc.mode' ), $this->risky_of( $new ) );
	}

	public function test_waf_exclusions_are_risky_only_when_they_grow(): void {
		$more                                    = $this->base();
		$more['rules']['waf']['excluded_params'] = array( 'content' );
		$this->assertSame( array( 'rules.waf.excluded_params' ), $this->risky_of( $more ) );

		$this->assertSame( array(), $this->risky_of( $this->base(), $more ), 'removing exclusions tightens the WAF' );
	}

	public function test_shrinking_blocklist_and_patterns_are_risky(): void {
		$old                                    = $this->base();
		$old['rules']['ip_blocklist']['ips']    = array( '198.51.100.1', '198.51.100.2' );
		$old['rules']['user_agent']['patterns'] = array( 'a', 'b' );
		$new                                    = $old;
		$new['rules']['ip_blocklist']['ips']    = array( '198.51.100.1' );
		$new['rules']['user_agent']['patterns'] = array();

		$this->assertSame( array( 'rules.ip_blocklist.ips', 'rules.user_agent.patterns' ), $this->risky_of( $new, $old ) );

		$grown                                 = $old;
		$grown['rules']['ip_blocklist']['ips'] = array( '198.51.100.1', '198.51.100.2', '198.51.100.3' );
		$this->assertSame( array(), $this->risky_of( $grown, $old ), 'a longer blocklist is not risky' );

		$swapped                                 = $old;
		$swapped['rules']['ip_blocklist']['ips'] = array( '198.51.100.8', '198.51.100.9' );
		$this->assertSame( array(), $this->risky_of( $swapped, $old ), 'same length is not a shrink' );
	}

	public function test_lowering_a_retention_period_is_risky_and_raising_it_is_not(): void {
		$low                                = $this->base();
		$low['log_retention_days']          = 1;
		$low['traffic']['retention_days']   = 1;
		$this->assertSame( array( 'log_retention_days', 'traffic.retention_days' ), $this->risky_of( $low ) );

		$this->assertSame( array(), $this->risky_of( $this->base(), $low ), 'a longer retention only keeps more' );
	}

	public function test_thresholds_and_texts_are_log_only(): void {
		$new = $this->base();
		$new['rules']['login_lockout']['max_attempts'] = 50;
		$new['rules']['rate_limit']['max_requests']    = 5000;
		$new['block_message']                          = 'Go away';

		$this->assertNotEmpty( SettingsDiff::changes( $this->base(), $new ) );
		$this->assertSame( array(), $this->risky_of( $new ) );
	}

	public function test_describe_puts_the_actor_and_risky_paths_first(): void {
		$this->assertSame(
			'Settings changed by eve: allowlist, mode; also: block_message',
			SettingsDiff::describe( 'eve', array( 'allowlist', 'block_message', 'mode' ), array( 'allowlist', 'mode' ) )
		);
		$this->assertSame( 'Settings changed by eve: block_message', SettingsDiff::describe( 'eve', array( 'block_message' ), array() ) );
	}

	public function test_describe_cuts_only_the_also_list_when_many_keys_changed(): void {
		$others = array();
		for ( $i = 0; $i < 60; $i++ ) {
			$others[] = 'rules.some_rule.setting_number_' . $i;
		}

		$reason = SettingsDiff::describe( 'eve', array_merge( array( 'allowlist', 'mode' ), $others ), array( 'allowlist', 'mode' ) );

		$this->assertLessThanOrEqual( 255, strlen( $reason ) );
		$this->assertStringStartsWith( 'Settings changed by eve: allowlist, mode; also: rules.some_rule.setting_number_0', $reason );
		$this->assertStringEndsWith( '...', $reason );
	}
}
