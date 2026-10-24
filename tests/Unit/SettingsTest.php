<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPBouncer\Settings;

/**
 * @covers \WPBouncer\Settings
 */
final class SettingsTest extends TestCase {

	public function test_defaults_survive_their_own_sanitisation(): void {
		$this->assertSame( Settings::defaults(), Settings::sanitize( Settings::defaults() ) );
	}

	public function test_every_rule_has_an_enabled_switch(): void {
		foreach ( Settings::defaults()['rules'] as $id => $rule ) {
			$this->assertArrayHasKey( 'enabled', $rule, $id );
			$this->assertIsBool( $rule['enabled'], $id );
		}
	}

	public function test_partial_stored_values_are_filled_from_defaults(): void {
		$s = new Settings(
			array(
				'mode'  => 'monitor',
				'rules' => array( 'waf' => array( 'xss' => false ) ),
				'bogus' => 'dropped',
			)
		);
		$this->assertTrue( $s->is_monitor_mode() );
		$this->assertFalse( $s->rule( 'waf' )['xss'] );
		$this->assertTrue( $s->rule( 'waf' )['sqli'] );
		$this->assertSame( 5, $s->rule( 'login_lockout' )['max_attempts'] );
		$this->assertNull( $s->get( 'bogus' ) );
		$this->assertFalse( $s->rule( 'not_a_rule' )['enabled'] );
	}

	public function test_invalid_choices_fall_back_to_defaults(): void {
		$out = Settings::sanitize(
			array(
				'mode'      => 'yolo',
				'ip_source' => 'HTTP_EVIL',
				'rules'     => array(
					'xmlrpc'  => array( 'mode' => 'nope' ),
					'country' => array( 'mode' => 'x', 'scope' => 'y' ),
				),
			)
		);
		$this->assertSame( 'enforce', $out['mode'] );
		$this->assertSame( 'remote_addr', $out['ip_source'] );
		$this->assertSame( 'block_all', $out['rules']['xmlrpc']['mode'] );
		$this->assertSame( 'block', $out['rules']['country']['mode'] );
		$this->assertSame( 'site', $out['rules']['country']['scope'] );
	}

	public function test_ip_lists_from_textarea_keep_only_valid_entries(): void {
		$out = Settings::sanitize(
			array(
				'allowlist' => "10.0.0.1\n  192.168.0.0/16 ,2001:db8::/32\r\nnot-an-ip\n10.0.0.1\n300.1.1.1",
			)
		);
		$this->assertSame( array( '10.0.0.1', '192.168.0.0/16', '2001:db8::/32' ), $out['allowlist'] );
	}

	public function test_numbers_are_clamped(): void {
		$out = Settings::sanitize(
			array(
				'log_retention_days' => '9999',
				'rules'              => array(
					'login_lockout' => array(
						'max_attempts'    => '0',
						'window_minutes'  => 'abc',
						'lockout_minutes' => '-5',
					),
				),
			)
		);
		$this->assertSame( 365, $out['log_retention_days'] );
		$this->assertSame( 1, $out['rules']['login_lockout']['max_attempts'] );
		$this->assertSame( 15, $out['rules']['login_lockout']['window_minutes'], 'non-numeric uses the default' );
		$this->assertSame( 1, $out['rules']['login_lockout']['lockout_minutes'] );
	}

	public function test_countries_are_validated(): void {
		$out = Settings::sanitize( array( 'rules' => array( 'country' => array( 'countries' => array( 'ru', 'CN', 'ZZ', 'XX', 'T1', 'CN', '<script>' ) ) ) ) );
		$this->assertSame( array( 'RU', 'CN', 'T1' ), $out['rules']['country']['countries'] );
	}

	public function test_invalid_ua_regex_is_dropped(): void {
		$out = Settings::sanitize( array( 'rules' => array( 'user_agent' => array( 'patterns' => "good\n/broken(/\n/^ok$/i\ngood" ) ) ) );
		$this->assertSame( array( 'good', '/^ok$/i' ), $out['rules']['user_agent']['patterns'] );
	}

	public function test_ua_patterns_keep_only_the_first_100(): void {
		$lines = implode( "\n", array_map( static fn( $i ) => "bot{$i}", range( 1, 130 ) ) );
		$out   = Settings::sanitize( array( 'rules' => array( 'user_agent' => array( 'patterns' => $lines ) ) ) );
		$this->assertCount( 100, $out['rules']['user_agent']['patterns'] );
		$this->assertSame( 'bot100', $out['rules']['user_agent']['patterns'][99] );
	}

	public function test_ua_patterns_keep_commas(): void {
		$out = Settings::sanitize( array( 'rules' => array( 'user_agent' => array( 'patterns' => 'Foo, Bar' ) ) ) );
		$this->assertSame( array( 'Foo, Bar' ), $out['rules']['user_agent']['patterns'] );
	}

	public function test_banned_usernames_are_lowercased_and_unique(): void {
		$out = Settings::sanitize( array( 'rules' => array( 'login_lockout' => array( 'banned_usernames' => "Admin\nadmin\n ROOT " ) ) ) );
		$this->assertSame( array( 'admin', 'root' ), $out['rules']['login_lockout']['banned_usernames'] );
	}

	public function test_block_message_is_plain_text(): void {
		$out = Settings::sanitize( array( 'block_message' => '<b>Go</b>   <script>x</script>away' ) );
		$this->assertSame( 'Go xaway', $out['block_message'] );
		$this->assertSame( Settings::defaults()['block_message'], Settings::sanitize( array( 'block_message' => '   ' ) )['block_message'] );
	}

	public function test_geo_header_name_is_restricted(): void {
		$this->assertSame( 'GEOIP_COUNTRY_CODE', Settings::sanitize( array( 'geo_header' => 'GEOIP_COUNTRY_CODE' ) )['geo_header'] );
		$this->assertSame( 'CF-IPCountry', Settings::sanitize( array( 'geo_header' => 'bad header!' ) )['geo_header'] );
	}

	public function test_bool_parsing(): void {
		$out = Settings::sanitize(
			array(
				'rules' => array(
					'waf' => array(
						'enabled' => '1',
						'sqli'    => '0',
						'xss'     => 'off',
						'traversal' => 'yes',
					),
				),
			)
		);
		$this->assertTrue( $out['rules']['waf']['enabled'] );
		$this->assertFalse( $out['rules']['waf']['sqli'] );
		$this->assertFalse( $out['rules']['waf']['xss'] );
		$this->assertTrue( $out['rules']['waf']['traversal'] );
		$this->assertFalse( $out['rules']['waf']['code_injection'], 'missing checkbox = off' );
	}

	public function test_apply_form_only_touches_the_submitted_tab(): void {
		$current                                   = Settings::defaults();
		$current['allowlist']                      = array( '10.0.0.1' );
		$current['rules']['country']['enabled']    = true;
		$current['rules']['country']['countries']  = array( 'RU' );

		// Rules tab submitted with only the WAF switched on: every other rule on that tab
		// goes off (unticked), but settings on other tabs are left alone.
		$out = Settings::apply_form( $current, array( 'rules' => array( 'waf' => array( 'enabled' => '1', 'sqli' => '1' ) ) ), 'rules' );

		$this->assertTrue( $out['rules']['waf']['enabled'] );
		$this->assertFalse( $out['rules']['xmlrpc']['enabled'] );
		$this->assertFalse( $out['rules']['login_lockout']['enabled'] );
		$this->assertSame( array( '10.0.0.1' ), $out['allowlist'], 'general tab untouched' );
		$this->assertTrue( $out['rules']['country']['enabled'], 'countries tab untouched' );
		$this->assertSame( array( 'RU' ), $out['rules']['country']['countries'] );
	}

	public function test_apply_form_countries_tab(): void {
		$out = Settings::apply_form(
			Settings::defaults(),
			array(
				'rules' => array(
					'country' => array(
						'enabled'   => '1',
						'mode'      => 'allow',
						'countries' => array( 'US', 'CA' ),
					),
				),
			),
			'countries'
		);
		$this->assertTrue( $out['rules']['country']['enabled'] );
		$this->assertSame( 'allow', $out['rules']['country']['mode'] );
		$this->assertSame( array( 'US', 'CA' ), $out['rules']['country']['countries'] );
		$this->assertTrue( $out['rules']['waf']['enabled'], 'rules tab untouched' );
	}

	public function test_apply_form_unknown_tab_changes_nothing(): void {
		$this->assertSame( Settings::defaults(), Settings::apply_form( Settings::defaults(), array( 'mode' => 'monitor' ), 'hacker' ) );
	}

	public function test_lines_helper(): void {
		$this->assertSame( array( 'a', 'b' ), Settings::lines( "a\r\n\n b \n" ) );
		$this->assertSame( array( 'a', 'b', 'c' ), Settings::lines( 'a, b c', true ) );
		$this->assertSame( array( 'x' ), Settings::lines( array( 'x', '', array( 'nested' ) ) ) );
	}

	public function test_new_protections_are_on_by_default(): void {
		$d = Settings::defaults();
		$this->assertTrue( $d['rules']['sensitive_files']['enabled'] );
		$this->assertTrue( $d['rules']['not_found']['enabled'] );
		$this->assertTrue( $d['rules']['uploads_php']['enabled'] );
		$this->assertTrue( $d['alerts']['enabled'] );
		$this->assertFalse( $d['alerts']['plugin_updates'], 'routine updates do not email by default' );
	}

	public function test_sites_upgrading_from_older_settings_get_the_new_defaults(): void {
		// A 1.1.0 option has no alerts block and none of the new rules.
		$s = new Settings( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) );
		$this->assertTrue( $s->rule( 'sensitive_files' )['enabled'] );
		$this->assertSame( 20, $s->rule( 'not_found' )['max_404'] );
		$this->assertTrue( $s->rule( 'uploads_php' )['htaccess'] );
		$this->assertSame( array(), $s->get( 'alerts' )['recipients'] );
		$this->assertTrue( $s->get( 'alerts' )['new_admin'] );
	}

	public function test_partial_alerts_are_filled_from_defaults(): void {
		$s = new Settings( array( 'alerts' => array( 'plugin_updates' => true ) ) );
		$this->assertTrue( $s->get( 'alerts' )['plugin_updates'] );
		$this->assertTrue( $s->get( 'alerts' )['plugin_changes'] );
	}

	public function test_alert_recipients_are_validated(): void {
		$out = Settings::sanitize( array( 'alerts' => array( 'recipients' => "Me@Example.org\nnot-an-email\nyou@example.net, me@example.org\n\"x\"\r\nbcc:@x" ) ) );
		$this->assertSame( array( 'me@example.org', 'you@example.net' ), $out['alerts']['recipients'] );

		$many = array();
		for ( $i = 0; $i < 15; $i++ ) {
			$many[] = "a{$i}@example.org";
		}
		$this->assertCount( 10, Settings::sanitize( array( 'alerts' => array( 'recipients' => $many ) ) )['alerts']['recipients'] );
	}

	public function test_new_rule_numbers_are_clamped(): void {
		$out = Settings::sanitize(
			array(
				'rules' => array(
					'sensitive_files' => array( 'ban_minutes' => -5 ),
					'not_found'       => array( 'max_404' => 1, 'window_seconds' => 999999, 'ban_minutes' => 'x' ),
				),
			)
		);
		$this->assertSame( 0, $out['rules']['sensitive_files']['ban_minutes'] );
		$this->assertSame( 3, $out['rules']['not_found']['max_404'] );
		$this->assertSame( 3600, $out['rules']['not_found']['window_seconds'] );
		$this->assertSame( 60, $out['rules']['not_found']['ban_minutes'] );
	}

	public function test_sensitive_file_extra_paths(): void {
		$out = Settings::sanitize( array( 'rules' => array( 'sensitive_files' => array( 'extra_paths' => "/Old-Admin/\n/\n/a\nhas space\n/old-admin/" ) ) ) );
		$this->assertSame( array( '/old-admin/' ), $out['rules']['sensitive_files']['extra_paths'] );
	}

	public function test_general_tab_owns_alerts_and_rules_tab_owns_new_rules(): void {
		$out = Settings::apply_form( Settings::defaults(), array( 'mode' => 'enforce' ), 'general' );
		$this->assertFalse( $out['alerts']['enabled'], 'unticked on the General tab' );
		$this->assertTrue( $out['rules']['uploads_php']['enabled'], 'rules tab untouched' );

		$out = Settings::apply_form( Settings::defaults(), array(), 'rules' );
		$this->assertFalse( $out['rules']['sensitive_files']['enabled'] );
		$this->assertFalse( $out['rules']['not_found']['enabled'] );
		$this->assertFalse( $out['rules']['uploads_php']['enabled'] );
		$this->assertTrue( $out['alerts']['enabled'], 'general tab untouched' );
	}

	public function test_traffic_log_is_off_by_default_and_kept_a_week(): void {
		$t = Settings::defaults()['traffic'];
		$this->assertFalse( $t['enabled'] );
		$this->assertSame( 7, $t['retention_days'] );
		$this->assertTrue( $t['skip_background'] );
		$this->assertTrue( ( new Settings( array() ) )->get( 'traffic' )['skip_background'], 'filled in for older settings' );
	}

	public function test_traffic_retention_is_at_most_a_week(): void {
		$this->assertSame( 7, Settings::sanitize( array( 'traffic' => array( 'retention_days' => 30 ) ) )['traffic']['retention_days'] );
		$this->assertSame( 1, Settings::sanitize( array( 'traffic' => array( 'retention_days' => 0 ) ) )['traffic']['retention_days'] );
		$this->assertSame( 3, Settings::sanitize( array( 'traffic' => array( 'retention_days' => '3' ) ) )['traffic']['retention_days'] );
	}

	public function test_traffic_tab_owns_only_traffic_settings(): void {
		$out = Settings::apply_form( Settings::defaults(), array( 'traffic' => array( 'enabled' => '1', 'retention_days' => '2' ) ), 'traffic' );
		$this->assertTrue( $out['traffic']['enabled'] );
		$this->assertSame( 2, $out['traffic']['retention_days'] );
		$this->assertFalse( $out['traffic']['skip_background'], 'unticked on that tab' );
		$this->assertTrue( $out['alerts']['enabled'], 'general tab untouched' );

		$out = Settings::apply_form( $out, array(), 'general' );
		$this->assertTrue( $out['traffic']['enabled'], 'general tab leaves traffic alone' );
	}

	/** RT-24 */
	public function test_sanitize_drops_over_broad_proxies_and_allowlist_entries(): void {
		$in  = array(
			'trusted_proxies' => "0.0.0.0/0\n::/0\n10.0.0.0/7\n10.0.0.0/8\n192.0.2.5",
			'allowlist'       => "0.0.0.0/0\n198.51.100.0/24",
		);
		$out = Settings::sanitize( $in );
		$this->assertSame( array( '10.0.0.0/8', '192.0.2.5' ), $out['trusted_proxies'] );
		$this->assertSame( array( '198.51.100.0/24' ), $out['allowlist'] );
	}

	public function test_sanitize_keeps_broad_ranges_in_the_blocklist(): void {
		$in  = array( 'rules' => array( 'ip_blocklist' => array( 'enabled' => true, 'ips' => "0.0.0.0/1\n198.51.100.9" ) ) );
		$out = Settings::sanitize( $in );
		$this->assertSame( array( '0.0.0.0/1', '198.51.100.9' ), $out['rules']['ip_blocklist']['ips'] );
	}

	public function test_dropped_broad_ranges_names_what_would_be_removed(): void {
		$in = array(
			'trusted_proxies' => "0.0.0.0/0\n10.0.0.0/8",
			'allowlist'       => array( '::/0', '0.0.0.0/0', '203.0.113.5' ),
		);
		$this->assertSame( array( '0.0.0.0/0', '::/0' ), Settings::dropped_broad_ranges( $in ) );
		$this->assertSame( array(), Settings::dropped_broad_ranges( array( 'trusted_proxies' => '10.0.0.0/8' ) ) );
	}

	/** The save trap: IP settings belong to the General tab only. */
	public function test_ip_settings_survive_saving_other_tabs(): void {
		$current                    = Settings::defaults();
		$current['ip_source']       = 'x_real_ip';
		$current['trusted_proxies'] = array( '127.0.0.1' );

		$rules = Settings::apply_form( $current, array( 'rules' => array( 'waf' => array( 'enabled' => '1' ) ) ), 'rules' );
		$this->assertSame( 'x_real_ip', $rules['ip_source'] );
		$this->assertSame( array( '127.0.0.1' ), $rules['trusted_proxies'] );

		$countries = Settings::apply_form( $current, array( 'rules' => array( 'country' => array( 'enabled' => '1' ) ) ), 'countries' );
		$this->assertSame( 'x_real_ip', $countries['ip_source'] );
		$this->assertSame( array( '127.0.0.1' ), $countries['trusted_proxies'] );

		$traffic = Settings::apply_form( $current, array( 'traffic' => array( 'enabled' => '1' ) ), 'traffic' );
		$this->assertSame( 'x_real_ip', $traffic['ip_source'] );
		$this->assertSame( array( '127.0.0.1' ), $traffic['trusted_proxies'] );

		$this->assertContains( 'ip_source', Settings::TAB_FIELDS['general'] );
		$this->assertContains( 'trusted_proxies', Settings::TAB_FIELDS['general'] );
	}

	public function test_general_tab_saves_a_header_source_with_no_proxies(): void {
		$out = Settings::apply_form( Settings::defaults(), array( 'ip_source' => 'x_real_ip', 'trusted_proxies' => '' ), 'general' );
		$this->assertSame( 'x_real_ip', $out['ip_source'], 'saving is allowed; the admin gets a warning' );
		$this->assertSame( array(), $out['trusted_proxies'] );
	}

	/** NEW-2 */
	public function test_sanitize_drops_ipv6_forms_of_the_whole_ipv4_space(): void {
		$wide = "::ffff:0:0/96\n::/80\n::ffff:0.0.0.0/100\n::ffff:10.0.0.0/104";
		$out  = Settings::sanitize( array( 'trusted_proxies' => $wide, 'allowlist' => $wide ) );
		$this->assertSame( array( '::ffff:10.0.0.0/104' ), $out['trusted_proxies'] );
		$this->assertSame( array( '::ffff:10.0.0.0/104' ), $out['allowlist'] );
	}
}
