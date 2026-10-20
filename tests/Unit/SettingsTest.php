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
}
