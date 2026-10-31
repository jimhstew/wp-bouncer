<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Audit;

use PHPUnit\Framework\TestCase;
use WPBouncer\Audit\DriftDetector;
use WPBouncer\Audit\DriftVerdict;
use WPBouncer\Audit\FingerprintKey;
use WPBouncer\Audit\FingerprintRecord;
use WPBouncer\Audit\SettingsFingerprint;
use WPBouncer\Settings;
use WPBouncer\SettingsDiff;

/**
 * The pure core of WPB-12: leaves, fingerprint, detector, verdict.
 *
 * @covers \WPBouncer\Audit\DriftDetector
 * @covers \WPBouncer\Audit\DriftVerdict
 * @covers \WPBouncer\Audit\FingerprintKey
 * @covers \WPBouncer\Audit\FingerprintRecord
 * @covers \WPBouncer\Audit\SettingsFingerprint
 * @covers \WPBouncer\SettingsDiff::leaves
 */
final class DriftTest extends TestCase {

	private function key( string $secret = 'secret-one', int $blog = 1 ): FingerprintKey {
		return new FingerprintKey( $secret, $blog );
	}

	/** @return array<string, mixed> */
	private function settings( array $over = array() ): array {
		return array_replace_recursive( Settings::defaults(), $over );
	}

	private function fp( mixed $raw, ?FingerprintKey $key = null, bool $present = true, int $logged = 0 ): FingerprintRecord {
		return SettingsFingerprint::record( $raw, $present, $key ?? $this->key(), $logged );
	}

	/* ---------- SettingsDiff::leaves ---------- */

	public function test_lists_are_one_leaf_and_unknown_keys_are_ignored(): void {
		$raw            = $this->settings( array( 'allowlist' => array( '1.2.3.4', '5.6.7.8' ) ) );
		$raw['junk']    = 'x';
		$raw['rules']['waf']['junk'] = 'y';
		$leaves         = SettingsDiff::leaves( $raw );

		$this->assertSame( array( true, array( '1.2.3.4', '5.6.7.8' ) ), $leaves['allowlist'] );
		$this->assertArrayNotHasKey( 'junk', $leaves );
		$this->assertArrayNotHasKey( 'rules.waf.junk', $leaves );
		$this->assertArrayNotHasKey( 'rules.waf', $leaves );
		$this->assertArrayHasKey( 'rules.waf.enabled', $leaves );
	}

	public function test_missing_paths_and_non_array_parents_are_absent(): void {
		$raw = $this->settings();
		unset( $raw['mode'] );
		$raw['rules'] = 'broken';
		$leaves       = SettingsDiff::leaves( $raw );

		$this->assertSame( array( false, null ), $leaves['mode'] );
		$this->assertSame( array( false, null ), $leaves['rules.waf.enabled'] );
		foreach ( SettingsDiff::leaves( false ) as $leaf ) {
			$this->assertFalse( $leaf[0] );
		}
	}

	/* ---------- fingerprint ---------- */

	public function test_key_order_and_junk_keys_make_no_difference(): void {
		$a = $this->settings();
		$b = array_reverse( $a, true );
		$b['rules']['junk'] = 1;
		$this->assertTrue( $this->fp( $a )->equals( $this->fp( $b ) ) );
	}

	public function test_changing_one_leaf_changes_exactly_that_mac(): void {
		$a = $this->fp( $this->settings() );
		$b = $this->fp( $this->settings( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) ) );
		$diff = array_keys( array_diff_assoc( $a->leaves, $b->leaves ) );
		$this->assertSame( array( 'rules.waf.enabled' ), $diff );
	}

	public function test_types_matter_and_nested_values_are_stable(): void {
		$a = $this->fp( $this->settings( array( 'rules' => array( 'waf' => array( 'enabled' => '1' ) ) ) ) );
		$b = $this->fp( $this->settings( array( 'rules' => array( 'waf' => array( 'enabled' => true ) ) ) ) );
		$this->assertFalse( $a->equals( $b ) );

		$x = $this->settings();
		$x['allowlist'] = array( 'k' => array( 'b' => 1, 'a' => 2 ), 'j' => (object) array( 'z' => 1 ) );
		$y = $this->settings();
		$y['allowlist'] = array( 'j' => (object) array( 'z' => 1 ), 'k' => array( 'a' => 2, 'b' => 1 ) );
		$this->assertTrue( $this->fp( $x )->equals( $this->fp( $y ) ) );
	}

	public function test_invalid_utf8_falls_back_and_is_stable(): void {
		$this->assertStringStartsWith( 'p:', SettingsFingerprint::canonical( true, "bad\xB1" ) );
		$s = $this->settings();
		$s['allowlist'] = array( "bad\xB1" );
		$this->assertTrue( $this->fp( $s )->equals( $this->fp( $s ) ) );
	}

	public function test_a_list_that_only_changes_order_is_different(): void {
		$a = $this->fp( $this->settings( array( 'allowlist' => array( 'a', 'b' ) ) ) );
		$b = $this->fp( $this->settings( array( 'allowlist' => array( 'b', 'a' ) ) ) );
		$this->assertFalse( $a->equals( $b ) );
	}

	public function test_the_record_contains_no_value(): void {
		$s = $this->settings(
			array(
				'allowlist' => array( '198.51.100.77' ),
				'alerts'    => array( 'recipients' => array( 'secret.person@example.org' ) ),
				'rules'     => array( 'waf' => array( 'block_message' => 'Zebra-Quartz-Message' ) ),
			)
		);
		$json = $this->fp( $s )->to_json();
		foreach ( array( '198.51.100.77', 'secret.person', 'Zebra-Quartz' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, $json );
		}
		$this->assertMatchesRegularExpression( '/^[\x20-\x7e]+$/', $json );
	}

	public function test_record_round_trips_and_rejects_junk(): void {
		$rec = $this->fp( $this->settings(), null, true, 123 );
		$back = FingerprintRecord::from_stored( $rec->to_json() );
		$this->assertNotNull( $back );
		$this->assertTrue( $back->seal_valid( $this->key() ) );
		$this->assertSame( 123, $back->logged );

		foreach ( array( false, null, '', 'x', '[]', array( 'v' => 1 ), '{"v":2}', 'O:8:"stdClass":0:{}', str_repeat( 'a', 70000 ) ) as $bad ) {
			$this->assertNull( FingerprintRecord::from_stored( $bad ) );
		}
		$data = $rec->to_array();
		$data['leaves']['rules.x'] = 'nothex';
		$this->assertNull( FingerprintRecord::from_stored( json_encode( $data ) ) );
		$data = $rec->to_array();
		$data['leaves']['bad path!'] = str_repeat( 'a', 32 );
		$this->assertNull( FingerprintRecord::from_stored( json_encode( $data ) ) );
	}

	public function test_the_seal_covers_logged_the_blog_and_the_key(): void {
		$rec = $this->fp( $this->settings(), null, true, 5 );
		$this->assertTrue( $rec->seal_valid( $this->key() ) );
		$this->assertFalse( $rec->seal_valid( $this->key( 'secret-one', 2 ) ) );
		$this->assertFalse( $rec->seal_valid( $this->key( 'other' ) ) );
		$forged = new FingerprintRecord( $rec->kid, 0, $rec->leaves, $rec->seal );
		$this->assertFalse( $forged->seal_valid( $this->key() ) );
	}

	/* ---------- detector ---------- */

	private function compare( ?FingerprintRecord $stored, mixed $raw, bool $marker = true, bool $present = true ): DriftVerdict {
		return DriftDetector::compare( $stored, $this->fp( $raw, null, $present ), $this->key(), $marker );
	}

	public function test_same_settings_match_and_junk_keys_match(): void {
		$s = $this->settings();
		$stored = $this->fp( $s );
		$this->assertSame( DriftVerdict::MATCH, $this->compare( $stored, $s )->kind );
		$s['junk'] = 1;
		$this->assertSame( DriftVerdict::MATCH, $this->compare( $stored, $s )->kind );
	}

	public function test_a_changed_added_or_removed_key_is_changed(): void {
		$stored = $this->fp( $this->settings() );
		$v = $this->compare( $stored, $this->settings( array( 'mode' => 'monitor' ) ) );
		$this->assertSame( DriftVerdict::CHANGED, $v->kind );
		$this->assertSame( array( 'mode' ), $v->paths );

		$removed = $this->settings();
		unset( $removed['rules']['waf']['enabled'] );
		$this->assertSame( array( 'rules.waf.enabled' ), $this->compare( $stored, $removed )->paths );

		$base = $this->settings();
		unset( $base['mode'] );
		$added = $this->compare( $this->fp( $base ), $this->settings() );
		$this->assertSame( array( 'mode' ), $added->paths );
	}

	public function test_a_missing_option_is_changed_settings(): void {
		$v = $this->compare( $this->fp( $this->settings() ), false, true, false );
		$this->assertSame( DriftVerdict::CHANGED, $v->kind );
		$this->assertContains( 'settings', $v->paths );
		$this->assertTrue( $v->forces_alert() );
	}

	public function test_no_record_is_a_baseline_or_missing_by_marker(): void {
		$this->assertSame( DriftVerdict::BASELINE, $this->compare( null, $this->settings(), false )->kind );
		$this->assertSame( DriftVerdict::FINGERPRINT_MISSING, $this->compare( null, $this->settings(), true )->kind );
	}

	public function test_another_key_is_keys_changed(): void {
		$stored = $this->fp( $this->settings(), $this->key( 'old-secret' ) );
		$this->assertSame( DriftVerdict::KEYS_CHANGED, $this->compare( $stored, $this->settings() )->kind );
	}

	public function test_an_unsealed_record_is_altered(): void {
		$rec    = $this->fp( $this->settings() );
		$leaves = $rec->leaves;
		unset( $leaves['mode'] );
		$dropped = new FingerprintRecord( $rec->kid, 0, $leaves, $rec->seal );
		$this->assertSame( DriftVerdict::FINGERPRINT_ALTERED, $this->compare( $dropped, $this->settings() )->kind );

		$extra = new FingerprintRecord( $rec->kid, 0, $rec->leaves + array( 'extra.leaf' => str_repeat( 'a', 32 ) ), $rec->seal );
		$this->assertSame( DriftVerdict::FINGERPRINT_ALTERED, $this->compare( $extra, $this->settings() )->kind );

		$edited = $rec->leaves;
		$edited['mode'] = str_repeat( 'b', 32 );
		$v = $this->compare( new FingerprintRecord( $rec->kid, 0, $edited, $rec->seal ), $this->settings() );
		$this->assertSame( DriftVerdict::FINGERPRINT_ALTERED, $v->kind );
		$this->assertSame( array( 'mode' ), $v->paths );
	}

	public function test_a_record_from_another_site_is_altered(): void {
		$other = SettingsFingerprint::record( $this->settings(), true, $this->key( 'secret-one', 2 ), 0 );
		$this->assertSame( DriftVerdict::FINGERPRINT_ALTERED, $this->compare( $other, $this->settings() )->kind );
	}

	public function test_schema_only_differences_are_silent(): void {
		$key = $this->key();
		$rec = $this->fp( $this->settings() );

		// A leaf only in the stored record (the plugin dropped a setting).
		$leaves                = $rec->leaves;
		$leaves['old.setting'] = str_repeat( 'a', 32 );
		$v = $this->compare( FingerprintRecord::sealed( $key, 0, $leaves ), $this->settings() );
		$this->assertSame( DriftVerdict::SCHEMA, $v->kind );
		$this->assertFalse( $v->reportable() );

		// A leaf only in the current schema (the plugin added a setting), absent from the option.
		$leaves = $rec->leaves;
		unset( $leaves['mode'] );
		$v = $this->compare( FingerprintRecord::sealed( $key, 0, $leaves ), $this->settings() );
		$this->assertSame( DriftVerdict::CHANGED, $v->kind, 'present in the option: not silent' );
		$stripped = $this->settings();
		unset( $stripped['mode'] );
		$this->assertSame( DriftVerdict::SCHEMA, $this->compare( FingerprintRecord::sealed( $key, 0, $leaves ), $stripped )->kind );
	}

	/* ---------- verdict ---------- */

	public function test_reason_is_capped_with_the_head_intact(): void {
		$paths = array();
		for ( $i = 0; $i < 30; $i++ ) {
			$paths[] = 'rules.some_long_rule_name_' . $i . '.some_long_setting_name';
		}
		foreach ( array( DriftVerdict::CHANGED, DriftVerdict::FINGERPRINT_ALTERED, DriftVerdict::KEYS_CHANGED, DriftVerdict::FINGERPRINT_MISSING ) as $kind ) {
			$reason = ( new DriftVerdict( $kind, $paths ) )->reason( 'an admin page check' );
			$this->assertLessThanOrEqual( 255, strlen( $reason ), $kind );
			$this->assertStringStartsWith( DriftVerdict::HEADS[ $kind ], $reason );
		}
		$this->assertStringContainsString( 'actor unknown', ( new DriftVerdict( DriftVerdict::CHANGED, array( 'mode' ) ) )->reason( 'the daily check' ) );
	}

	public function test_paths_are_made_safe(): void {
		$v = new DriftVerdict( DriftVerdict::CHANGED, array( 'a b<script>' ) );
		$this->assertSame( array( 'abscript' ), $v->paths );
	}

	public function test_forced_alerts(): void {
		$this->assertTrue( ( new DriftVerdict( DriftVerdict::CHANGED, array( 'alerts.enabled' ) ) )->forces_alert() );
		$this->assertTrue( ( new DriftVerdict( DriftVerdict::CHANGED, array( 'mode' ) ) )->forces_alert() );
		$this->assertTrue( ( new DriftVerdict( DriftVerdict::CHANGED, array( 'settings' ) ) )->forces_alert() );
		$this->assertFalse( ( new DriftVerdict( DriftVerdict::CHANGED, array( 'rules.waf.enabled' ) ) )->forces_alert() );
		foreach ( array( DriftVerdict::FINGERPRINT_MISSING, DriftVerdict::FINGERPRINT_ALTERED, DriftVerdict::KEYS_CHANGED ) as $kind ) {
			$this->assertTrue( ( new DriftVerdict( $kind ) )->forces_alert() );
		}
		$this->assertFalse( ( new DriftVerdict( DriftVerdict::BASELINE ) )->forces_alert() );
		$many = array_merge( array_fill( 0, 25, 'rules.waf.enabled' ), array( 'alerts.enabled' ) );
		$this->assertTrue( ( new DriftVerdict( DriftVerdict::CHANGED, $many ) )->forces_alert(), 'a cut path list cannot hide an alert path' );
	}

	public function test_mail_detail_notes_a_failed_row(): void {
		$v = new DriftVerdict( DriftVerdict::CHANGED, array( 'mode' ) );
		$this->assertStringContainsString( 'Changed: mode.', $v->mail_detail( 'the daily check', true ) );
		$this->assertStringNotContainsString( 'could not be written', $v->mail_detail( 'the daily check', true ) );
		$this->assertStringContainsString( 'could not be written', $v->mail_detail( 'the daily check', false ) );
	}
}
