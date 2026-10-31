<?php
/**
 * Record format 2: the sealed "pending" field and the read of format 1.
 *
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

/**
 * @covers \WPBouncer\Audit\FingerprintRecord
 * @covers \WPBouncer\Audit\DriftDetector
 * @covers \WPBouncer\Audit\SettingsFingerprint
 */
final class FingerprintRecordPendingTest extends TestCase {

	private function key(): FingerprintKey {
		return new FingerprintKey( 'secret', 1 );
	}

	public function test_pending_is_sealed_and_round_trips(): void {
		$pending = array(
			'kind'  => 'changed',
			'paths' => array( 'allowlist' ),
		);
		$rec     = SettingsFingerprint::record( Settings::defaults(), true, $this->key(), 5, array(), $pending );
		$back    = FingerprintRecord::from_stored( $rec->to_json() );
		$this->assertNotNull( $back );
		$this->assertSame( $pending, $back->pending );
		$this->assertTrue( $back->seal_valid( $this->key() ) );

		$data            = json_decode( $rec->to_json(), true );
		$data['pending'] = array(
			'kind'  => 'changed',
			'paths' => array(),
		);
		$forged          = FingerprintRecord::from_stored( json_encode( $data ) );
		$this->assertNotNull( $forged );
		$this->assertFalse( $forged->seal_valid( $this->key() ), 'a changed pending breaks the seal' );
	}

	public function test_a_malformed_pending_is_rejected(): void {
		$rec  = SettingsFingerprint::record( Settings::defaults(), true, $this->key(), 0 );
		$data = json_decode( $rec->to_json(), true );
		foreach ( array( 'x', array( 'kind' => 'evil', 'paths' => array() ), array( 'kind' => 'changed', 'paths' => array( "a\nb" ) ) ) as $bad ) {
			$data['pending'] = $bad;
			$this->assertNull( FingerprintRecord::from_stored( json_encode( $data ) ) );
		}
	}

	public function test_a_format_1_record_is_read_and_upgrades_without_drift(): void {
		$key    = $this->key();
		$now    = SettingsFingerprint::record( Settings::defaults(), true, $key, 0, array( SettingsFingerprint::SITE_EMAIL => 'a@example.com' ) );
		$leaves = array_diff_key( $now->leaves, array_flip( SettingsFingerprint::extra_paths() ) );
		$v1     = FingerprintRecord::from_stored( FingerprintRecord::sealed( $key, 0, $leaves, array(), 1 )->to_json() );
		$this->assertNotNull( $v1 );
		$this->assertSame( 1, $v1->version );
		$this->assertTrue( $v1->seal_valid( $key ) );
		$this->assertSame( DriftVerdict::SCHEMA, DriftDetector::compare( $v1, $now, $key, true )->kind );

		$v2 = SettingsFingerprint::record( Settings::defaults(), true, $key, 0, array( SettingsFingerprint::SITE_EMAIL => 'a@example.com' ) );
		$this->assertSame( DriftVerdict::MATCH, DriftDetector::compare( $v2, $now, $key, true )->kind );
		$other = SettingsFingerprint::record( Settings::defaults(), true, $key, 0, array( SettingsFingerprint::SITE_EMAIL => 'x@example.com' ) );
		$verdict = DriftDetector::compare( $v2, $other, $key, true );
		$this->assertSame( array( 'wp.admin_email' ), $verdict->paths );
		$this->assertTrue( $verdict->forces_alert() );
	}
}
