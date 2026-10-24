<?php
/**
 * GeoDatabase range lookups and bulk inserts on MySQL/MariaDB.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Geo;

use WPBouncer\Geo\GeoDatabase;
use WPBouncer\Support\IpUtils;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Geo\GeoDatabase
 */
final class GeoDatabaseTest extends IntegrationTestCase {

	/** @var GeoDatabase */
	private $geo;

	public function set_up() {
		parent::set_up();
		global $wpdb;
		$this->geo = new GeoDatabase( $wpdb );
	}

	/**
	 * A range row as CsvImporter::parse_row() would build it.
	 *
	 * @param string $from    First IP.
	 * @param string $to      Last IP.
	 * @param string $country Country.
	 * @return array{from: string, to: string, country: string}
	 */
	private function range( string $from, string $to, string $country ): array {
		return array(
			'from'    => (string) IpUtils::to_hex16( $from ),
			'to'      => (string) IpUtils::to_hex16( $to ),
			'country' => $country,
		);
	}

	public function test_table_name_uses_the_prefix(): void {
		global $wpdb;
		$this->assertSame( $wpdb->prefix . 'bouncer_geo', $this->geo->table() );
	}

	public function test_empty_table_has_no_answers(): void {
		$this->assertSame( 0, $this->geo->count() );
		$this->assertNull( $this->geo->lookup( '1.0.0.1' ) );
	}

	public function test_lookup_finds_ipv4_ranges_including_both_edges(): void {
		$this->geo->insert_batch(
			array(
				$this->range( '1.0.0.0', '1.0.0.255', 'AU' ),
				$this->range( '1.0.1.0', '1.0.3.255', 'CN' ),
			)
		);

		$this->assertSame( 'AU', $this->geo->lookup( '1.0.0.0' ) );
		$this->assertSame( 'AU', $this->geo->lookup( '1.0.0.128' ) );
		$this->assertSame( 'AU', $this->geo->lookup( '1.0.0.255' ) );
		$this->assertSame( 'CN', $this->geo->lookup( '1.0.1.0' ) );
		$this->assertSame( 'CN', $this->geo->lookup( '1.0.3.255' ) );
	}

	public function test_lookup_returns_null_in_gaps_and_outside_all_ranges(): void {
		$this->geo->insert_batch(
			array(
				$this->range( '10.0.0.0', '10.0.0.255', 'AU' ),
				$this->range( '10.0.2.0', '10.0.2.255', 'CN' ),
			)
		);

		$this->assertNull( $this->geo->lookup( '10.0.1.5' ), 'gap between ranges' );
		$this->assertNull( $this->geo->lookup( '9.255.255.255' ), 'below the first range' );
		$this->assertNull( $this->geo->lookup( '10.0.3.0' ), 'above the last range' );
	}

	public function test_lookup_handles_ipv6(): void {
		$this->geo->insert_batch(
			array(
				$this->range( '2001:200::', '2001:200:ffff:ffff:ffff:ffff:ffff:ffff', 'JP' ),
				$this->range( '2a00:1450::', '2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff', 'IE' ),
			)
		);

		$this->assertSame( 'JP', $this->geo->lookup( '2001:200:1234::1' ) );
		$this->assertSame( 'IE', $this->geo->lookup( '2a00:1450:4001:81b::200e' ) );
		$this->assertNull( $this->geo->lookup( '2001:300::1' ) );
	}

	public function test_ipv4_and_ipv6_do_not_collide(): void {
		$this->geo->insert_batch( array( $this->range( '1.0.0.0', '1.0.0.255', 'AU' ) ) );

		$this->assertNull( $this->geo->lookup( '2001:200::1' ) );
	}

	public function test_lookup_rejects_garbage_without_querying(): void {
		$this->assertNull( $this->geo->lookup( 'not-an-ip' ) );
		$this->assertNull( $this->geo->lookup( '' ) );
		$this->assertNull( $this->geo->lookup( "1.0.0.1' OR '1'='1" ) );
	}

	public function test_insert_batch_ignores_duplicates_and_keeps_the_first(): void {
		$this->geo->insert_batch( array( $this->range( '1.0.0.0', '1.0.0.255', 'AU' ) ) );

		$this->geo->insert_batch(
			array(
				$this->range( '1.0.0.0', '1.0.0.255', 'US' ),
				$this->range( '2.0.0.0', '2.0.0.255', 'FR' ),
			)
		);

		$this->assertSame( 2, $this->geo->count() );
		$this->assertSame( 'AU', $this->geo->lookup( '1.0.0.9' ) );
		$this->assertSame( 'FR', $this->geo->lookup( '2.0.0.9' ) );
	}

	public function test_insert_batch_with_nothing_is_a_no_op(): void {
		$this->geo->insert_batch( array() );

		$this->assertSame( 0, $this->geo->count() );
	}

	public function test_insert_batch_handles_a_full_batch(): void {
		$rows = array();
		for ( $i = 0; $i < 500; $i++ ) {
			$rows[] = $this->range( '20.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . '.0', '20.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . '.255', 'DE' );
		}

		$this->geo->insert_batch( $rows );

		$this->assertSame( 500, $this->geo->count() );
		$this->assertSame( 'DE', $this->geo->lookup( '20.1.0.77' ) );
	}

	public function test_import_file_replaces_the_table_with_the_fixture(): void {
		$this->geo->insert_batch( array( $this->range( '99.0.0.0', '99.0.0.255', 'ZZ' ) ) );

		// Not the TRUNCATE-in-transaction path: import_file() truncates first, which commits.
		$result = $this->geo->import_file( dirname( __DIR__, 2 ) . '/fixtures/geo-sample.csv' );

		$this->assertSame( 5, $result['imported'] );
		$this->assertSame( 2, $result['skipped'] );
		$this->assertNull( $this->geo->lookup( '99.0.0.1' ), 'old data is gone' );
		$this->assertSame( 'AU', $this->geo->lookup( '1.0.0.9' ), 'first of two duplicate ranges wins' );
		$this->assertSame( 'CN', $this->geo->lookup( '1.0.2.9' ) );
		$this->assertSame( 'JP', $this->geo->lookup( '2001:200::1' ) );
		$this->assertSame( 'IE', $this->geo->lookup( '2a00:1450::1' ) );
		$this->assertSame( 4, $this->geo->count(), 'five parsed rows, one duplicate start ignored' );
	}

	public function test_import_file_throws_for_a_missing_file(): void {
		$this->expectException( \RuntimeException::class );

		$this->geo->import_file( $this->uploads_dir . '/missing.csv' );
	}

	public function test_truncate_empties_the_table(): void {
		$this->geo->insert_batch( array( $this->range( '1.0.0.0', '1.0.0.255', 'AU' ) ) );

		$this->geo->truncate();

		$this->assertSame( 0, $this->geo->count() );
	}
}
