<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Geo;

use PHPUnit\Framework\TestCase;
use WPBouncer\Geo\CsvImporter;

/**
 * @covers \WPBouncer\Geo\CsvImporter
 */
final class CsvImporterTest extends TestCase {

	private string $fixtures;

	protected function setUp(): void {
		$this->fixtures = dirname( __DIR__, 2 ) . '/fixtures';
	}

	public function test_parses_dbip_ipv4_row(): void {
		$this->assertSame(
			array(
				'from'    => '00000000000000000000ffff01000000',
				'to'      => '00000000000000000000ffff010000ff',
				'country' => 'AU',
			),
			CsvImporter::parse_row( array( '1.0.0.0', '1.0.0.255', 'AU' ) )
		);
	}

	public function test_parses_dbip_ipv6_row(): void {
		$row = CsvImporter::parse_row( array( '2001:200::', '2001:200:ffff:ffff:ffff:ffff:ffff:ffff', 'jp' ) );
		$this->assertSame( '20010200000000000000000000000000', $row['from'] );
		$this->assertSame( '20010200ffffffffffffffffffffffff', $row['to'] );
		$this->assertSame( 'JP', $row['country'] );
	}

	public function test_parses_ip2location_integer_row(): void {
		$row = CsvImporter::parse_row( array( '16777216', '16777471', 'US', 'United States of America' ) );
		$this->assertSame( '00000000000000000000ffff01000000', $row['from'] );
		$this->assertSame( '00000000000000000000ffff010000ff', $row['to'] );
	}

	/** @dataProvider junk */
	public function test_rejects_junk( array $fields ): void {
		$this->assertNull( CsvImporter::parse_row( $fields ) );
	}

	public static function junk(): array {
		return array(
			'header'          => array( array( 'ip_start', 'ip_end', 'country' ) ),
			'too few columns' => array( array( '1.0.0.0', '1.0.0.255' ) ),
			'bad country'     => array( array( '1.0.0.0', '1.0.0.255', 'Australia' ) ),
			'unknown ZZ'      => array( array( '1.0.0.0', '1.0.0.255', 'ZZ' ) ),
			'reversed range'  => array( array( '1.0.0.255', '1.0.0.0', 'AU' ) ),
			'mixed family'    => array( array( '1.0.0.0', '2001::', 'AU' ) ),
			'integer too big' => array( array( '99999999999', '99999999999', 'AU' ) ),
			'empty'           => array( array( '', '', '' ) ),
		);
	}

	public function test_import_streams_in_batches(): void {
		$batches = array();
		$result  = CsvImporter::import(
			$this->fixtures . '/geo-sample.csv',
			static function ( array $batch ) use ( &$batches ): void {
				$batches[] = $batch;
			},
			2
		);

		$this->assertSame( 5, $result['imported'] );
		$this->assertSame( 2, $result['skipped'], 'header and a junk row' );
		$this->assertSame( array( 2, 2, 1 ), array_map( 'count', $batches ) );
		$this->assertSame( 'AU', $batches[0][0]['country'] );
	}

	public function test_import_reads_gzip(): void {
		$tmp = tempnam( sys_get_temp_dir(), 'wpb' ) . '.csv.gz';
		file_put_contents( $tmp, gzencode( (string) file_get_contents( $this->fixtures . '/geo-sample.csv' ) ) );

		$rows   = array();
		$result = CsvImporter::import(
			$tmp,
			static function ( array $batch ) use ( &$rows ): void {
				$rows = array_merge( $rows, $batch );
			}
		);
		unlink( $tmp );

		$this->assertSame( 5, $result['imported'] );
		$this->assertCount( 5, $rows );
	}

	public function test_import_missing_file_throws(): void {
		$this->expectException( \RuntimeException::class );
		CsvImporter::import( '/definitely/not/here.csv', static function (): void {} );
	}

	/* prepare() and import_chunk(): the multi-request import ------------- */

	/** @var string[] */
	private array $tmp_files = array();

	protected function tearDown(): void {
		foreach ( $this->tmp_files as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
		}
		$this->tmp_files = array();
		parent::tearDown();
	}

	private function tmp( string $suffix = '.csv' ): string {
		$base              = (string) tempnam( sys_get_temp_dir(), 'wpb' );
		$this->tmp_files[] = $base;
		$this->tmp_files[] = $base . $suffix;
		return $base . $suffix;
	}

	/** A CSV of $n distinct /24 ranges. */
	private function big_csv( int $n ): string {
		$lines = array( '# comment line', 'start,end,country' );
		for ( $i = 0; $i < $n; $i++ ) {
			$a       = 1 + intdiv( $i, 65536 );
			$b       = intdiv( $i, 256 ) % 256;
			$c       = $i % 256;
			$lines[] = "{$a}.{$b}.{$c}.0,{$a}.{$b}.{$c}.255," . ( 0 === $i % 2 ? 'US' : 'DE' );
		}
		$file = $this->tmp();
		file_put_contents( $file, implode( "\n", $lines ) . "\n" );
		return $file;
	}

	public function test_prepare_unpacks_gzip_to_plain_csv(): void {
		$source = $this->tmp( '.csv.gz' );
		$plain  = (string) file_get_contents( $this->fixtures . '/geo-sample.csv' );
		file_put_contents( $source, gzencode( $plain ) );
		$dest = $this->tmp();

		$bytes = CsvImporter::prepare( $source, $dest );

		$this->assertSame( strlen( $plain ), $bytes );
		$this->assertSame( $plain, file_get_contents( $dest ) );
	}

	public function test_prepare_copies_plain_csv(): void {
		$dest = $this->tmp();
		CsvImporter::prepare( $this->fixtures . '/geo-sample.csv', $dest );
		$this->assertFileEquals( $this->fixtures . '/geo-sample.csv', $dest );
	}

	/**
	 * @dataProvider not_geo_files
	 */
	public function test_prepare_rejects_files_that_are_not_geo_csv( string $content ): void {
		$source = $this->tmp();
		file_put_contents( $source, $content );
		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( "doesn't look like" );
		CsvImporter::prepare( $source, $this->tmp() );
	}

	/** @return array<string, array{0: string}> */
	public function not_geo_files(): array {
		return array(
			'html error page' => array( "<!DOCTYPE html>\n<html><body><h1>404 Not Found</h1></body></html>\n" ),
			'maxmind blocks'  => array( "network,geoname_id,registered_country_geoname_id\n1.0.0.0/24,2077456,2077456\n" ),
			'empty'           => array( '' ),
		);
	}

	public function test_prepare_missing_source_throws(): void {
		$this->expectException( \RuntimeException::class );
		CsvImporter::prepare( '/definitely/not/here.csv', $this->tmp() );
	}

	public function test_chunks_resume_to_the_same_result_as_one_pass(): void {
		$file = $this->big_csv( 1234 );

		$whole = array();
		CsvImporter::import(
			$file,
			static function ( array $batch ) use ( &$whole ): void {
				$whole = array_merge( $whole, $batch );
			},
			100
		);

		// Stop after every second batch, the way a time budget would.
		$chunked  = array();
		$offset   = 0;
		$imported = 0;
		$calls    = 0;
		do {
			$batches = 0;
			$r       = CsvImporter::import_chunk(
				$file,
				$offset,
				static function ( array $batch ) use ( &$chunked ): void {
					$chunked = array_merge( $chunked, $batch );
				},
				100,
				static function () use ( &$batches ): bool {
					return ++$batches >= 2;
				}
			);
			$offset    = $r['offset'];
			$imported += $r['imported'];
			++$calls;
		} while ( ! $r['done'] && $calls < 100 );

		$this->assertTrue( $r['done'] );
		$this->assertSame( 7, $calls, '1234 rows at 200 per call' );
		$this->assertSame( 1234, $imported );
		$this->assertSame( $whole, $chunked, 'no row lost or repeated at chunk boundaries' );
		$this->assertSame( filesize( $file ), $offset );
	}

	public function test_chunk_counts_skipped_rows_once(): void {
		$r = CsvImporter::import_chunk(
			$this->fixtures . '/geo-sample.csv',
			0,
			static function (): void {},
			2,
			static function (): bool {
				return false;
			}
		);
		$this->assertTrue( $r['done'] );
		$this->assertSame( 5, $r['imported'] );
		$this->assertSame( 2, $r['skipped'] );
	}

	public function test_chunk_without_trailing_newline_keeps_last_row(): void {
		$file = $this->tmp();
		file_put_contents( $file, "1.0.0.0,1.0.0.255,AU\n2.0.0.0,2.0.0.255,FR" );
		$rows = array();
		$r    = CsvImporter::import_chunk(
			$file,
			0,
			static function ( array $batch ) use ( &$rows ): void {
				$rows = array_merge( $rows, $batch );
			},
			500,
			static function (): bool {
				return false;
			}
		);
		$this->assertTrue( $r['done'] );
		$this->assertSame( array( 'AU', 'FR' ), array_column( $rows, 'country' ) );
	}

	public function test_chunk_missing_file_throws(): void {
		$this->expectException( \RuntimeException::class );
		CsvImporter::import_chunk( '/definitely/not/here.csv', 0, static function (): void {}, 10, static function (): bool {
			return false;
		} );
	}
}
