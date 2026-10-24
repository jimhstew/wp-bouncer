<?php
/**
 * The multi-request geo import, with real files and a real table.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Geo;

use WPBouncer\Geo\GeoDatabase;
use WPBouncer\Geo\GeoImport;
use WPBouncer\Plugin;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Geo\GeoImport
 */
final class GeoImportTest extends IntegrationTestCase {

	/** @var GeoDatabase */
	private $db;

	/** @var GeoImport */
	private $import;

	public function set_up() {
		parent::set_up();
		global $wpdb;
		$this->db     = new GeoDatabase( $wpdb );
		$this->import = new GeoImport( $this->db );
	}

	private function fixture(): string {
		return dirname( __DIR__, 2 ) . '/fixtures/geo-sample.csv';
	}

	/** A CSV with many rows, so several steps are needed. */
	private function big_csv( int $rows ): string {
		$path = $this->uploads_dir . '/big.csv';
		$out  = "ip_start,ip_end,country\n";
		for ( $i = 0; $i < $rows; $i++ ) {
			$out .= '30.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . ".0,30." . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . ".255,DE\n";
		}
		file_put_contents( $path, $out );
		return $path;
	}

	public function test_status_is_null_when_nothing_runs(): void {
		$this->assertNull( $this->import->status() );
	}

	public function test_start_prepares_a_working_file_and_saves_progress(): void {
		$this->import->start( $this->fixture(), 'sample.csv' );

		$state = $this->import->status();
		$this->assertNotNull( $state );
		$this->assertSame( 0, $state['offset'] );
		$this->assertSame( 'sample.csv', $state['source'] );
		$this->assertFileExists( $state['file'] );
		$this->assertSame( $this->uploads_dir . '/wp-bouncer', dirname( $state['file'] ), 'working copy lives under uploads/wp-bouncer' );
		$this->assertFileExists( $this->uploads_dir . '/wp-bouncer/index.php' );
		$this->assertStringContainsString( 'denied', (string) file_get_contents( $this->uploads_dir . '/wp-bouncer/.htaccess' ) );
		$this->assertSame( filesize( $this->fixture() ), $state['size'] );
		$this->assertArrayNotHasKey( GeoImport::STATE_OPTION, wp_load_alloptions(), 'progress is not autoloaded' );
	}

	public function test_a_single_step_finishes_a_small_file_and_cleans_up(): void {
		$this->import->start( $this->fixture(), 'sample.csv' );
		$file = $this->import->status()['file'];

		$progress = $this->import->step( 5.0 );

		$this->assertTrue( $progress['done'] );
		$this->assertSame( 100, $progress['percent'] );
		$this->assertSame( 5, $progress['imported'] );
		$this->assertSame( 2, $progress['skipped'] );
		$this->assertNull( $this->import->status(), 'progress record removed' );
		$this->assertFileDoesNotExist( $file, 'working file removed' );
		$this->assertSame( 4, $this->db->count() );
		$meta = get_option( Plugin::GEO_META_OPTION );
		$this->assertSame( 4, $meta['rows'] );
		$this->assertSame( 'sample.csv', $meta['source'] );
		$this->assertSame( 2, $meta['skipped'] );
		$this->assertEqualsWithDelta( time(), $meta['imported'], 10 );
	}

	public function test_a_zero_second_budget_still_makes_progress_in_small_steps(): void {
		$this->import->start( $this->big_csv( 1200 ), 'big.csv' );

		$steps = 0;
		do {
			$progress = $this->import->step( 0.0 );
			++$steps;
			$this->assertLessThan( 20, $steps, 'import must terminate' );
			if ( ! $progress['done'] ) {
				$this->assertGreaterThan( 0, $progress['imported'], 'each step loads at least one batch' );
				$this->assertLessThan( 100, $progress['percent'] );
			}
		} while ( ! $progress['done'] );

		$this->assertGreaterThan( 1, $steps, 'a zero budget splits the work' );
		$this->assertSame( 1200, $progress['imported'] );
		$this->assertSame( 1200, $this->db->count() );
		$this->assertSame( 'DE', $this->db->lookup( '30.1.5.9' ) );
	}

	public function test_start_empties_the_table_and_rejects_bad_files_without_touching_data(): void {
		$this->db->insert_batch( array( array( 'from' => str_repeat( '0', 31 ) . '1', 'to' => str_repeat( '0', 31 ) . '2', 'country' => 'AU' ) ) );
		$bad = $this->uploads_dir . '/page.html';
		file_put_contents( $bad, "<html><body>Not Found</body></html>\n" );

		try {
			$this->import->start( $bad, 'page.html' );
			$this->fail( 'A non-geo file must be refused.' );
		} catch ( \RuntimeException $e ) {
			$this->assertNotSame( '', $e->getMessage() );
		}

		$this->assertSame( 1, $this->db->count(), 'current data is untouched' );
		$this->assertNull( $this->import->status() );
	}

	public function test_a_url_source_is_stored_as_a_label_without_credentials(): void {
		$this->import->start( $this->fixture(), 'https://bob:hunter2@geo.example.org/x/db.csv?license_key=SECRET' );
		$this->assertSame( 'geo.example.org/…/db.csv', $this->import->status()['source'] );
	}

	public function test_a_missing_source_file_is_refused(): void {
		$this->expectException( \RuntimeException::class );

		$this->import->start( $this->uploads_dir . '/nope.csv', 'nope.csv' );
	}

	public function test_step_without_an_import_throws(): void {
		$this->expectException( \RuntimeException::class );

		$this->import->step( 1.0 );
	}

	public function test_step_fails_clearly_when_the_working_file_vanished(): void {
		$this->import->start( $this->fixture(), 'sample.csv' );
		unlink( $this->import->status()['file'] );

		$this->expectException( \RuntimeException::class );

		$this->import->step( 1.0 );
	}

	public function test_cancel_keeps_loaded_ranges_marks_incomplete_and_removes_the_file(): void {
		$this->import->start( $this->big_csv( 1200 ), 'big.csv' );
		$file = $this->import->status()['file'];
		$this->import->step( 0.0 );
		$loaded = $this->db->count();
		$this->assertGreaterThan( 0, $loaded );

		$this->import->cancel();

		$this->assertNull( $this->import->status() );
		$this->assertFileDoesNotExist( $file );
		$this->assertSame( $loaded, $this->db->count(), 'ranges loaded so far are kept' );
		$meta = get_option( Plugin::GEO_META_OPTION );
		$this->assertStringContainsString( 'incomplete', $meta['source'] );
		$this->assertSame( $loaded, $meta['rows'] );
	}

	public function test_cancel_with_nothing_running_is_harmless(): void {
		$this->import->cancel();

		$this->assertNull( $this->import->status() );
		$this->assertFalse( get_option( Plugin::GEO_META_OPTION ) );
	}

	public function test_starting_again_abandons_the_previous_working_file(): void {
		$this->import->start( $this->fixture(), 'one.csv' );
		$first = $this->import->status()['file'];

		$this->import->start( $this->fixture(), 'two.csv' );

		$this->assertFileDoesNotExist( $first );
		$this->assertSame( 'two.csv', $this->import->status()['source'] );
	}

	public function test_gzipped_sources_are_unpacked(): void {
		$gz = $this->uploads_dir . '/geo.csv.gz';
		file_put_contents( $gz, gzencode( (string) file_get_contents( $this->fixture() ) ) );

		$this->import->start( $gz, 'geo.csv.gz' );
		$progress = $this->import->step( 5.0 );

		$this->assertTrue( $progress['done'] );
		$this->assertSame( 4, $this->db->count() );
	}

	public function test_the_working_file_is_removed_when_the_unpacked_size_passes_the_cap(): void {
		$gz = $this->uploads_dir . '/bomb.csv.gz';
		file_put_contents( $gz, gzencode( str_repeat( "\0", 2 * 1048576 ), 9 ) );
		$cap = static function (): int {
			return 1048576;
		};
		add_filter( 'wp_bouncer_geo_max_bytes', $cap );
		try {
			$this->import->start( $gz, 'bomb.csv.gz' );
			$this->fail( 'expected the cap to stop the import' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'larger than', $e->getMessage() );
		} finally {
			remove_filter( 'wp_bouncer_geo_max_bytes', $cap );
		}
		$this->assertNull( $this->import->status() );
		$this->assertSame( array(), glob( $this->uploads_dir . '/wp-bouncer/geo-import-*.csv' ) ?: array() );
	}

	public function test_start_sweeps_stale_working_files_only(): void {
		$dir   = $this->uploads_dir . '/wp-bouncer';
		wp_mkdir_p( $dir );
		$old   = $dir . '/geo-import-old.csv';
		$fresh = $dir . '/geo-import-fresh.csv';
		file_put_contents( $old, 'x' );
		file_put_contents( $fresh, 'x' );
		touch( $old, time() - 2 * DAY_IN_SECONDS );

		$this->import->start( $this->fixture(), 'sample.csv' );

		$this->assertFileDoesNotExist( $old );
		$this->assertFileExists( $fresh );
	}

	public function test_percent_helper(): void {
		$this->assertSame( 0, GeoImport::percent( array( 'size' => 0, 'offset' => 0 ) ) );
		$this->assertSame( 50, GeoImport::percent( array( 'size' => 200, 'offset' => 100 ) ) );
		$this->assertSame( 100, GeoImport::percent( array( 'size' => 100, 'offset' => 500 ) ) );
	}

	public function test_plugin_geo_database_is_used_for_lookups_once_rows_are_loaded(): void {
		$this->import->start( $this->fixture(), 'sample.csv' );
		$this->import->step( 5.0 );
		$this->plugin->reload_settings();

		$this->assertSame( 'AU', $this->plugin->geo()->lookup( '1.0.0.9' ) );
		$this->assertSame( 'JP', $this->plugin->geo()->lookup( '2001:200::5' ) );
		$this->assertNull( $this->plugin->geo()->lookup( '8.8.8.8' ) );
	}
}
