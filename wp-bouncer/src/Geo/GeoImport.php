<?php
/**
 * Runs a geo database import across several short requests.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Geo;

use WPBouncer\Plugin;
use WPBouncer\Support\UrlRedactor;

defined( 'ABSPATH' ) || exit;

/**
 * A full DB-IP file is about 700,000 ranges. Inserting them takes from
 * 20 seconds to a few minutes, which is longer than many hosts let one PHP
 * request run, so the import is split up:
 *
 * 1. start()  unpacks the file to a plain CSV under wp-content/uploads/wp-bouncer,
 *             checks it is readable, empties the table and saves the progress.
 * 2. step()   imports for a few seconds from the saved byte offset and saves
 *             again. The Tools screen calls it over AJAX until it reports done.
 * 3. finish   (inside the last step) updates the geo meta option and deletes
 *             the working file.
 *
 * While an import runs, ranges that aren't loaded yet look up as "unknown",
 * so country blocking lets those visitors in until it finishes.
 */
final class GeoImport {

	/** Progress of the current import (not autoloaded). */
	public const STATE_OPTION = 'wp_bouncer_geo_import';

	/** Folder under wp-content/uploads for the working copy. */
	public const WORK_DIR = 'wp-bouncer';

	/** Rows per INSERT. */
	private const BATCH = 500;

	/**
	 * WordPress database handle.
	 *
	 * @var GeoDatabase
	 */
	private GeoDatabase $db;

	/**
	 * Set up the GeoImport.
	 *
	 * @param GeoDatabase $db Geo table.
	 */
	public function __construct( GeoDatabase $db ) {
		$this->db = $db;
	}

	/**
	 * Current progress, or null when no import is running.
	 *
	 * @return array{file: string, size: int, offset: int, imported: int, skipped: int, source: string, started: int}|null
	 */
	public function status(): ?array {
		$state = get_option( self::STATE_OPTION );
		if ( ! is_array( $state ) || empty( $state['file'] ) ) {
			return null;
		}
		return $state;
	}

	/**
	 * Percentage done, 0-100.
	 *
	 * @param array<string, mixed> $state Import state, as returned by status().
	 * @return int
	 */
	public static function percent( array $state ): int {
		if ( empty( $state['size'] ) ) {
			return 0;
		}
		return (int) min( 100, floor( 100 * (int) $state['offset'] / (int) $state['size'] ) );
	}

	/**
	 * Begin importing a file. Any import already running is abandoned.
	 *
	 * @param string $source_path The uploaded or downloaded .csv / .csv.gz file.
	 * @param string $label       Where it came from (file name or URL), for display.
	 * @throws \RuntimeException When the file is unreadable or not a geo CSV. The current data is untouched.
	 */
	public function start( string $source_path, string $label ): void {
		$this->discard_working_file();

		$work = $this->work_dir() . '/geo-import-' . wp_generate_password( 16, false ) . '.csv';
		try {
			$size = CsvImporter::prepare( $source_path, $work );
		} catch ( \RuntimeException $e ) {
			wp_delete_file( $work );
			throw $e;
		}

		$this->db->truncate();
		update_option(
			self::STATE_OPTION,
			array(
				'file'     => $work,
				'size'     => $size,
				'offset'   => 0,
				'imported' => 0,
				'skipped'  => 0,
				'source'   => UrlRedactor::label( $label ),
				'started'  => time(),
			),
			false
		);
	}

	/**
	 * Import for about $seconds, then save progress.
	 *
	 * @param float $seconds Time budget. Each step overruns it by at most one batch.
	 * @return array{done: bool, percent: int, imported: int, skipped: int}
	 * @throws \RuntimeException When no import is running or the working file is gone.
	 */
	public function step( float $seconds ): array {
		$state = $this->status();
		if ( null === $state ) {
			throw new \RuntimeException( __( 'No geo database import is running.', 'wp-bouncer' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- translated string literal, not user input; the message is escaped by whoever prints it.
		}

		$deadline = microtime( true ) + $seconds;
		$chunk    = CsvImporter::import_chunk(
			$state['file'],
			(int) $state['offset'],
			array( $this->db, 'insert_batch' ),
			self::BATCH,
			static function () use ( $deadline ): bool {
				return microtime( true ) >= $deadline;
			}
		);

		$state['offset']    = $chunk['offset'];
		$state['imported'] += $chunk['imported'];
		$state['skipped']  += $chunk['skipped'];

		if ( $chunk['done'] ) {
			$this->finish( $state, false );
		} else {
			update_option( self::STATE_OPTION, $state, false );
		}

		return array(
			'done'     => $chunk['done'],
			'percent'  => $chunk['done'] ? 100 : self::percent( $state ),
			'imported' => (int) $state['imported'],
			'skipped'  => (int) $state['skipped'],
		);
	}

	/**
	 * Stop a running import. Ranges loaded so far are kept and used.
	 */
	public function cancel(): void {
		$state = $this->status();
		if ( null !== $state ) {
			$this->finish( $state, true );
		}
	}

	/**
	 * Record the result and clean up.
	 *
	 * @param array<string, mixed> $state      Progress.
	 * @param bool                 $incomplete Stopped before the end.
	 */
	private function finish( array $state, bool $incomplete ): void {
		$source = (string) $state['source'];
		if ( $incomplete ) {
			/* translators: %s: file name or URL. */
			$source = sprintf( __( '%s (incomplete)', 'wp-bouncer' ), $source );
		}
		update_option(
			Plugin::GEO_META_OPTION,
			array(
				'rows'     => $this->db->count(),
				'source'   => $source,
				'imported' => time(),
				'skipped'  => (int) $state['skipped'],
			),
			true
		);
		$this->discard_working_file();
	}

	/** Delete the working file and the progress record. */
	public function discard_working_file(): void {
		$state = get_option( self::STATE_OPTION );
		if ( is_array( $state ) && ! empty( $state['file'] ) && is_string( $state['file'] ) ) {
			wp_delete_file( $state['file'] );
		}
		delete_option( self::STATE_OPTION );
	}

	/**
	 * Folder for working files: wp-content/uploads/wp-bouncer, closed to web
	 * visitors. Falls back to the system temp folder.
	 */
	private function work_dir(): string {
		$uploads = wp_upload_dir( null, false );
		if ( empty( $uploads['error'] ) && ! empty( $uploads['basedir'] ) ) {
			$dir = $uploads['basedir'] . '/' . self::WORK_DIR;
			if ( wp_mkdir_p( $dir ) && wp_is_writable( $dir ) ) {
				if ( ! file_exists( $dir . '/index.php' ) ) {
					file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- writes a fixed hardening file into the plugin's own uploads folder; WP_Filesystem needs credentials and is not loaded in cron.
				}
				if ( ! file_exists( $dir . '/.htaccess' ) ) {
					file_put_contents( $dir . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- writes a fixed hardening file into the plugin's own uploads folder; WP_Filesystem needs credentials and is not loaded in cron.
				}
				return $dir;
			}
		}
		return untrailingslashit( get_temp_dir() );
	}
}
