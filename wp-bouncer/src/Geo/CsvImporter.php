<?php
/**
 * Parses free IP-to-country CSV databases into fixed-width ranges.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Geo;

use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Supported formats (first three columns are used, extra columns ignored):
 *
 * - DB-IP "IP to Country Lite" (CC BY 4.0), https://db-ip.com/db/lite.php
 *     1.0.0.0,1.0.0.255,AU
 *     2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
 * - IP2Location LITE DB1 (IPv4, integer form), https://lite.ip2location.com
 *     "16777216","16777471","US","United States of America"
 * - Any CSV of start-IP,end-IP,country-code.
 *
 * Gzipped files (.csv.gz) are read transparently.
 */
final class CsvImporter {

	/**
	 * Turn one CSV row into a range.
	 *
	 * @param array<int, string|null> $fields CSV fields.
	 * @return array{from: string, to: string, country: string}|null Hex-encoded 16-byte bounds, or null for headers, comments and junk.
	 */
	public static function parse_row( array $fields ): ?array {
		if ( count( $fields ) < 3 ) {
			return null;
		}
		$start   = self::to_ip( trim( (string) $fields[0] ) );
		$end     = self::to_ip( trim( (string) $fields[1] ) );
		$country = strtoupper( trim( (string) $fields[2] ) );

		if ( null === $start || null === $end || ! preg_match( '/^[A-Z]{2}$/', $country ) || 'ZZ' === $country ) {
			return null;
		}
		// Both ends must be the same address family.
		if ( IpUtils::is_ipv6( $start ) !== IpUtils::is_ipv6( $end ) ) {
			return null;
		}

		$from = (string) IpUtils::to_hex16( $start );
		$to   = (string) IpUtils::to_hex16( $end );
		if ( strcmp( $from, $to ) > 0 ) {
			return null;
		}
		return array(
			'from'    => $from,
			'to'      => $to,
			'country' => $country,
		);
	}

	/**
	 * Accept dotted/colon notation or a decimal IPv4 integer.
	 *
	 * @param string $value Field value.
	 */
	private static function to_ip( string $value ): ?string {
		if ( IpUtils::is_valid( $value ) ) {
			return $value;
		}
		if ( '' !== $value && ctype_digit( $value ) && strlen( $value ) <= 10 && (int) $value <= 4294967295 ) {
			return long2ip( (int) $value );
		}
		return null;
	}

	/**
	 * Stream a CSV file and hand parsed ranges to $writer in batches, in one go.
	 *
	 * Fine for small files and the CLI. The admin screen imports with
	 * prepare() and import_chunk() instead, so no single request runs long.
	 *
	 * @param string   $path       File path (.csv or .csv.gz).
	 * @param callable $writer     Receives each batch (a list of parse_row() results).
	 * @param int      $batch_size Rows per batch.
	 * @return array{imported: int, skipped: int}
	 * @throws \RuntimeException When the file can't be opened.
	 */
	public static function import( string $path, callable $writer, int $batch_size = 1000 ): array {
		$handle = @gzopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- handled below.
		if ( false === $handle ) {
			throw new \RuntimeException( 'Could not open geo database file.' );
		}

		$imported = 0;
		$skipped  = 0;
		$batch    = array();

		while ( ! gzeof( $handle ) ) {
			$line = gzgets( $handle, 4096 );
			if ( false === $line ) {
				break;
			}
			self::take_line( $line, $batch, $imported, $skipped );
			if ( count( $batch ) >= $batch_size ) {
				$writer( $batch );
				$batch = array();
			}
		}
		if ( $batch ) {
			$writer( $batch );
		}
		gzclose( $handle );

		return array(
			'imported' => $imported,
			'skipped'  => $skipped,
		);
	}

	/**
	 * Copy a .csv or .csv.gz file to a plain, seekable CSV and check that it
	 * contains ranges we can read.
	 *
	 * The check runs before anything is deleted, so a wrong file (an HTML error
	 * page from a bad URL, a zip, a MaxMind file) leaves the current data alone.
	 *
	 * @param string $source      File to read (gzip is detected automatically).
	 * @param string $dest        Plain CSV to write.
	 * @param int    $probe_lines How many data lines to test.
	 * @return int Size of $dest in bytes.
	 * @throws \RuntimeException When the file can't be read or has no usable ranges.
	 */
	public static function prepare( string $source, string $dest, int $probe_lines = 200 ): int {
		$in = @gzopen( $source, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- handled below.
		if ( false === $in ) {
			throw new \RuntimeException( 'Could not open geo database file.' );
		}
		$out = @fopen( $dest, 'wb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions -- a failed open is handled by the false check below; plugin-owned local file, WP_Filesystem cannot stream.
		if ( false === $out ) {
			gzclose( $in );
			throw new \RuntimeException( 'Could not write a working copy of the geo database. Check that wp-content/uploads is writable.' );
		}
		$bytes = 0;
		while ( ! gzeof( $in ) ) {
			$chunk = gzread( $in, 1048576 );
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			$written = fwrite( $out, $chunk ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- streams a large plugin-owned file in chunks; WP_Filesystem would read it all into memory.
			if ( strlen( $chunk ) !== $written ) {
				gzclose( $in );
				fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- streams a large plugin-owned file in chunks; WP_Filesystem would read it all into memory.
				throw new \RuntimeException( 'Ran out of disk space while unpacking the geo database.' );
			}
			$bytes += $written;
		}
		gzclose( $in );
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- streams a large plugin-owned file in chunks; WP_Filesystem would read it all into memory.

		$probe = self::import_chunk(
			$dest,
			0,
			static function (): void {},
			$probe_lines,
			static function (): bool {
				return true;
			}
		);
		if ( 0 === $probe['imported'] ) {
			throw new \RuntimeException( 'That file doesn\'t look like an IP-to-country CSV: none of its first lines could be read. Expected start_ip,end_ip,country_code.' );
		}
		return $bytes;
	}

	/**
	 * Import part of a plain CSV, starting at a byte offset.
	 *
	 * Rows go to $writer in batches. After each batch $should_stop() is asked
	 * whether to carry on, so the caller decides how long a chunk runs. The
	 * returned offset is always at the start of a line and every row before it
	 * has been written, so the next call can resume from it. Writing a batch
	 * twice (after a failed request is retried) must be harmless, which
	 * GeoDatabase guarantees with INSERT IGNORE on the primary key.
	 *
	 * @param string           $path        Plain CSV (from prepare()).
	 * @param int              $offset      Byte offset to start at.
	 * @param callable         $writer      Receives each batch (a list of parse_row() results).
	 * @param int              $batch_size  Rows per batch.
	 * @param callable(): bool $should_stop Asked after each batch.
	 * @return array{offset: int, imported: int, skipped: int, done: bool}
	 * @throws \RuntimeException When the file can't be opened.
	 */
	public static function import_chunk( string $path, int $offset, callable $writer, int $batch_size, callable $should_stop ): array {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions -- a failed open is handled by the false check below; plugin-owned local file, WP_Filesystem cannot stream.
		if ( false === $handle ) {
			throw new \RuntimeException( 'The geo database working file has gone missing. Start the import again.' );
		}
		if ( $offset > 0 && 0 !== fseek( $handle, $offset ) ) {
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- streams a large plugin-owned file in chunks; WP_Filesystem would read it all into memory.
			throw new \RuntimeException( 'Could not resume the geo database import. Start it again.' );
		}

		$imported = 0;
		$skipped  = 0;
		$batch    = array();
		$done     = false;

		while ( true ) {
			$line = fgets( $handle, 4096 );
			if ( false === $line ) {
				$done = true;
				break;
			}
			self::take_line( $line, $batch, $imported, $skipped );
			if ( count( $batch ) >= $batch_size ) {
				$writer( $batch );
				$batch = array();
				if ( $should_stop() ) {
					break;
				}
			}
		}
		if ( $batch ) {
			$writer( $batch );
		}
		$position = ftell( $handle );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- streams a large plugin-owned file in chunks; WP_Filesystem would read it all into memory.

		return array(
			'offset'   => false === $position ? $offset : $position,
			'imported' => $imported,
			'skipped'  => $skipped,
			'done'     => $done,
		);
	}

	/**
	 * Parse one raw line into $batch, or count it as skipped.
	 *
	 * Blank lines and # comments are ignored without counting.
	 *
	 * @param string                                                       $line     Raw line.
	 * @param array<int, array{from: string, to: string, country: string}> $batch    Batch being built.
	 * @param int                                                          $imported Running count of parsed rows.
	 * @param int                                                          $skipped  Running count of unreadable rows.
	 */
	private static function take_line( string $line, array &$batch, int &$imported, int &$skipped ): void {
		$line = trim( $line );
		if ( '' === $line || '#' === $line[0] ) {
			return;
		}
		$row = self::parse_row( str_getcsv( $line, ',', '"', '\\' ) );
		if ( null === $row ) {
			++$skipped;
			return;
		}
		$batch[] = $row;
		++$imported;
	}
}
