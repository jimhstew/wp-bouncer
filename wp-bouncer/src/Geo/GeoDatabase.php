<?php
/**
 * Local IP-range table used for country lookups.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Geo;

use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Stores ranges in {prefix}bouncer_geo with both bounds as 32-character
 * lowercase hex strings (see IpUtils::to_hex16()). Fixed-width hex sorts the
 * same way as the addresses themselves, so one indexed query answers for
 * IPv4 and IPv6 alike:
 *
 *   SELECT country, ip_to FROM t WHERE ip_from <= :ip ORDER BY ip_from DESC LIMIT 1
 *
 * Hex is used rather than VARBINARY(16) because it behaves identically on
 * MySQL, MariaDB and SQLite-backed WordPress and needs no UNHEX(), at the
 * cost of about twice the storage.
 */
final class GeoDatabase implements GeoProviderInterface {

	/** @var \wpdb */
	private $db;
	private string $table;

	/**
	 * @param \wpdb $db WordPress database handle.
	 */
	public function __construct( $db ) {
		$this->db    = $db;
		$this->table = $db->prefix . 'bouncer_geo';
	}

	/** Fully-qualified table name. */
	public function table(): string {
		return $this->table;
	}

	/** {@inheritDoc} */
	public function lookup( string $ip ): ?string {
		$hex = IpUtils::to_hex16( $ip );
		if ( null === $hex ) {
			return null;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is internal.
		$row = $this->db->get_row( $this->db->prepare( "SELECT country, ip_to FROM {$this->table} WHERE ip_from <= %s ORDER BY ip_from DESC LIMIT 1", $hex ) );
		if ( ! $row || strcmp( (string) $row->ip_to, $hex ) < 0 ) {
			return null;
		}
		return (string) $row->country;
	}

	/** Number of ranges loaded. */
	public function count(): int {
		return (int) $this->db->get_var( "SELECT COUNT(*) FROM {$this->table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/** Remove every range. */
	public function truncate(): void {
		$this->db->query( "TRUNCATE TABLE {$this->table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * Insert a batch of ranges from CsvImporter::parse_row().
	 *
	 * @param array<int, array{from: string, to: string, country: string}> $rows Ranges.
	 */
	public function insert_batch( array $rows ): void {
		if ( empty( $rows ) ) {
			return;
		}
		$placeholders = array();
		$values       = array();
		foreach ( $rows as $row ) {
			$placeholders[] = '(%s, %s, %s)';
			$values[]       = $row['from'];
			$values[]       = $row['to'];
			$values[]       = $row['country'];
		}
		// phpcs:ignore WordPress.DB.PreparedSQL -- placeholders are built above.
		$this->db->query( $this->db->prepare( "INSERT IGNORE INTO {$this->table} (ip_from, ip_to, country) VALUES " . implode( ',', $placeholders ), $values ) );
	}

	/**
	 * Replace the whole table with a CSV file.
	 *
	 * @param string $path CSV or CSV.gz path.
	 * @return array{imported: int, skipped: int}
	 */
	public function import_file( string $path ): array {
		$this->truncate();
		return CsvImporter::import( $path, array( $this, 'insert_batch' ), 500 );
	}
}
