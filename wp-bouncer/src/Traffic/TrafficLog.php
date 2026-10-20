<?php
/**
 * Database-backed traffic log: every request that reached WordPress.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Traffic;

defined( 'ABSPATH' ) || exit;

/**
 * Reads and writes {prefix}bouncer_traffic. Times are stored in UTC.
 *
 * Rows are kept for at most a week (see Settings, traffic.retention_days)
 * and removed by an hourly cron job.
 */
final class TrafficLog {

	/** Longest retention the settings allow, in days. */
	public const MAX_DAYS = 7;

	/** Columns the list can be sorted by. */
	private const SORTABLE = array( 'created_at', 'ip', 'client', 'status', 'method' );

	/** @var \wpdb */
	private $db;
	private string $table;

	/**
	 * @param \wpdb $db WordPress database handle.
	 */
	public function __construct( $db ) {
		$this->db    = $db;
		$this->table = $db->prefix . 'bouncer_traffic';
	}

	/** Fully-qualified table name. */
	public function table(): string {
		return $this->table;
	}

	/**
	 * Store one request.
	 *
	 * @param array<string, mixed> $data See TrafficEntry::build().
	 * @return int Row id, or 0 when not stored.
	 */
	public function record( array $data ): int {
		$row               = TrafficEntry::build( $data );
		$row['created_at'] = gmdate( 'Y-m-d H:i:s' );
		// A missing table (an upgrade that hasn't run yet) must not print errors into a page.
		$suppress = $this->db->suppress_errors( true );
		$ok       = $this->db->insert( $this->table, $row, array( '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s' ) );
		$this->db->suppress_errors( $suppress );
		return $ok ? (int) $this->db->insert_id : 0;
	}

	/**
	 * WHERE clause from filters.
	 *
	 * @param array<string, string> $filters client, status (2xx…5xx), ip, search, since (UTC).
	 * @return array{0: string, 1: array<int, string|int>}
	 */
	private function where( array $filters ): array {
		$sql  = array( '1=1' );
		$args = array();
		if ( ! empty( $filters['client'] ) ) {
			$sql[]  = 'client = %s';
			$args[] = (string) $filters['client'];
		}
		if ( ! empty( $filters['ip'] ) ) {
			$sql[]  = 'ip = %s';
			$args[] = (string) $filters['ip'];
		}
		$range = TrafficEntry::status_range( (string) ( $filters['status'] ?? '' ) );
		if ( null !== $range ) {
			$sql[]  = 'status BETWEEN %d AND %d';
			$args[] = $range[0];
			$args[] = $range[1];
		}
		if ( ! empty( $filters['since'] ) ) {
			$sql[]  = 'created_at >= %s';
			$args[] = (string) $filters['since'];
		}
		if ( ! empty( $filters['search'] ) ) {
			$like   = '%' . $this->db->esc_like( (string) $filters['search'] ) . '%';
			$sql[]  = '(ip LIKE %s OR uri LIKE %s OR referrer LIKE %s OR user_agent LIKE %s)';
			$args[] = $like;
			$args[] = $like;
			$args[] = $like;
			$args[] = $like;
		}
		return array( implode( ' AND ', $sql ), $args );
	}

	/**
	 * Prepare only when there are arguments.
	 *
	 * @param string            $sql  SQL.
	 * @param array<int, mixed> $args Arguments.
	 */
	private function prepare( string $sql, array $args ): string {
		return $args ? $this->db->prepare( $sql, $args ) : $sql;
	}

	/**
	 * A page of rows, newest first by default.
	 *
	 * @param array<string, string> $filters  See where().
	 * @param int                   $per_page Rows per page.
	 * @param int                   $page     1-based page.
	 * @param string                $orderby  Column.
	 * @param string                $order    ASC|DESC.
	 * @return array<int, array<string, string>>
	 */
	public function query( array $filters = array(), int $per_page = 50, int $page = 1, string $orderby = 'created_at', string $order = 'DESC' ): array {
		list( $where, $args ) = $this->where( $filters );
		$orderby              = in_array( $orderby, self::SORTABLE, true ) ? $orderby : 'created_at';
		$order                = 'ASC' === strtoupper( $order ) ? 'ASC' : 'DESC';
		$per_page             = max( 1, min( 1000, $per_page ) );
		$offset               = ( max( 1, $page ) - 1 ) * $per_page;

		$sql = "SELECT * FROM {$this->table} WHERE {$where} ORDER BY {$orderby} {$order}, id {$order} LIMIT {$per_page} OFFSET {$offset}";
		return (array) $this->db->get_results( $this->prepare( $sql, $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL
	}

	/**
	 * Rows matching filters.
	 *
	 * @param array<string, string> $filters See where().
	 */
	public function count( array $filters = array() ): int {
		list( $where, $args ) = $this->where( $filters );
		return (int) $this->db->get_var( $this->prepare( "SELECT COUNT(*) FROM {$this->table} WHERE {$where}", $args ) ); // phpcs:ignore WordPress.DB.PreparedSQL
	}

	/**
	 * Distinct IPs since a time.
	 *
	 * @param string $since UTC datetime.
	 */
	public function unique_ips( string $since ): int {
		return (int) $this->db->get_var( $this->db->prepare( "SELECT COUNT(DISTINCT ip) FROM {$this->table} WHERE created_at >= %s", $since ) ); // phpcs:ignore WordPress.DB.PreparedSQL
	}

	/**
	 * Requests per client type since a time.
	 *
	 * @param string $since UTC datetime.
	 * @return array<string, int> Type => count, largest first.
	 */
	public function by_client( string $since ): array {
		$rows = $this->db->get_results( $this->db->prepare( "SELECT client AS k, COUNT(*) AS n FROM {$this->table} WHERE created_at >= %s GROUP BY client ORDER BY n DESC", $since ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$out[ (string) $row['k'] ] = (int) $row['n'];
		}
		return $out;
	}

	/**
	 * Delete rows older than $days days.
	 *
	 * @param int $days Retention in days (1 to MAX_DAYS).
	 * @return int Rows deleted.
	 */
	public function purge_older_than( int $days ): int {
		$days   = max( 1, min( self::MAX_DAYS, $days ) );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		return (int) $this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE created_at < %s", $cutoff ) ); // phpcs:ignore WordPress.DB.PreparedSQL
	}

	/** Delete every row. */
	public function clear(): void {
		$this->db->query( "DELETE FROM {$this->table}" ); // phpcs:ignore WordPress.DB.PreparedSQL
	}
}
