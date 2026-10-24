<?php
/**
 * Database-backed block log: what was blocked, when, and why.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Log;

defined( 'ABSPATH' ) || exit;

/**
 * Reads and writes {prefix}bouncer_log. Times are stored in UTC.
 *
 * The admin Activity Log screen and the dashboard widgets read through the
 * query helpers here. The firewall only ever calls record().
 */
final class BlockLog implements BlockLogInterface {

	/** Column length limits (match the schema in Installer). */
	private const LIMITS = array(
		'ip'         => 45,
		'country'    => 2,
		'rule'       => 32,
		'action'     => 16,
		'reason'     => 255,
		'method'     => 10,
		'uri'        => 2048,
		'user_agent' => 512,
	);

	/**
	 * WordPress database handle.
	 *
	 * @var \wpdb
	 */
	private $db;
	/**
	 * Fully prefixed table name.
	 *
	 * @var string
	 */
	private string $table;

	/**
	 * Set up the BlockLog.
	 *
	 * @param \wpdb $db WordPress database handle.
	 */
	public function __construct( $db ) {
		$this->db    = $db;
		$this->table = $db->prefix . 'bouncer_log';
	}

	/** Fully-qualified table name. */
	public function table(): string {
		return $this->table;
	}

	/**
	 * Coerce an entry to the schema: every column present, strings truncated.
	 *
	 * @param array<string, mixed> $entry Raw entry.
	 * @return array<string, string>
	 */
	public static function normalize( array $entry ): array {
		$out = array();
		foreach ( self::LIMITS as $column => $limit ) {
			$value          = isset( $entry[ $column ] ) && is_scalar( $entry[ $column ] ) ? (string) $entry[ $column ] : '';
			$value          = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $value );
			$out[ $column ] = function_exists( 'mb_substr' ) ? mb_substr( $value, 0, $limit ) : substr( $value, 0, $limit );
		}
		if ( '' === $out['action'] ) {
			$out['action'] = self::ACTION_BLOCKED;
		}
		return $out;
	}

	/**
	 * Record one event.
	 *
	 * @param array<string, string> $entry Event fields: ip, country, rule, action, reason, method, uri, user_agent.
	 * @return int Inserted row id (0 when not stored).
	 */
	public function record( array $entry ): int {
		$row               = self::normalize( $entry );
		$row['created_at'] = gmdate( 'Y-m-d H:i:s' );
		$ok                = $this->db->insert( $this->table, $row );
		return $ok ? (int) $this->db->insert_id : 0;
	}

	/**
	 * Build a WHERE clause from filters.
	 *
	 * @param array<string, string> $filters rule, action, search, since (Y-m-d H:i:s UTC).
	 * @return array{0: string, 1: array<int, string>} SQL fragment and its arguments.
	 */
	private function where( array $filters ): array {
		$sql  = array( '1=1' );
		$args = array();
		foreach ( array( 'rule', 'action', 'country' ) as $col ) {
			if ( ! empty( $filters[ $col ] ) ) {
				$sql[]  = "{$col} = %s";
				$args[] = (string) $filters[ $col ];
			}
		}
		if ( ! empty( $filters['since'] ) ) {
			$sql[]  = 'created_at >= %s';
			$args[] = (string) $filters['since'];
		}
		if ( ! empty( $filters['search'] ) ) {
			$like   = '%' . $this->db->esc_like( (string) $filters['search'] ) . '%';
			$sql[]  = '(ip LIKE %s OR uri LIKE %s OR reason LIKE %s OR user_agent LIKE %s)';
			$args[] = $like;
			$args[] = $like;
			$args[] = $like;
			$args[] = $like;
		}
		return array( implode( ' AND ', $sql ), $args );
	}

	/**
	 * Prepare only when there are arguments ($wpdb->prepare() rejects none).
	 *
	 * @param string            $sql  SQL.
	 * @param array<int, mixed> $args Arguments.
	 */
	private function prepare( string $sql, array $args ): string {
		return $args ? $this->db->prepare( $sql, $args ) : $sql;
	}

	/**
	 * Fetch a page of log rows, newest first by default.
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
		$orderby              = in_array( $orderby, array( 'created_at', 'ip', 'country', 'rule', 'action' ), true ) ? $orderby : 'created_at';
		$order                = 'ASC' === strtoupper( $order ) ? 'ASC' : 'DESC';
		$per_page             = max( 1, min( 1000, $per_page ) );
		$offset               = ( max( 1, $page ) - 1 ) * $per_page;

		$sql = "SELECT * FROM {$this->table} WHERE {$where} ORDER BY {$orderby} {$order}, id {$order} LIMIT {$per_page} OFFSET {$offset}";
		return (array) $this->db->get_results( $this->prepare( $sql, $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL -- $sql only interpolates the $wpdb->prefix table name, $where (fixed fragments with %s placeholders from where()), an allow-listed column, ASC/DESC and int-cast limit/offset; user values are bound via prepare().
	}

	/**
	 * Count rows matching filters.
	 *
	 * @param array<string, string> $filters See where().
	 */
	public function count( array $filters = array() ): int {
		list( $where, $args ) = $this->where( $filters );
		return (int) $this->db->get_var( $this->prepare( "SELECT COUNT(*) FROM {$this->table} WHERE {$where}", $args ) ); // phpcs:ignore WordPress.DB.PreparedSQL -- $where is built from fixed fragments with %s placeholders in where() and its values are bound via prepare(); the table name is built from $wpdb->prefix.
	}

	/**
	 * Counts grouped by a column since a time.
	 *
	 * @param string $column rule|ip|country|action.
	 * @param string $since  UTC datetime.
	 * @param int    $limit  Max groups.
	 * @return array<string, int> value => count, largest first. Alerts are not counted.
	 */
	public function top( string $column, string $since, int $limit = 10 ): array {
		if ( ! in_array( $column, array( 'rule', 'ip', 'country', 'action' ), true ) ) {
			return array();
		}
		$limit = max( 1, min( 100, $limit ) );
		$rows  = $this->db->get_results(
			$this->db->prepare( "SELECT {$column} AS k, COUNT(*) AS n FROM {$this->table} WHERE created_at >= %s AND {$column} <> '' AND action <> 'alert' GROUP BY {$column} ORDER BY n DESC LIMIT {$limit}", $since ), // phpcs:ignore WordPress.DB.PreparedSQL -- $column is checked against an allow-list above, $limit is an int clamped to 1-100 and $since is bound with %s; the table name is built from $wpdb->prefix.
			ARRAY_A
		);
		$out   = array();
		foreach ( (array) $rows as $row ) {
			$out[ (string) $row['k'] ] = (int) $row['n'];
		}
		return $out;
	}

	/**
	 * Events per UTC day for the last $days days (missing days are 0).
	 * Alerts are not counted: they are notices, not blocked visitors.
	 *
	 * @param int $days Number of days including today.
	 * @return array<string, int> Y-m-d => count, oldest first.
	 */
	public function per_day( int $days ): array {
		$days  = max( 1, min( 365, $days ) );
		$start = gmdate( 'Y-m-d 00:00:00', time() - ( $days - 1 ) * DAY_IN_SECONDS );
		$rows  = $this->db->get_results(
			$this->db->prepare( "SELECT DATE(created_at) AS d, COUNT(*) AS n FROM {$this->table} WHERE created_at >= %s AND action <> 'alert' GROUP BY DATE(created_at)", $start ), // phpcs:ignore WordPress.DB.PreparedSQL -- the table name is built from $wpdb->prefix and the only variable value is bound with a %s placeholder.
			ARRAY_A
		);
		$out   = array();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$out[ gmdate( 'Y-m-d', time() - $i * DAY_IN_SECONDS ) ] = 0;
		}
		foreach ( (array) $rows as $row ) {
			if ( isset( $out[ $row['d'] ] ) ) {
				$out[ $row['d'] ] = (int) $row['n'];
			}
		}
		return $out;
	}

	/**
	 * Delete rows older than $days days.
	 *
	 * @param int $days Retention in days.
	 * @return int Rows deleted.
	 */
	public function purge_older_than( int $days ): int {
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, $days ) * DAY_IN_SECONDS );
		return (int) $this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE created_at < %s", $cutoff ) ); // phpcs:ignore WordPress.DB.PreparedSQL -- the table name is built from $wpdb->prefix and the only variable value is bound with a %s placeholder.
	}

	/** Delete every row. */
	public function clear(): void {
		$this->db->query( "TRUNCATE TABLE {$this->table}" ); // phpcs:ignore WordPress.DB.PreparedSQL -- no user input; the table name is built from $wpdb->prefix and these statements take no placeholders.
	}
}
