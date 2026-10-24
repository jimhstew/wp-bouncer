<?php
/**
 * Which PHP, MySQL and MariaDB branches still get security fixes.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Bundled data, no network. To update it: edit BRANCHES below and set
 * VERIFIED_ON to the day you checked the sources (release checklist item):
 *
 * - PHP:     https://www.php.net/supported-versions.php
 * - MySQL:   Oracle Lifetime Support Policy (day-level dates via https://endoflife.date/mysql;
 *            https://www.mysql.com/support/eol-notice.html records the end of each branch)
 * - MariaDB: https://mariadb.org/about/#maintenance-policy
 *
 * `security_until` is the last day (UTC, inclusive) of security support.
 * Where a source gives only a month, the last day of that month is used.
 * MySQL uses the end of Extended Support, the last day Oracle ships fixes for
 * the branch (community releases continue until then, as 8.0 did to April 2026).
 * A branch that is not listed is never "supported". If it is older than the
 * newest listed branch of its product it is treated as past the end of
 * support (that covers MySQL 5.6, Innovation releases and short-term MariaDB
 * releases, which all end when the next one ships). If it is newer than every
 * listed branch it is "unknown" until the table is updated.
 */
final class SupportPolicy {

	/** Day the table below was last checked against the sources. */
	public const VERIFIED_ON = '2026-10-24';

	/** A branch is "ending" within this many days of its last security day. */
	public const ENDING_DAYS = 90;

	/** After this many days without a re-check, "supported" is reported as "unknown". */
	public const STALE_DAYS = 365;

	/**
	 * Product => branch => last day of security support.
	 *
	 * @var array<string, array<string, array{security_until: string, lts: bool}>>
	 */
	private const BRANCHES = array(
		'php'     => array(
			'7.4' => array(
				'security_until' => '2022-11-28',
				'lts'            => false,
			),
			'8.0' => array(
				'security_until' => '2023-11-26',
				'lts'            => false,
			),
			'8.1' => array(
				'security_until' => '2025-12-31',
				'lts'            => false,
			),
			'8.2' => array(
				'security_until' => '2026-12-31',
				'lts'            => false,
			),
			'8.3' => array(
				'security_until' => '2027-12-31',
				'lts'            => false,
			),
			'8.4' => array(
				'security_until' => '2028-12-31',
				'lts'            => false,
			),
			'8.5' => array(
				'security_until' => '2029-12-31',
				'lts'            => false,
			),
		),
		'mysql'   => array(
			'5.7' => array(
				'security_until' => '2023-10-31',
				'lts'            => true,
			),
			'8.0' => array(
				'security_until' => '2026-04-30',
				'lts'            => true,
			),
			'8.4' => array(
				'security_until' => '2032-04-30',
				'lts'            => true,
			),
			'9.7' => array(
				'security_until' => '2034-04-30',
				'lts'            => true,
			),
		),
		'mariadb' => array(
			'10.3'  => array(
				'security_until' => '2023-05-25',
				'lts'            => true,
			),
			'10.4'  => array(
				'security_until' => '2024-06-18',
				'lts'            => true,
			),
			'10.5'  => array(
				'security_until' => '2025-06-24',
				'lts'            => true,
			),
			'10.6'  => array(
				'security_until' => '2026-07-06',
				'lts'            => true,
			),
			'10.11' => array(
				'security_until' => '2028-02-16',
				'lts'            => true,
			),
			'11.4'  => array(
				'security_until' => '2029-05-29',
				'lts'            => true,
			),
			'11.8'  => array(
				'security_until' => '2028-06-04',
				'lts'            => true,
			),
			'12.3'  => array(
				'security_until' => '2029-06-12',
				'lts'            => true,
			),
		),
	);

	/**
	 * Last day of security support for a branch.
	 *
	 * @param string $product php|mysql|mariadb.
	 * @param string $branch  For example "8.3".
	 * @return string|null "YYYY-MM-DD", or null if the branch is not in the table.
	 */
	public function security_until( string $product, string $branch ): ?string {
		return self::BRANCHES[ $product ][ $branch ]['security_until'] ?? null;
	}

	/**
	 * Where does a branch stand?
	 *
	 * @param string $product php|mysql|mariadb.
	 * @param string $branch  For example "8.3".
	 * @param int    $now     Unix time.
	 * @return Severity Ok, Notice (ending within ENDING_DAYS), Critical (past the end, or an unlisted
	 *                  branch older than the newest listed one) or Unknown (newer than every listed branch).
	 *                  If the table is stale, "Ok" is reported as Unknown.
	 */
	public function status( string $product, string $branch, int $now ): Severity {
		$until = $this->security_until( $product, $branch );
		if ( null === $until ) {
			// Not listed. Older than the newest listed branch means it ended when a newer one shipped
			// (MySQL 5.6, an Innovation release, a short-term MariaDB); newer than all of them is unknown.
			return $this->is_older_than_listed( $product, $branch ) ? Severity::Critical : Severity::Unknown;
		}
		$end = (int) strtotime( $until . ' 23:59:59 UTC' );
		if ( $now > $end ) {
			return Severity::Critical;
		}
		if ( $end - $now <= self::ENDING_DAYS * 86400 ) {
			return Severity::Notice;
		}
		return $this->is_stale( $now ) ? Severity::Unknown : Severity::Ok;
	}

	/**
	 * Is an unlisted branch lower than the newest branch of its product?
	 *
	 * @param string $product php|mysql|mariadb.
	 * @param string $branch  For example "5.6".
	 */
	private function is_older_than_listed( string $product, string $branch ): bool {
		$listed = array_keys( self::BRANCHES[ $product ] ?? array() );
		if ( array() === $listed || 1 !== preg_match( '/^\d+\.\d+$/', $branch ) ) {
			return false;
		}
		usort( $listed, static fn( $a, $b ): int => version_compare( (string) $a, (string) $b ) );
		return version_compare( $branch, (string) end( $listed ), '<' );
	}

	/**
	 * Has the table gone too long without a re-check?
	 *
	 * @param int $now Unix time.
	 */
	public function is_stale( int $now ): bool {
		return $now - (int) strtotime( self::VERIFIED_ON . ' 00:00:00 UTC' ) > self::STALE_DAYS * 86400;
	}
}
