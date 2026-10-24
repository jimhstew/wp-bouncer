<?php
/**
 * Turns version strings into the branches the support policy knows.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Pure. Distribution suffixes are ignored; managed or unusual databases
 * (Aurora, Azure, TiDB, SQLite...) give null, which means "unknown", not a warning.
 */
final class VersionParser {

	/**
	 * PHP branch.
	 *
	 * @param string $version PHP_VERSION, for example "8.3.12-1ubuntu" or "8.4.0RC1".
	 * @return string|null "8.3", or null.
	 */
	public static function php( string $version ): ?string {
		return 1 === preg_match( '/^(\d+)\.(\d+)/', trim( $version ), $m ) ? $m[1] . '.' . $m[2] : null;
	}

	/**
	 * Database product and branch.
	 *
	 * @param string $server_info Driver version string.
	 * @return array{product: string, branch: string}|null
	 */
	public static function database( string $server_info ): ?array {
		$info = trim( $server_info );
		if ( '' === $info || 1 === preg_match( '/aurora|azure|tidb|sqlite|vitess|cockroach|postgres/i', $info ) ) {
			return null;
		}
		$maria = false !== stripos( $info, 'mariadb' );
		if ( $maria ) {
			// Older clients report MariaDB as "5.5.5-10.6.18-MariaDB...": the real version follows.
			$info = (string) preg_replace( '/^5\.5\.5-/', '', $info );
		}
		if ( 1 !== preg_match( '/^(\d+)\.(\d+)/', $info, $m ) ) {
			return null;
		}
		return array(
			'product' => $maria ? 'mariadb' : 'mysql',
			'branch'  => $m[1] . '.' . $m[2],
		);
	}
}
