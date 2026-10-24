<?php
/**
 * The real server, behind EnvironmentInterface.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Reads PHP_VERSION, the DB driver's version string (no SQL), ini values and constants.
 */
final class RuntimeEnvironment implements EnvironmentInterface {

	/** {@inheritDoc} */
	public function php_version(): string {
		return PHP_VERSION;
	}

	/** {@inheritDoc} */
	public function db_server_info(): string {
		global $wpdb;
		return isset( $wpdb ) && method_exists( $wpdb, 'db_server_info' ) ? (string) $wpdb->db_server_info() : '';
	}

	/** {@inheritDoc} */
	public function sapi(): string {
		return PHP_SAPI;
	}

	/**
	 * A php.ini value.
	 *
	 * @param string $name Directive.
	 */
	public function ini( string $name ): string|false {
		$value = ini_get( $name );
		return false === $value ? false : (string) $value;
	}

	/**
	 * A constant's value, or null if undefined.
	 *
	 * @param string $name Constant.
	 */
	public function constant( string $name ): mixed {
		return defined( $name ) ? constant( $name ) : null;
	}

	/** {@inheritDoc} */
	public function is_https(): bool {
		return function_exists( 'is_ssl' ) && is_ssl();
	}

	/**
	 * Is a path inside the web root?
	 *
	 * @param string $path File or folder.
	 */
	public function inside_web_root( string $path ): ?bool {
		if ( '' === $path ) {
			return null;
		}
		// For a file that does not exist yet, look at its folder. Symbolic links are resolved by
		// realpath(), but a link inside the WordPress folder that points elsewhere (or the reverse)
		// is judged by where it ends up, not by how the web server is set up: this is a hint.
		$real = realpath( is_dir( $path ) ? $path : dirname( $path ) );
		$root = realpath( ABSPATH );
		if ( false === $real || false === $root ) {
			return null;
		}
		$roots = array( $root );
		// WordPress in a subdirectory: when the folder above has its own index.php, that is the web root.
		$parent = dirname( $root );
		if ( $parent !== $root && is_file( $parent . DIRECTORY_SEPARATOR . 'index.php' ) ) {
			$roots[] = $parent;
		}
		$real = rtrim( $real, '/\\' ) . DIRECTORY_SEPARATOR;
		foreach ( $roots as $dir ) {
			if ( str_starts_with( $real, rtrim( $dir, '/\\' ) . DIRECTORY_SEPARATOR ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Size of a file.
	 *
	 * @param string $path File.
	 */
	public function file_size( string $path ): ?int {
		if ( '' === $path || ! is_file( $path ) || ! is_readable( $path ) ) {
			return null;
		}
		$size = filesize( $path );
		return false === $size ? null : $size;
	}
}
