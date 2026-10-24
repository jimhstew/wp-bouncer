<?php
/**
 * What the checks may ask about the server.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * A narrow window onto PHP, the database and WordPress constants, so the
 * checks can be tested with a fake.
 */
interface EnvironmentInterface {

	/** PHP version string (PHP_VERSION). */
	public function php_version(): string;

	/** Database server string from the driver (no SQL is run). */
	public function db_server_info(): string;

	/** PHP SAPI name, for example "fpm-fcgi". */
	public function sapi(): string;

	/**
	 * A php.ini value.
	 *
	 * @param string $name Directive.
	 * @return string|false The value, or false if the directive is unknown.
	 */
	public function ini( string $name ): string|false;

	/**
	 * A constant's value.
	 *
	 * @param string $name Constant name.
	 * @return mixed Null if it is not defined.
	 */
	public function constant( string $name ): mixed;

	/** Is the current request over HTTPS? */
	public function is_https(): bool;

	/**
	 * Is a path (or the folder holding it) inside the WordPress folder, where the web server can usually serve it?
	 *
	 * @param string $path File or folder.
	 * @return bool|null Null when it cannot be told.
	 */
	public function inside_web_root( string $path ): ?bool;

	/**
	 * Size of a file.
	 *
	 * @param string $path File.
	 * @return int|null Bytes, or null if it does not exist or cannot be read.
	 */
	public function file_size( string $path ): ?int;
}
