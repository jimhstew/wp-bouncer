<?php
/**
 * Minimal PSR-4 autoloader so the plugin runs without Composer.
 *
 * Maps the WPBouncer\ namespace onto the src/ directory:
 * WPBouncer\Rules\WafRule => src/Rules/WafRule.php
 *
 * @package WPBouncer
 */

namespace WPBouncer;

defined( 'ABSPATH' ) || exit;

/**
 * Registers an spl autoloader for the plugin's classes.
 */
final class Autoloader {

	private const PREFIX = 'WPBouncer\\';

	/**
	 * Register the autoloader.
	 *
	 * @param string $base_dir Absolute path to the src/ directory.
	 */
	public static function register( string $base_dir ): void {
		$base_dir = rtrim( $base_dir, '/\\' ) . '/';

		spl_autoload_register(
			static function ( string $class ) use ( $base_dir ): void {
				if ( 0 !== strpos( $class, self::PREFIX ) ) {
					return;
				}
				$relative = substr( $class, strlen( self::PREFIX ) );
				$file     = $base_dir . str_replace( '\\', '/', $relative ) . '.php';
				if ( is_readable( $file ) ) {
					require_once $file;
				}
			}
		);
	}
}
