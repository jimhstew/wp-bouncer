<?php
/**
 * PHPUnit bootstrap.
 *
 * The unit tests cover the plain-PHP core (rules, firewall, settings, IP
 * maths, geo parsing). They need no WordPress install and no database.
 *
 * @package WPBouncer\Tests
 */

// Source files guard against direct access with defined( 'ABSPATH' ).
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

$root   = dirname( __DIR__ );
$plugin = $root . '/wp-bouncer';

if ( is_readable( $root . '/vendor/autoload.php' ) ) {
	require_once $root . '/vendor/autoload.php';
}

require_once $root . '/tests/Support/i18n_stubs.php';
require_once $plugin . '/src/Autoloader.php';
\WPBouncer\Autoloader::register( $plugin . '/src' );

spl_autoload_register(
	static function ( string $class ) use ( $root ): void {
		$prefix = 'WPBouncer\\Tests\\';
		if ( 0 === strpos( $class, $prefix ) ) {
			$file = $root . '/tests/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
			if ( is_readable( $file ) ) {
				require_once $file;
			}
		}
	}
);
