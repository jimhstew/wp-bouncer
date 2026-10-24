<?php
/**
 * The wpb_manage_firewall meta capability.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Actions that reach beyond one site (fetching URLs, writing .htaccess, the
 * PHP probe, regular expressions that run on every request) need this
 * capability. It maps to manage_options on a single site and to
 * manage_network_options on multisite, so only network admins have it there.
 * Others can remap it with their own map_meta_cap callback.
 */
final class FirewallCapability {

	/** Meta capability name. */
	public const NAME = 'wpb_manage_firewall';

	/** Hook in. */
	public static function register(): void {
		add_filter( 'map_meta_cap', array( self::class, 'map' ), 10, 2 );
	}

	/**
	 * Map the meta capability to a primitive one.
	 *
	 * @param mixed  $caps Primitive capabilities required so far.
	 * @param string $cap  Capability being checked.
	 * @return mixed
	 */
	public static function map( $caps, $cap ) {
		if ( self::NAME !== $cap ) {
			return $caps;
		}
		return array( is_multisite() ? 'manage_network_options' : 'manage_options' );
	}
}
