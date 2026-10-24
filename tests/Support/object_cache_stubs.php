<?php
/**
 * Minimal wp_cache_* functions in the plugin's Storage namespace, for ObjectCacheCounter unit tests.
 * Unqualified calls inside that namespace resolve here before the global functions.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Storage;

/** Cache contents: "group:key" => int. */
function wpb_test_cache( ?array $replace = null ): array {
	static $cache = array();
	if ( null !== $replace ) {
		$cache = $replace;
	}
	return $cache;
}

function wp_cache_add( $key, $value, $group = '', $ttl = 0 ) {
	$c = wpb_test_cache();
	if ( isset( $c[ "$group:$key" ] ) ) {
		return false;
	}
	$c[ "$group:$key" ] = $value;
	wpb_test_cache( $c );
	return true;
}

function wp_cache_set( $key, $value, $group = '', $ttl = 0 ) {
	$c                  = wpb_test_cache();
	$c[ "$group:$key" ] = $value;
	wpb_test_cache( $c );
	return true;
}

function wp_cache_incr( $key, $by = 1, $group = '' ) {
	$c = wpb_test_cache();
	if ( ! isset( $c[ "$group:$key" ] ) ) {
		return false;
	}
	$c[ "$group:$key" ] += $by;
	wpb_test_cache( $c );
	return $c[ "$group:$key" ];
}

function wp_cache_decr( $key, $by = 1, $group = '' ) {
	$c = wpb_test_cache();
	if ( ! isset( $c[ "$group:$key" ] ) ) {
		return false;
	}
	$c[ "$group:$key" ] = max( 0, $c[ "$group:$key" ] - $by );
	wpb_test_cache( $c );
	return $c[ "$group:$key" ];
}

function wp_cache_get( $key, $group = '', $force = false ) {
	$c = wpb_test_cache();
	return $c[ "$group:$key" ] ?? false;
}

function wp_cache_delete( $key, $group = '' ) {
	$c = wpb_test_cache();
	unset( $c[ "$group:$key" ] );
	wpb_test_cache( $c );
	return true;
}
