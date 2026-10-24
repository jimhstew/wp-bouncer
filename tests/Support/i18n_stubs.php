<?php
/**
 * Minimal stand-ins for the few WordPress helpers that pure classes call for display text.
 *
 * Only loaded by the unit bootstrap (the integration suite has real WordPress).
 *
 * @package WPBouncer\Tests
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO, WordPress.NamingConventions.PrefixAllGlobals

if ( ! function_exists( '__' ) ) {
	/** Return the text unchanged. */
	function __( string $text, string $domain = 'default' ): string {
		return $text;
	}
}

if ( ! function_exists( '_n' ) ) {
	/** Pick singular or plural. */
	function _n( string $single, string $plural, int $number, string $domain = 'default' ): string {
		return 1 === $number ? $single : $plural;
	}
}

if ( ! function_exists( 'size_format' ) ) {
	/** Short size text, in the same style as core ("64 MB"). */
	function size_format( int $bytes ): string {
		foreach ( array(
			'GB' => 1073741824,
			'MB' => 1048576,
			'KB' => 1024,
		) as $unit => $size ) {
			if ( $bytes >= $size ) {
				return round( $bytes / $size ) . ' ' . $unit;
			}
		}
		return $bytes . ' B';
	}
}
