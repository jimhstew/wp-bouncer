<?php
/**
 * Builds the settings fingerprint.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

use WPBouncer\SettingsDiff;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP. One keyed MAC per settings leaf, taken from the raw option value, plus a "settings" leaf
 * for the shape of the option (array, missing or other).
 */
final class SettingsFingerprint {

	/** Canonical encoding of a leaf that is not in the option. */
	public const ABSENT = 'absent';

	/** Leaf of the site admin email: the address that always receives a forced drift mail. */
	public const SITE_EMAIL = 'wp.admin_email';

	/** Leaf of the network admin email (multisite only; absent elsewhere). */
	public const NETWORK_EMAIL = 'wp.network_admin_email';

	/**
	 * Fingerprint a raw option value.
	 *
	 * @param mixed                $raw     What get_option() returned, or the value written.
	 * @param bool                 $present Is the option there (false when it is missing).
	 * @param FingerprintKey       $key     Key.
	 * @param int                  $logged  Time of the last drift row to store in the record.
	 * @param array<string, mixed> $extra Extra leaves by path (SITE_EMAIL, NETWORK_EMAIL); null means absent.
	 * @param array<string, mixed> $pending A drift found but not yet logged: kind and paths (empty = none).
	 */
	public static function record( mixed $raw, bool $present, FingerprintKey $key, int $logged, array $extra = array(), array $pending = array() ): FingerprintRecord {
		$raw    = $present ? $raw : false;
		$leaves = array();
		foreach ( SettingsDiff::leaves( $raw ) as $path => $leaf ) {
			$leaves[ $path ] = $key->leaf( $path, self::canonical( $leaf[0], $leaf[1] ) );
		}
		$shape              = $present ? ( is_array( $raw ) ? 'array' : 'other' ) : 'missing';
		$leaves['settings'] = $key->leaf( 'settings', self::canonical( true, $shape ) );
		foreach ( $extra as $path => $value ) {
			$leaves[ (string) $path ] = $key->leaf( (string) $path, self::canonical( null !== $value, $value ) );
		}
		return FingerprintRecord::sealed( $key, $logged, $leaves, $pending );
	}

	/**
	 * Paths of the leaves that records written before format 2 do not have.
	 *
	 * @return string[]
	 */
	public static function extra_paths(): array {
		return array( self::SITE_EMAIL, self::NETWORK_EMAIL );
	}

	/**
	 * Canonical text of one leaf value: key order does not matter, list order and types do.
	 *
	 * @param bool  $present Is the path there.
	 * @param mixed $value   Value.
	 * @return string "absent", "v:<json>", or "p:<serialized>" when the value cannot be encoded as JSON.
	 */
	public static function canonical( bool $present, mixed $value ): string {
		if ( ! $present ) {
			return self::ABSENT;
		}
		$value = self::sort_keys( $value );
		try {
			return 'v:' . json_encode( $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- pure PHP class, no WordPress calls.
		} catch ( \JsonException $e ) {
			unset( $e );
			return 'p:' . serialize( $value ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- only hashed, never unserialized.
		}
	}

	/**
	 * Sort the keys of arrays that are not lists, at every depth.
	 *
	 * @param mixed $value Value.
	 * @return mixed
	 */
	private static function sort_keys( mixed $value ): mixed {
		if ( ! is_array( $value ) ) {
			return $value;
		}
		foreach ( $value as $k => $v ) {
			$value[ $k ] = self::sort_keys( $v );
		}
		if ( ! array_is_list( $value ) ) {
			ksort( $value, SORT_STRING );
		}
		return $value;
	}
}
