<?php
/**
 * Decides what a stored fingerprint says about the current settings.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP, no I/O. The decision table of the design, in order.
 */
final class DriftDetector {

	/**
	 * Compare the stored record with the one built from the current settings.
	 *
	 * @param FingerprintRecord|null $stored  Stored record (null when missing or unparsable).
	 * @param FingerprintRecord      $current Record built from the current raw option.
	 * @param FingerprintKey         $key     Key.
	 * @param bool                   $marker  True when a baseline was set before.
	 */
	public static function compare( ?FingerprintRecord $stored, FingerprintRecord $current, FingerprintKey $key, bool $marker ): DriftVerdict {
		if ( null === $stored ) {
			return new DriftVerdict( $marker ? DriftVerdict::FINGERPRINT_MISSING : DriftVerdict::BASELINE );
		}
		if ( $stored->kid !== $key->kid() ) {
			return new DriftVerdict( DriftVerdict::KEYS_CHANGED );
		}
		if ( ! $stored->seal_valid( $key ) ) {
			$paths = array();
			foreach ( array_unique( array_merge( array_keys( $stored->leaves ), array_keys( $current->leaves ) ) ) as $path ) {
				if ( ( $stored->leaves[ $path ] ?? null ) !== ( $current->leaves[ $path ] ?? null ) ) {
					$paths[] = (string) $path;
				}
			}
			sort( $paths, SORT_STRING );
			return new DriftVerdict( DriftVerdict::FINGERPRINT_ALTERED, $paths );
		}
		$changed = array();
		$schema  = false;
		foreach ( $current->leaves as $path => $mac ) {
			$path = (string) $path;
			if ( isset( $stored->leaves[ $path ] ) ) {
				if ( $stored->leaves[ $path ] !== $mac ) {
					$changed[] = $path;
				}
			} elseif ( $stored->version < 2 && in_array( $path, SettingsFingerprint::extra_paths(), true ) ) {
				$schema = true; // A format 1 record has no email leaves: re-baseline once, silently.
			} elseif ( $mac !== $key->leaf( $path, SettingsFingerprint::canonical( false, null ) ) ) {
				$changed[] = $path; // A leaf that is new to the schema but present in the option.
			} else {
				$schema = true;
			}
		}
		if ( ! empty( $changed ) ) {
			sort( $changed, SORT_STRING );
			if ( in_array( 'settings', $changed, true ) ) {
				// A deleted or corrupted option changes everything: name it first, before the list is cut.
				$changed = array_merge( array( 'settings' ), array_diff( $changed, array( 'settings' ) ) );
			}
			return new DriftVerdict( DriftVerdict::CHANGED, $changed );
		}
		if ( $schema || array_diff_key( $stored->leaves, $current->leaves ) ) {
			return new DriftVerdict( DriftVerdict::SCHEMA );
		}
		return new DriftVerdict( DriftVerdict::MATCH );
	}
}
