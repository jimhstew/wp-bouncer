<?php
/**
 * Result of comparing the settings with the stored fingerprint.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

use WPBouncer\SettingsDiff;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP, immutable. Wording is English and fixed, like every stored Activity Log reason.
 */
final class DriftVerdict {

	public const MATCH               = 'match';
	public const SCHEMA              = 'schema';
	public const BASELINE            = 'baseline';
	public const CHANGED             = 'changed';
	public const FINGERPRINT_MISSING = 'fingerprint_missing';
	public const FINGERPRINT_ALTERED = 'fingerprint_altered';
	public const KEYS_CHANGED        = 'keys_changed';

	/** Fixed heads of the stored reasons, by kind (the Activity Log recognises rows by them). */
	public const HEADS = array(
		self::CHANGED             => 'Settings changed outside WP Bouncer',
		self::FINGERPRINT_MISSING => 'Settings fingerprint missing or altered',
		self::FINGERPRINT_ALTERED => 'Settings fingerprint missing or altered',
		self::KEYS_CHANGED        => 'Security keys changed or settings fingerprint altered',
	);

	/** Longest Activity Log reason (the column is varchar(255)). */
	private const REASON_MAX = 255;

	/**
	 * Kind of result.
	 *
	 * @var string
	 */
	public readonly string $kind;

	/**
	 * Safe key paths (see SettingsDiff::safe_paths()).
	 *
	 * @var string[]
	 */
	public readonly array $paths;

	/**
	 * Do the paths include one that can silence or redirect alerts?
	 *
	 * @var bool
	 */
	private bool $silences;

	/**
	 * Set up the verdict.
	 *
	 * @param string   $kind  One of the kind constants.
	 * @param string[] $paths Raw differing paths (made safe here).
	 */
	public function __construct( string $kind, array $paths = array() ) {
		$this->kind     = $kind;
		$this->silences = false;
		foreach ( $paths as $path ) {
			if ( 'mode' === $path || 'settings' === $path || 0 === strpos( (string) $path, 'alerts.' ) || 0 === strpos( (string) $path, 'wp.' ) ) {
				$this->silences = true;
			}
		}
		$this->paths = SettingsDiff::safe_paths( array_values( $paths ) );
	}

	/** Should a row and an alert be written? */
	public function reportable(): bool {
		return isset( self::HEADS[ $this->kind ] );
	}

	/**
	 * Must the alert go out whatever the alert switch says?
	 *
	 * True when the differing paths touch the alert settings, the mode or the whole option, and for the
	 * kinds where nobody knows what changed.
	 */
	public function forces_alert(): bool {
		if ( ! $this->reportable() ) {
			return false;
		}
		return self::CHANGED !== $this->kind || $this->silences;
	}

	/**
	 * Activity Log reason, at most 255 characters. The paths are cut first.
	 *
	 * @param string $found_by Who found it, such as "the daily check".
	 */
	public function reason( string $found_by ): string {
		$head = self::HEADS[ $this->kind ] ?? '';
		$list = implode( ', ', $this->paths );
		switch ( $this->kind ) {
			case self::CHANGED:
				$prefix = $head . ' (found by ' . $found_by . ', not when made; actor unknown): ';
				$suffix = '. Now the baseline; review them.';
				return $prefix . self::fit( $list, self::REASON_MAX - strlen( $prefix ) - strlen( $suffix ) ) . $suffix;
			case self::FINGERPRINT_ALTERED:
				$base = $head . ' (found by ' . $found_by . '; actor unknown). Baseline rebuilt; review all settings.';
				if ( '' === $list ) {
					return self::fit( $base, self::REASON_MAX );
				}
				$prefix = $base . ' Differs from the record (unverified): ';
				return $prefix . self::fit( $list, self::REASON_MAX - strlen( $prefix ) - 1 ) . '.';
			case self::FINGERPRINT_MISSING:
			case self::KEYS_CHANGED:
				return self::fit( $head . ' (found by ' . $found_by . '; actor unknown). Baseline rebuilt; review all settings.', self::REASON_MAX );
		}
		return '';
	}

	/**
	 * Detail text for the alert email.
	 *
	 * @param string $found_by    Who found it, such as "the daily check".
	 * @param bool   $row_written False when the Activity Log row could not be written.
	 */
	public function mail_detail( string $found_by, bool $row_written ): string {
		switch ( $this->kind ) {
			case self::FINGERPRINT_MISSING:
				$what = 'unknown (the stored fingerprint was missing or altered)';
				break;
			case self::KEYS_CHANGED:
				$what = 'unknown (the WordPress security keys changed, or the fingerprint was altered)';
				break;
			case self::FINGERPRINT_ALTERED:
				$what = empty( $this->paths ) ? 'unknown (the stored fingerprint was altered)' : implode( ', ', $this->paths ) . ' (unverified: the stored fingerprint was altered)';
				break;
			default:
				$what = implode( ', ', $this->paths );
		}
		$detail = 'Found by ' . $found_by . ', not when it was made. Actor unknown; the request details in this email are of the check, not of the change. Changed: ' . $what . '. This can be a legitimate restore, import or staging copy. WP Bouncer now treats these settings as normal: review them.';
		if ( ! $row_written ) {
			$detail .= ' The Activity Log row could not be written.';
		}
		return $detail;
	}

	/**
	 * Cut text to a length, ending in "..." when something was cut.
	 *
	 * @param string $text Text.
	 * @param int    $max  Longest result.
	 */
	private static function fit( string $text, int $max ): string {
		if ( $max < 4 ) {
			return '';
		}
		return strlen( $text ) > $max ? substr( $text, 0, $max - 3 ) . '...' : $text;
	}
}
