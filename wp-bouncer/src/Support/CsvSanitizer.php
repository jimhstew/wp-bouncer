<?php
/**
 * Spreadsheet formula-injection guard for CSV exports.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Neutralises cell values that a spreadsheet would run as a formula.
 *
 * Log fields (URI, User-Agent, referrer) are attacker-controlled. A cell is
 * prefixed with an apostrophe when its first non-blank character is one of
 * = + - @ | % (or a full-width form), or when it starts with a tab, CR or LF.
 * A trigger that follows an embedded ; tab or newline is neutralised too,
 * because spreadsheets in semicolon locales split the cell there. Plain
 * numbers are left alone. Pure PHP, no WordPress calls.
 */
final class CsvSanitizer {

	/** Blank characters (ASCII, no-break space, ideographic space, U+2000 to U+200B) as raw UTF-8 bytes. */
	private const BLANK = '(?:[ \t\r\n\f\v\0]|\xC2\xA0|\xE3\x80\x80|\xE2\x80[\x80-\x8B])';

	/** Trigger characters: ASCII, and the full-width = + - @ | % as raw UTF-8 bytes. */
	private const TRIGGER = '(?:[=+\-@|%]|\xEF\xBC\x9D|\xEF\xBC\x8B|\xEF\xBC\x8D|\xEF\xBC\xA0|\xEF\xBD\x9C|\xEF\xBC\x85)';

	/**
	 * Make one cell safe to open in a spreadsheet.
	 *
	 * @param mixed $value Cell value.
	 * @return string
	 */
	public static function cell( $value ): string {
		$value = (string) $value;
		if ( '' === $value ) {
			return '';
		}
		if ( 1 === preg_match( '/^-?\d+(?:[.,]\d+)?$/D', $value ) ) {
			return $value;
		}
		// Embedded triggers after a delimiter.
		$embedded = preg_replace( '/([;\t\r\n]' . self::BLANK . '*)(' . self::TRIGGER . ')/', "$1'$2", $value );
		$value    = is_string( $embedded ) ? $embedded : $value;

		if ( 1 === preg_match( '/^(?:[\t\r\n]|' . self::BLANK . '*' . self::TRIGGER . ')/', $value ) ) {
			return "'" . $value;
		}
		return $value;
	}
}
