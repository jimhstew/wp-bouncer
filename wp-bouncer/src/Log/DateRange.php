<?php
/**
 * Strict parsing of the Activity Log date range.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Log;

defined( 'ABSPATH' ) || exit;

/**
 * The window selected by the log_from / log_to request parameters, in the site's time zone.
 *
 * Pure PHP: no WordPress calls. A request string is only ever matched against a fixed pattern
 * and passed to checkdate(); it never reaches strtotime() or a DateTime constructor.
 */
final class DateRange {

	/** Days shown by the map when no range is given. */
	public const DEFAULT_DAYS = 30;

	/** Longest range accepted, in days. */
	public const MAX_DAYS = 365;

	/** The note values. */
	public const NOTE_NONE     = '';
	public const NOTE_INVALID  = 'invalid';
	public const NOTE_REVERSED = 'reversed';
	public const NOTE_CAPPED   = 'capped';

	/**
	 * Accepted first day (Y-m-d), null when no range applies.
	 *
	 * @var string|null
	 */
	public ?string $from;

	/**
	 * Accepted last day (Y-m-d), null when no range applies.
	 *
	 * @var string|null
	 */
	public ?string $to;

	/**
	 * Effective first local day (Y-m-d).
	 *
	 * @var string
	 */
	public string $start;

	/**
	 * Effective last local day (Y-m-d).
	 *
	 * @var string
	 */
	public string $end;

	/**
	 * Start of the window, UTC Y-m-d H:i:s (inclusive).
	 *
	 * @var string
	 */
	public string $since_utc;

	/**
	 * End of the window, UTC Y-m-d H:i:s (exclusive).
	 *
	 * @var string
	 */
	public string $until_utc;

	/**
	 * Unix time of the first local midnight.
	 *
	 * @var int
	 */
	public int $start_ts;

	/**
	 * Unix time of the last local day's midnight.
	 *
	 * @var int
	 */
	public int $end_ts;

	/**
	 * True when the request gave a usable range.
	 *
	 * @var bool
	 */
	public bool $explicit;

	/**
	 * Why part of the input was ignored: '' | invalid | reversed | capped.
	 *
	 * @var string
	 */
	public string $note;

	/**
	 * Inclusive number of days.
	 *
	 * @var int
	 */
	private int $days;

	/**
	 * Use parse().
	 *
	 * @param \DateTimeImmutable $start    First local day at 00:00.
	 * @param \DateTimeImmutable $end      Last local day at 00:00.
	 * @param bool               $explicit Whether the range came from the request.
	 * @param string             $note     Note.
	 */
	private function __construct( \DateTimeImmutable $start, \DateTimeImmutable $end, bool $explicit, string $note ) {
		$utc             = new \DateTimeZone( 'UTC' );
		$after           = $end->modify( '+1 day' )->setTime( 0, 0 );
		$this->start     = $start->format( 'Y-m-d' );
		$this->end       = $end->format( 'Y-m-d' );
		$this->from      = $explicit ? $this->start : null;
		$this->to        = $explicit ? $this->end : null;
		$this->start_ts  = $start->getTimestamp();
		$this->end_ts    = $end->getTimestamp();
		$this->since_utc = $start->setTimezone( $utc )->format( 'Y-m-d H:i:s' );
		$this->until_utc = $after->setTimezone( $utc )->format( 'Y-m-d H:i:s' );
		$this->explicit  = $explicit;
		$this->note      = $note;
		$this->days      = (int) $start->setTime( 12, 0 )->diff( $end->setTime( 12, 0 ) )->days + 1;
	}

	/**
	 * Parse the two request values.
	 *
	 * @param string        $from Raw log_from ('' when missing).
	 * @param string        $to   Raw log_to ('' when missing).
	 * @param \DateTimeZone $tz   The site's time zone.
	 * @param int           $now  Current Unix time.
	 */
	public static function parse( string $from, string $to, \DateTimeZone $tz, int $now ): self {
		$today = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz )->setTime( 0, 0 );
		$note  = self::NOTE_NONE;
		$f     = self::day( $from, $today );
		$t     = self::day( $to, $today );
		if ( ( '' !== $from && null === $f ) || ( '' !== $to && null === $t ) ) {
			$note = self::NOTE_INVALID;
		}
		if ( null !== $t && $t > $today ) {
			$t = $today;
		}
		if ( null !== $t && null === $f ) {
			$f = $t->modify( '-' . ( self::DEFAULT_DAYS - 1 ) . ' days' );
		} elseif ( null !== $f && null === $t ) {
			$t = $today;
		}
		if ( null !== $f && null !== $t && $f > $t ) {
			$f    = null;
			$t    = null;
			$note = self::NOTE_REVERSED;
		}
		if ( null === $f || null === $t ) {
			return new self( $today->modify( '-' . ( self::DEFAULT_DAYS - 1 ) . ' days' ), $today, false, $note );
		}
		if ( (int) $f->setTime( 12, 0 )->diff( $t->setTime( 12, 0 ) )->days + 1 > self::MAX_DAYS ) {
			$f    = $t->modify( '-' . ( self::MAX_DAYS - 1 ) . ' days' );
			$note = self::NOTE_CAPPED;
		}
		return new self( $f, $t, true, $note );
	}

	/**
	 * Inclusive number of days in the effective window.
	 */
	public function days(): int {
		return $this->days;
	}

	/**
	 * A strict Y-m-d day as local midnight, or null.
	 *
	 * @param string             $value Raw value.
	 * @param \DateTimeImmutable $today Today at local 00:00 (carries the time zone).
	 */
	private static function day( string $value, \DateTimeImmutable $today ): ?\DateTimeImmutable {
		if ( 1 !== preg_match( '/^(\d{4})-(\d{2})-(\d{2})\z/', $value, $m ) ) {
			return null;
		}
		$y  = (int) $m[1];
		$mo = (int) $m[2];
		$d  = (int) $m[3];
		if ( $y < 2000 || $y > 2100 || ! checkdate( $mo, $d, $y ) ) {
			return null;
		}
		return $today->setDate( $y, $mo, $d )->setTime( 0, 0 );
	}
}
