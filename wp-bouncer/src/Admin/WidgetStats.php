<?php
/**
 * Builds the numbers for the dashboard widget (no WordPress calls).
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Log\WidgetStatsSource;
use WPBouncer\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Turns log queries into one plain array. Values are raw (unescaped): the
 * renderer escapes them. Alerts are never counted.
 */
final class WidgetStats {

	public const STATUS_ENFORCE  = 'enforce';
	public const STATUS_MONITOR  = 'monitor';
	public const STATUS_DISABLED = 'disabled';

	/** Seconds in a day (this class calls no WordPress code, so it has no DAY_IN_SECONDS). */
	private const DAY = 86400;

	/** Rows in each "top" list. */
	public const TOP_LIMIT = 3;

	/** Rows in the recent list. */
	public const RECENT_LIMIT = 5;

	/**
	 * Build the widget data.
	 *
	 * @param WidgetStatsSource $src      Log reader.
	 * @param Clock             $clock    Clock.
	 * @param string            $mode     'monitor' when monitor mode is on, anything else means enforcing.
	 * @param bool              $disabled WP_BOUNCER_DISABLE is set.
	 * @param bool              $geo      A geo database is loaded.
	 * @return array{
	 *     status: string, headline_action: string,
	 *     h24: int, h24_prev: int, d7: int, d7_prev: int, trend24: string, trend7: string,
	 *     secondary: array{monitored: int, lockout: int, blocked: int},
	 *     rate_limited: bool,
	 *     top_rules: array<int, array{value: string, count: int}>,
	 *     top_ips: array<int, array{value: string, count: int}>,
	 *     top_countries: array<int, array{value: string, count: int}>|null,
	 *     recent: array<int, array{created_at: string, ip: string, rule: string, action: string}>,
	 *     empty: bool,
	 *     window_total: int
	 * }
	 */
	public function build( WidgetStatsSource $src, Clock $clock, string $mode, bool $disabled, bool $geo ): array {
		$status   = $disabled ? self::STATUS_DISABLED : ( 'monitor' === $mode ? self::STATUS_MONITOR : self::STATUS_ENFORCE );
		$headline = self::STATUS_MONITOR === $status ? BlockLogInterface::ACTION_MONITORED : BlockLogInterface::ACTION_BLOCKED;

		$now    = $clock->now();
		$fmt    = static fn ( int $seconds ): string => gmdate( 'Y-m-d H:i:s', $now - $seconds );
		$counts = $src->period_counts( $fmt( 14 * self::DAY ), $fmt( 7 * self::DAY ), $fmt( self::DAY ), $fmt( 2 * self::DAY ) );

		$zero = array(
			'h24'      => 0,
			'h24_prev' => 0,
			'd7'       => 0,
			'd14'      => 0,
		);
		$get  = static fn ( string $action ): array => array_merge( $zero, $counts[ $action ] ?? array() );
		$head = $get( $headline );

		$secondary = array(
			'monitored' => $get( BlockLogInterface::ACTION_MONITORED )['d7'],
			'lockout'   => $get( BlockLogInterface::ACTION_LOCKOUT )['d7'],
			'blocked'   => $get( BlockLogInterface::ACTION_BLOCKED )['d7'],
		);
		$d7_prev   = max( 0, $head['d14'] - $head['d7'] );
		$empty     = 0 === $get( BlockLogInterface::ACTION_BLOCKED )['d14'] + $get( BlockLogInterface::ACTION_MONITORED )['d14'] + $get( BlockLogInterface::ACTION_LOCKOUT )['d14'];

		$window_total = $get( BlockLogInterface::ACTION_BLOCKED )['d14'] + $get( BlockLogInterface::ACTION_MONITORED )['d14'] + $get( BlockLogInterface::ACTION_LOCKOUT )['d14'] + $get( BlockLogInterface::ACTION_SUPPRESSED )['d14'];

		$out = array(
			'status'          => $status,
			'headline_action' => $headline,
			'h24'             => $head['h24'],
			'h24_prev'        => $head['h24_prev'],
			'd7'              => $head['d7'],
			'd7_prev'         => $d7_prev,
			'trend24'         => self::trend( $head['h24'], $head['h24_prev'] ),
			'trend7'          => self::trend( $head['d7'], $d7_prev ),
			'secondary'       => $secondary,
			'rate_limited'    => $get( BlockLogInterface::ACTION_SUPPRESSED )['d14'] > 0,
			'top_rules'       => array(),
			'top_ips'         => array(),
			'top_countries'   => $geo ? array() : null,
			'recent'          => array(),
			'empty'           => $empty,
			'window_total'    => $window_total,
		);
		if ( $empty ) {
			return $out;
		}

		$since7           = $fmt( 7 * self::DAY );
		$out['top_rules'] = self::pairs( $src->top( 'rule', $since7, self::TOP_LIMIT, $headline ) );
		$out['top_ips']   = self::pairs( $src->top( 'ip', $since7, self::TOP_LIMIT, $headline ) );
		if ( $geo ) {
			$out['top_countries'] = self::countries( $src->top( 'country', $since7, self::TOP_LIMIT, $headline ) );
		}
		$out['recent'] = array_slice( $src->recent( self::RECENT_LIMIT, array( $headline ), $fmt( 14 * self::DAY ) ), 0, self::RECENT_LIMIT );
		return $out;
	}

	/**
	 * Compare two periods.
	 *
	 * @param int $now_count  Count in the latest period.
	 * @param int $prev_count Count in the period before it.
	 * @return string up|down|same|new ("new": something now, nothing before).
	 */
	public static function trend( int $now_count, int $prev_count ): string {
		if ( $now_count === $prev_count ) {
			return 'same';
		}
		if ( 0 === $prev_count ) {
			return 'new';
		}
		return $now_count > $prev_count ? 'up' : 'down';
	}

	/**
	 * Top list as a list of value/count pairs (array keys would turn "123" into an int).
	 *
	 * @param array<int|string, int> $top value => count.
	 * @return array<int, array{value: string, count: int}>
	 */
	private static function pairs( array $top ): array {
		$out = array();
		foreach ( array_slice( $top, 0, self::TOP_LIMIT, true ) as $value => $count ) {
			$out[] = array(
				'value' => (string) $value,
				'count' => (int) $count,
			);
		}
		return $out;
	}

	/**
	 * Countries: anything that is not two capital letters becomes '' (shown as "Unknown"), counts merged.
	 *
	 * @param array<int|string, int> $top code => count.
	 * @return array<int, array{value: string, count: int}>
	 */
	private static function countries( array $top ): array {
		$merged = array();
		foreach ( $top as $code => $count ) {
			$code            = preg_match( '/^[A-Z]{2}$/', (string) $code ) ? (string) $code : '';
			$merged[ $code ] = ( $merged[ $code ] ?? 0 ) + (int) $count;
		}
		arsort( $merged );
		return self::pairs( $merged );
	}
}
