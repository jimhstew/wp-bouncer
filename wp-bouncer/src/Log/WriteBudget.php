<?php
/**
 * Site-wide cap on block-log writes per minute.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Log;

use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Counts log writes per UTC minute in the counter store. Once the minute's
 * budget is used up, further events are not stored (blocking is unaffected)
 * and are counted, so one summary row can say how many were dropped.
 */
final class WriteBudget {

	/** Counters and the pending marker live for two days, so a quiet site still reports. */
	private const TTL         = 172800;
	private const PENDING_KEY = 'log_budget_pending';
	/** Most over-budget markers set per minute (each is one stored option). */
	private const MAX_MARKERS = 500;
	/** Most distinct rule names tracked per minute; the rest count as "other". */
	private const MAX_RULES = 16;

	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface
	 */
	private CounterStoreInterface $store;
	/**
	 * Time source.
	 *
	 * @var Clock
	 */
	private Clock $clock;
	/**
	 * Writes allowed per minute.
	 *
	 * @var int
	 */
	private int $per_minute;
	/**
	 * Writes allowed per minute for high-value rows.
	 *
	 * @var int
	 */
	private int $priority_per_minute;

	/**
	 * Set up the WriteBudget.
	 *
	 * @param CounterStoreInterface $store               Counter store.
	 * @param Clock                 $clock               Time source.
	 * @param int                   $per_minute          Writes allowed per minute.
	 * @param int                   $priority_per_minute Separate allowance for lockouts and uploads blocks (at least 5).
	 */
	public function __construct( CounterStoreInterface $store, Clock $clock, int $per_minute, int $priority_per_minute = 30 ) {
		$this->store               = $store;
		$this->clock               = $clock;
		$this->per_minute          = max( 1, $per_minute );
		$this->priority_per_minute = max( 5, $priority_per_minute );
	}

	/**
	 * Does this entry belong to the small separate budget?
	 *
	 * Lockouts and blocked uploads-guard rows are rare and valuable, so a cheap
	 * flood of other rows must not push them out of the log.
	 *
	 * @param array<string, string> $entry Log entry.
	 */
	public static function is_priority( array $entry ): bool {
		$action = $entry['action'] ?? '';
		return BlockLogInterface::ACTION_LOCKOUT === $action
			|| ( BlockLogInterface::ACTION_BLOCKED === $action && 'uploads_php' === ( $entry['rule'] ?? '' ) );
	}

	/**
	 * Counter key for the minute containing a timestamp.
	 *
	 * @param int $time Unix time.
	 */
	private function minute( int $time ): string {
		return gmdate( 'YmdHi', $time );
	}

	/**
	 * Counter key for the current minute's used allowance.
	 *
	 * @param string $minute   Minute key.
	 * @param bool   $priority Priority allowance.
	 */
	private function used_key( string $minute, bool $priority ): string {
		return ( $priority ? 'log_budget_p:' : 'log_budget:' ) . $minute;
	}

	/**
	 * Is there budget left in the current minute?
	 *
	 * Read-only while under budget. Once over, it counts the dropped event
	 * against its rule (one counter update) and remembers the minute.
	 *
	 * @param string $rule     Rule id of the event, for the summary.
	 * @param bool   $priority Use the priority allowance.
	 */
	public function peek( string $rule = '', bool $priority = false ): bool {
		$minute = $this->minute( $this->clock->now() );
		$used   = (int) $this->store->get( $this->used_key( $minute, $priority ) );
		if ( $used < ( $priority ? $this->priority_per_minute : $this->per_minute ) ) {
			return true;
		}
		$this->count_dropped( $minute, $rule );
		return false;
	}

	/**
	 * Use one write from the current minute's allowance.
	 *
	 * @param string $rule     Rule id of the event, for the summary.
	 * @param bool   $priority Use the priority allowance.
	 * @return bool True if the write is within the budget.
	 */
	public function consume( string $rule = '', bool $priority = false ): bool {
		$minute = $this->minute( $this->clock->now() );
		$used   = $this->store->increment( $this->used_key( $minute, $priority ), self::TTL );
		if ( $used <= ( $priority ? $this->priority_per_minute : $this->per_minute ) ) {
			return true;
		}
		$this->count_dropped( $minute, $rule );
		return false;
	}

	/**
	 * Count a dropped event against its rule and remember the minute.
	 *
	 * @param string $minute Minute key.
	 * @param string $rule   Rule id.
	 */
	private function count_dropped( string $minute, string $rule ): void {
		$rule  = substr( (string) preg_replace( '/[^a-z0-9_]/', '', strtolower( $rule ) ), 0, 32 );
		$rule  = '' === $rule ? 'other' : $rule;
		$list  = $this->store->get( 'log_budget_rules:' . $minute );
		$list  = is_array( $list ) ? $list : array();
		$known = in_array( $rule, $list, true );
		if ( ! $known && count( $list ) >= self::MAX_RULES ) {
			$rule  = 'other';
			$known = in_array( $rule, $list, true );
		}
		if ( ! $known ) {
			$list[] = $rule;
			$this->store->set( 'log_budget_rules:' . $minute, $list, self::TTL );
		}
		$this->store->increment( 'log_budget_drop:' . $minute . ':' . $rule, self::TTL );
		if ( $this->store->get( self::PENDING_KEY ) !== $minute ) {
			$this->store->set( self::PENDING_KEY, $minute, self::TTL );
		}
	}

	/**
	 * May another over-budget marker be stored this minute?
	 *
	 * Markers stop repeats from one IP being counted (and costing an option
	 * write) on every request. They are capped per minute; beyond the cap
	 * this only reads, and events are counted without markers.
	 */
	public function allow_marker(): bool {
		$key  = 'log_budget_marks:' . $this->minute( $this->clock->now() );
		$used = (int) $this->store->get( $key );
		if ( $used >= self::MAX_MARKERS ) {
			return false;
		}
		$this->store->increment( $key, self::TTL );
		return true;
	}

	/**
	 * The most recent finished over-budget minute not yet reported.
	 *
	 * The pending marker is deleted before the result is returned, which
	 * narrows (but cannot close) the window for a double summary.
	 *
	 * @return array{minute: string, suppressed: int, rules: array<string, int>}|null Minute as "HH:MM", the total dropped, and drops per rule (largest first).
	 */
	public function pending_summary(): ?array {
		$pending = $this->store->get( self::PENDING_KEY );
		if ( ! is_string( $pending ) || $pending >= $this->minute( $this->clock->now() ) ) {
			return null;
		}
		$this->store->delete( self::PENDING_KEY );

		$list  = $this->store->get( 'log_budget_rules:' . $pending );
		$rules = array();
		foreach ( is_array( $list ) ? $list : array() as $rule ) {
			$n = (int) $this->store->get( 'log_budget_drop:' . $pending . ':' . $rule );
			if ( $n > 0 ) {
				$rules[ (string) $rule ] = $n;
			}
		}
		arsort( $rules );
		$total = array_sum( $rules );
		if ( $total < 1 ) {
			return null;
		}
		return array(
			'minute'     => substr( $pending, 8, 2 ) . ':' . substr( $pending, 10, 2 ),
			'suppressed' => $total,
			'rules'      => $rules,
		);
	}
}
