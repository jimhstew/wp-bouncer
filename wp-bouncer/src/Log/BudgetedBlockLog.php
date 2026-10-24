<?php
/**
 * Block log decorator that enforces the per-minute write budget.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Log;

defined( 'ABSPATH' ) || exit;

/**
 * Wraps a BlockLogInterface. Alert rows always pass, so a flood of blocked
 * requests can't push site-change alerts out of the log. Everything else is
 * limited by the WriteBudget, and the first write after an over-budget minute
 * is preceded by one "suppressed" summary row.
 */
final class BudgetedBlockLog implements BlockLogInterface {

	/**
	 * Real log.
	 *
	 * @var BlockLogInterface
	 */
	private BlockLogInterface $inner;
	/**
	 * Budget.
	 *
	 * @var WriteBudget
	 */
	private WriteBudget $budget;

	/**
	 * Set up the BudgetedBlockLog.
	 *
	 * @param BlockLogInterface $inner  Real log.
	 * @param WriteBudget       $budget Budget.
	 */
	public function __construct( BlockLogInterface $inner, WriteBudget $budget ) {
		$this->inner  = $inner;
		$this->budget = $budget;
	}

	/**
	 * Record one event unless the minute's budget is spent.
	 *
	 * @param array<string, string> $entry Event fields, see BlockLogInterface::record().
	 * @return int Row id, or 0 when not stored.
	 */
	public function record( array $entry ): int {
		if ( ( $entry['action'] ?? '' ) === self::ACTION_ALERT ) {
			return $this->inner->record( $entry );
		}

		$this->flush_summary();

		$rule     = (string) ( $entry['rule'] ?? '' );
		$priority = WriteBudget::is_priority( $entry );
		if ( ! $this->budget->consume( $rule, $priority ) ) {
			return 0;
		}
		return $this->inner->record( $entry );
	}

	/**
	 * Write the summary row for an earlier over-budget minute, if one is waiting.
	 *
	 * Also called from the daily cron and the log screen, so a site that goes
	 * quiet after a flood still records it.
	 */
	public function flush_summary(): void {
		$summary = $this->budget->pending_summary();
		if ( null === $summary ) {
			return;
		}
		$parts = array();
		foreach ( $summary['rules'] as $rule => $count ) {
			$parts[] = $rule . ' ' . $count;
		}
		$this->inner->record(
			array(
				'ip'     => '',
				'rule'   => 'wp_bouncer',
				'action' => self::ACTION_SUPPRESSED,
				'reason' => sprintf( '%d further events suppressed in minute %s (UTC): %s', $summary['suppressed'], $summary['minute'], implode( ', ', $parts ) ),
			)
		);
	}
}
