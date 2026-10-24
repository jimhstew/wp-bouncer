<?php
/**
 * How serious a finding is.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Critical: no security fixes, or a setting that is dangerous on its own.
 * Warning: a setting that leaks or weakens the site. Notice: ending within
 * 90 days. Info: context only. Ok: fine. Unknown: could not be told (not a warning).
 */
enum Severity: string {

	case Critical = 'critical';
	case Warning  = 'warning';
	case Notice   = 'notice';
	case Info     = 'info';
	case Unknown  = 'unknown';
	case Ok       = 'ok';

	/** Sort order, worst first. */
	public function rank(): int {
		return match ( $this ) {
			self::Critical => 5,
			self::Warning  => 4,
			self::Notice   => 3,
			self::Info     => 2,
			self::Unknown  => 1,
			self::Ok       => 0,
		};
	}

	/** Does this count as an issue in the "N issues found" line? */
	public function is_issue(): bool {
		return $this->rank() >= self::Notice->rank();
	}

	/** Human label. */
	public function label(): string {
		return match ( $this ) {
			self::Critical => __( 'Critical', 'wp-bouncer' ),
			self::Warning  => __( 'Warning', 'wp-bouncer' ),
			self::Notice   => __( 'Notice', 'wp-bouncer' ),
			self::Info     => __( 'Info', 'wp-bouncer' ),
			self::Unknown  => __( 'Unknown', 'wp-bouncer' ),
			self::Ok       => __( 'OK', 'wp-bouncer' ),
		};
	}
}
