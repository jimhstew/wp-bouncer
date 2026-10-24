<?php
/**
 * Shared plumbing for rules backed by a settings array.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Verdict;

defined( 'ABSPATH' ) || exit;

/**
 * Base class: stores the rule's settings and offers small helpers.
 */
abstract class AbstractRule implements RuleInterface {

	/**
	 * This rule's slice of the plugin settings (settings['rules'][ id ]).
	 *
	 * @var array<string, mixed>
	 */
	protected array $settings;

	/**
	 * Set up the AbstractRule.
	 *
	 * @param array<string, mixed> $settings Rule settings; must contain 'enabled'.
	 */
	public function __construct( array $settings ) {
		$this->settings = $settings;
	}

	/** {@inheritDoc} */
	public function is_enabled(): bool {
		return ! empty( $this->settings['enabled'] );
	}

	/**
	 * Read one setting with a fallback.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $fallback Fallback.
	 * @return mixed
	 */
	protected function setting( string $key, $fallback = null ) {
		return array_key_exists( $key, $this->settings ) ? $this->settings[ $key ] : $fallback;
	}

	/**
	 * Build a Verdict attributed to this rule.
	 *
	 * @param string $reason      Explanation for the log.
	 * @param int    $status      HTTP status.
	 * @param int    $retry_after Retry-After seconds.
	 */
	protected function deny( string $reason, int $status = 403, int $retry_after = 0 ): Verdict {
		return new Verdict( $this->id(), $reason, $status, $retry_after );
	}
}
