<?php
/**
 * Builds the grouped rule overview shown on the Rules and Dashboard tabs.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress-facing assembler: gathers the facts, asks RuleStatus and
 * RuleCatalog, adds the text, and hands the views one plain structure so the
 * screens, the notices and the widget cannot disagree.
 *
 * Runs only on our own screens (never in the firewall path).
 */
final class RuleOverview {

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Set up the overview.
	 *
	 * @param Plugin $plugin Plugin instance.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Status of every built-in rule. Cheap: it reads settings and three options, and finds no third-party rules.
	 *
	 * @return array<string, array{on: bool, flag: string|null, reasons: string[]}>
	 */
	public function statuses(): array {
		$settings = $this->plugin->settings();
		$meta     = get_option( Plugin::GEO_META_OPTION, array() );
		$state    = get_option( UploadsGuard::STATE_OPTION );
		$probe    = get_option( UploadsGuard::PROBE_OPTION );

		return RuleStatus::builtin(
			array(
				'rules'                => $settings->to_array()['rules'],
				'geo_rows'             => is_array( $meta ) ? (int) ( $meta['rows'] ?? 0 ) : 0,
				'geo_source'           => (string) $settings->get( 'geo_source' ),
				'geo_header_untrusted' => $this->plugin->country_paused(),
				'disabled'             => Plugin::is_disabled(),
				'uploads_state'        => is_array( $state ) ? $state : null,
				'uploads_probe'        => is_array( $probe ) && isset( $probe['result'] ) ? (string) $probe['result'] : null,
			)
		);
	}

	/**
	 * Whole-plugin totals over the built-in rules (the Dashboard widget's status line).
	 *
	 * @return array{on: int, total: int, attention: int}
	 */
	public function totals(): array {
		return RuleStatus::totals( RuleCatalog::group( array() ), $this->statuses() );
	}

	/**
	 * The categories with their rules, in display order. Runs the wp_bouncer_rule_info filter.
	 *
	 * Rule row keys: id, title, description, builtin, external_tab (tab key or null),
	 * on, unknown (a third-party rule that failed), flag, reasons (list of
	 * text/link_text/link_url), removed (a built-in rule that a plugin took out of the rule chain), url, anchor (id fragment without "#", or null),
	 * summary (country rule only).
	 *
	 * @return list<array{slug: string, title: string, description: string, on: int, total: int, attention: int, rules: list<array<string, mixed>>}>
	 */
	public function categories(): array {
		$statuses = $this->statuses();
		$labels   = RuleLabels::rules();
		$cats     = RuleLabels::categories();

		list( $found, $state, $chain ) = $this->third_party_rules();
		$ids                           = array_keys( $found );
		/**
		 * Describe rules added through wp_bouncer_rules so they appear in the admin overview.
		 *
		 * Runs only when the admin overview is built, never in the firewall. Keep it cheap and free of side effects.
		 * Entries for built-in rules, or for ids not in the rule chain, are ignored. An unknown category goes to "other".
		 *
		 * @param array<string, array{category?: string, title?: string}> $info Rule id => details. Empty by default.
		 * @param string[]                                                $ids  Ids of non-built-in rules currently in the chain.
		 */
		$info        = apply_filters( 'wp_bouncer_rule_info', array(), $ids );
		$third_party = RuleCatalog::third_party( $info, $ids );
		$groups      = RuleCatalog::group( $third_party );

		// A built-in rule that a wp_bouncer_rules callback took out of the chain does nothing, whatever its switch says.
		// Note that uploads_php is not a firewall rule, so the chain never holds it.
		$removed = array();
		foreach ( RuleCatalog::builtin_ids() as $id ) {
			if ( 'uploads_php' !== $id && ! isset( $chain[ $id ] ) ) {
				$removed[ $id ] = true;
			}
		}
		$all = $statuses;
		foreach ( $removed as $id => $_true ) {
			$all[ $id ]['on'] = false; // Counted as off; the row still shows (and saves) the stored switch.
		}
		foreach ( $third_party as $id => $_details ) {
			$all[ $id ] = array(
				'on'      => (bool) ( $state[ $id ] ?? false ),
				'flag'    => null,
				'reasons' => array(),
			);
		}
		$placeholders = array_filter( $found, static fn ( $is_placeholder ) => 'placeholder' === $is_placeholder );
		$summary      = RuleStatus::summarise( $groups, $all );

		$used   = array();
		$out    = array();
		$rule_s = $this->plugin->settings()->rule( 'country' );
		foreach ( $groups as $slug => $rule_ids ) {
			$rows = array();
			foreach ( $rule_ids as $id ) {
				$builtin = RuleCatalog::is_builtin( $id );
				$status  = $all[ $id ];
				$reasons = array();
				foreach ( $status['reasons'] as $code ) {
					$reasons[] = RuleLabels::reason( $code );
				}
				$anchor = null;
				if ( $builtin ) {
					$anchor = 'rule-' . $id;
				} else {
					$clean = sanitize_html_class( $id );
					// Own prefix: a third-party id can never produce a built-in anchor such as rule-waf-title.
					if ( '' !== $clean && ! isset( $used[ 'rule-x-' . $clean ] ) ) {
						$anchor = 'rule-x-' . $clean;
					}
				}
				if ( null !== $anchor ) {
					$used[ $anchor ] = true;
				}
				$rows[] = array(
					'id'           => $id,
					'title'        => $builtin ? $labels[ $id ][0] : ( isset( $placeholders[ $id ] ) ? __( 'Unknown rule', 'wp-bouncer' ) : $third_party[ $id ]['title'] ),
					'description'  => $builtin ? $labels[ $id ][1] : '',
					'builtin'      => $builtin,
					'external_tab' => RuleCatalog::EXTERNAL[ $id ] ?? null,
					'on'           => $builtin ? $statuses[ $id ]['on'] : $status['on'],
					'removed'      => isset( $removed[ $id ] ),
					'unknown'      => ! $builtin && array_key_exists( $id, $state ) && null === $state[ $id ],
					'flag'         => $status['flag'],
					'reasons'      => $reasons,
					'url'          => $builtin ? AdminController::rule_url( $id ) : AdminController::url( 'rules' ) . ( null !== $anchor ? '#' . $anchor : '' ),
					'anchor'       => $anchor,
					'summary'      => 'country' === $id ? RuleLabels::country_summary( $rule_s ) : '',
				);
			}
			$out[] = array(
				'slug'        => $slug,
				'title'       => $cats[ $slug ][0],
				'description' => $cats[ $slug ][1],
				'on'          => $summary[ $slug ]['on'],
				'total'       => $summary[ $slug ]['total'],
				'attention'   => $summary[ $slug ]['attention'],
				'rules'       => $rows,
			);
		}
		return $out;
	}

	/**
	 * Non-built-in rules in the chain, whether each is on, and every id the chain holds.
	 *
	 * A rule whose id() or is_enabled() throws must not take the settings screen down. A failing
	 * is_enabled() gives a null state (shown as "Unknown"). A failing id() is listed under a placeholder
	 * id that starts with "?" (value "placeholder" in the first array), which sanitize_key() would strip.
	 *
	 * @return array{0: array<string, string>, 1: array<string, bool|null>, 2: array<string, true>} Non-built-in ids in order; id => on (null when unknown); every id in the chain.
	 */
	private function third_party_rules(): array {
		$found = array();
		$state = array();
		$chain = array();
		foreach ( $this->plugin->registered_rules() as $index => $rule ) {
			try {
				$id = (string) $rule->id();
			} catch ( \Throwable $e ) {
				$id           = '?' . (int) $index;
				$found[ $id ] = 'placeholder';
				$state[ $id ] = null;
				continue;
			}
			$chain[ $id ] = true;
			if ( '' === $id || RuleCatalog::is_builtin( $id ) || isset( $found[ $id ] ) ) {
				continue;
			}
			$found[ $id ] = 'real';
			try {
				$state[ $id ] = (bool) $rule->is_enabled();
			} catch ( \Throwable $e ) {
				$state[ $id ] = null;
			}
		}
		return array( $found, $state, $chain );
	}
}
