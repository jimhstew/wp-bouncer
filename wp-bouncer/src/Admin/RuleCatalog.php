<?php
/**
 * Rule categories for the admin screens (no WordPress calls).
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Which category each rule belongs to, and in what order they are shown.
 *
 * This is display metadata only. Keep it out of the firewall path.
 *
 * The category slugs are a public, permanent API (they appear in page anchors
 * and in the wp_bouncer_rule_info filter). Never rename them; change only the
 * translated display names in RuleLabels.
 */
final class RuleCatalog {

	/** Category for rules that declare none (third-party rules). */
	public const OTHER = 'other';

	/** Longest title a third-party rule may declare, in characters. */
	public const TITLE_MAX = 80;

	/**
	 * Display order of categories and of the built-in rules in each.
	 * The one place a built-in rule declares its category.
	 */
	public const CATEGORIES = array(
		'block-lists'        => array( 'ip_blocklist', 'country', 'user_agent' ),
		'login-accounts'     => array( 'login_lockout', 'xmlrpc', 'user_enumeration' ),
		'scanners-floods'    => array( 'sensitive_files', 'not_found', 'rate_limit' ),
		'payloads-hardening' => array( 'waf', 'uploads_php' ),
	);

	/** Rules whose settings live on another tab (a status card, no inputs on the Rules tab): id => tab. */
	public const EXTERNAL = array( 'country' => 'countries' );

	/**
	 * Category slugs in display order, OTHER last.
	 *
	 * @return string[]
	 */
	public static function slugs(): array {
		return array_merge( array_keys( self::CATEGORIES ), array( self::OTHER ) );
	}

	/**
	 * Every built-in rule id in display order.
	 *
	 * @return string[]
	 */
	public static function builtin_ids(): array {
		return array_merge( ...array_values( self::CATEGORIES ) );
	}

	/**
	 * Slug for a built-in id.
	 *
	 * @param string $id Rule id.
	 * @return string|null Null if the id is not built in.
	 */
	public static function category_of( string $id ): ?string {
		foreach ( self::CATEGORIES as $slug => $ids ) {
			if ( in_array( $id, $ids, true ) ) {
				return $slug;
			}
		}
		return null;
	}

	/**
	 * Is the id a built-in rule?
	 *
	 * @param string $id Rule id.
	 */
	public static function is_builtin( string $id ): bool {
		return null !== self::category_of( $id );
	}

	/**
	 * Clean third-party declarations.
	 *
	 * Built-in ids are dropped (built-in metadata wins) and so are ids not in
	 * $registered (only rules that are really in the chain are shown). The
	 * category is coerced to a known slug or OTHER; the title has its tags
	 * stripped, is trimmed, capped at 80 characters and falls back to the id.
	 * Every registered rule gets an entry, declared or not.
	 *
	 * @param mixed    $raw        Return value of the wp_bouncer_rule_info filter.
	 * @param string[] $registered Ids of non-built-in rules in the rule chain.
	 * @return array<string, array{category: string, title: string}>
	 */
	public static function third_party( $raw, array $registered ): array {
		$raw = is_array( $raw ) ? $raw : array();
		$out = array();
		foreach ( $registered as $id ) {
			$id = (string) $id;
			if ( '' === $id || self::is_builtin( $id ) || isset( $out[ $id ] ) ) {
				continue;
			}
			$info     = isset( $raw[ $id ] ) && is_array( $raw[ $id ] ) ? $raw[ $id ] : array();
			$category = isset( $info['category'] ) && is_string( $info['category'] ) ? $info['category'] : self::OTHER;
			if ( ! array_key_exists( $category, self::CATEGORIES ) ) {
				$category = self::OTHER;
			}
			$title = isset( $info['title'] ) && is_string( $info['title'] ) ? self::clean_title( $info['title'] ) : '';

			$out[ $id ] = array(
				'category' => $category,
				'title'    => '' !== $title ? $title : $id,
			);
		}
		return $out;
	}

	/**
	 * Plain, short, single-line text from an untrusted title.
	 *
	 * @param string $title Raw title.
	 */
	private static function clean_title( string $title ): string {
		$title = strip_tags( $title ); // phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- this class makes no WordPress calls (unit-tested without WordPress); the title is escaped again on output.
		$title = (string) preg_replace( '/[\x00-\x20\x7F]+/', ' ', $title );
		$title = trim( $title );
		return mb_substr( $title, 0, self::TITLE_MAX );
	}

	/**
	 * Group rule ids by category, in display order.
	 *
	 * Built-in rules come first in catalog order, then third-party rules in the
	 * order given. Empty categories are removed, except the four built-in ones.
	 *
	 * @param array<string, array{category: string, title: string}> $third_party From third_party().
	 * @return array<string, string[]> Slug => rule ids.
	 */
	public static function group( array $third_party ): array {
		$groups                = self::CATEGORIES;
		$groups[ self::OTHER ] = array();
		foreach ( $third_party as $id => $info ) {
			$slug              = array_key_exists( $info['category'], $groups ) ? $info['category'] : self::OTHER;
			$groups[ $slug ][] = (string) $id;
		}
		if ( array() === $groups[ self::OTHER ] ) {
			unset( $groups[ self::OTHER ] );
		}
		return $groups;
	}
}
