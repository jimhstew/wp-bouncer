<?php
/**
 * Marks list-table headers so assets/columns.js can add drag-to-resize handles (WPB-10b).
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Adds data attributes to the column headers WP_List_Table prints. Nothing is stored on the server.
 */
final class ColumnResize {

	/**
	 * Tab slugs whose list table can be resized. Also the table ids used in the browser's storage keys.
	 */
	public const TABS = array( 'log', 'traffic' );

	/**
	 * Smallest width in pixels when a column has no entry of its own.
	 */
	public const DEFAULT_MIN = 60;

	/**
	 * Add data-wpb-col, data-wpb-min and data-wpb-label to each header cell whose id is a known column.
	 *
	 * Other cells (and the input unchanged, if nothing matches) are left alone. Attribute values are
	 * escaped by WP_HTML_Tag_Processor.
	 *
	 * @param string                $html   Header row markup printed by WP_List_Table.
	 * @param array<string, string> $labels Column id => label, from get_columns().
	 * @param array<string, int>    $mins   Column id => minimum width in pixels.
	 * @return string
	 */
	public static function annotate( string $html, array $labels, array $mins ): string {
		$processor = new \WP_HTML_Tag_Processor( $html );
		$changed   = false;
		while ( $processor->next_tag( array( 'tag_name' => 'th' ) ) ) {
			$id = $processor->get_attribute( 'id' );
			if ( ! is_string( $id ) || ! array_key_exists( $id, $labels ) ) {
				continue;
			}
			$min = isset( $mins[ $id ] ) ? (int) $mins[ $id ] : self::DEFAULT_MIN;
			$processor->set_attribute( 'data-wpb-col', $id );
			$processor->set_attribute( 'data-wpb-min', (string) max( 1, $min ) );
			$processor->set_attribute( 'data-wpb-label', wp_strip_all_tags( (string) $labels[ $id ] ) );
			$changed = true;
		}
		return $changed ? $processor->get_updated_html() : $html;
	}
}
