<?php
/**
 * Decides whether the update-source filters are honoured.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Update;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP. The constant must be exactly true (a string such as 'false' does not count). The filters can redirect updates to another server, so they only
 * work when wp-config.php defines WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS as true.
 */
final class SourcePolicy {

	/**
	 * Are the update-source filters allowed?
	 *
	 * @param bool  $defined Whether the constant is defined.
	 * @param mixed $value   Its value (ignored when not defined).
	 */
	public static function filters_allowed( bool $defined, $value = null ): bool {
		return $defined && true === $value;
	}
}
