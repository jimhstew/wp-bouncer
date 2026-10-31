<?php
/**
 * Read side of the log for the Activity Log threat map.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Log;

defined( 'ABSPATH' ) || exit;

/**
 * Threat counts per country. BlockLog implements it; the tests use a fake.
 */
interface ThreatMapSource {

	/**
	 * Count blocked requests and lockouts per stored country value.
	 *
	 * @param array<string, string> $filters Only rule, action and country are used.
	 * @param string                $since   Start of the window (UTC Y-m-d H:i:s), inclusive.
	 * @param string                $until   End of the window (UTC Y-m-d H:i:s), exclusive.
	 * @return array<string, int>|null Raw stored value => count, largest first; null on a database error.
	 */
	public function threats_by_country( array $filters, string $since, string $until ): ?array;
}
