<?php
/**
 * Geo provider backed by a fixed map.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Geo\GeoProviderInterface;

/**
 * IP => country map, counting lookups.
 */
final class FakeGeo implements GeoProviderInterface {

	/** @var array<string, string> */
	private array $map;

	public int $lookups = 0;

	/**
	 * @param array<string, string> $map IP => country code.
	 */
	public function __construct( array $map = array() ) {
		$this->map = $map;
	}

	/** {@inheritDoc} */
	public function lookup( string $ip ): ?string {
		++$this->lookups;
		return $this->map[ $ip ] ?? null;
	}
}
