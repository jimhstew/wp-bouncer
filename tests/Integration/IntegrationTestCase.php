<?php
/**
 * Base class for the WordPress integration tests.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

/** WP_UnitTestCase plus the plugin helpers. */
abstract class IntegrationTestCase extends \WP_UnitTestCase {

	use PluginHelpers;

	/** {@inheritDoc} */
	public function set_up() {
		parent::set_up();
		$this->wpb_set_up();
	}

	/** {@inheritDoc} */
	public function tear_down() {
		$this->wpb_tear_down();
		parent::tear_down();
		$this->plugin->reload_settings();
	}
}
