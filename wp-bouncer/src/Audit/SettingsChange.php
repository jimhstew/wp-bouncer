<?php
/**
 * The difference between two versions of the stored settings.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

use WPBouncer\Settings;
use WPBouncer\SettingsDiff;

defined( 'ABSPATH' ) || exit;

/**
 * Decision core for the settings audit. No WordPress calls.
 *
 * Both sides are normalised the way the firewall loads them (junk keys dropped,
 * partial writes filled in, clamps applied), so a write that changes nothing in
 * effect gives no change at all. Paths are made safe for logs and email.
 */
final class SettingsChange {

	/**
	 * Settings before, normalised.
	 *
	 * @var array<string, mixed>
	 */
	public readonly array $old;

	/**
	 * Settings after, normalised.
	 *
	 * @var array<string, mixed>
	 */
	public readonly array $new;

	/**
	 * Changed key paths, sanitised.
	 *
	 * @var string[]
	 */
	public readonly array $changes;

	/**
	 * The risky subset of the changes, sanitised.
	 *
	 * @var string[]
	 */
	public readonly array $risky;

	/**
	 * Set up the value object.
	 *
	 * @param array<string, mixed> $before  Old settings.
	 * @param array<string, mixed> $after   New settings.
	 * @param string[]             $changes Safe changed paths.
	 * @param string[]             $risky   Safe risky paths.
	 */
	private function __construct( array $before, array $after, array $changes, array $risky ) {
		$this->old     = $before;
		$this->new     = $after;
		$this->changes = $changes;
		$this->risky   = $risky;
	}

	/**
	 * Compare two raw option values.
	 *
	 * @param mixed $old_raw Raw value before (anything the options API can hold).
	 * @param mixed $new_raw Raw value after.
	 * @param bool  $deleted The option was deleted ($new_raw should be the defaults).
	 * @return self|null Null when nothing changed.
	 */
	public static function from( mixed $old_raw, mixed $new_raw, bool $deleted = false ): ?self {
		$old = ( new Settings( is_array( $old_raw ) ? $old_raw : array() ) )->to_array();
		$new = ( new Settings( is_array( $new_raw ) ? $new_raw : array() ) )->to_array();

		$changes = SettingsDiff::changes( $old, $new );
		if ( $deleted || ! is_array( $new_raw ) ) {
			$changes[] = 'settings';
			sort( $changes, SORT_STRING );
		}
		if ( empty( $changes ) ) {
			return null;
		}
		$risky = SettingsDiff::risky( $changes, $old, $new );

		return new self( $old, $new, SettingsDiff::safe_paths( $changes ), SettingsDiff::safe_paths( $risky ) );
	}

	/**
	 * One-line Activity Log text.
	 *
	 * @param string $actor Who did it (see AuditActor).
	 * @return string Reason, at most 255 characters; paths only, never values.
	 */
	public function reason( string $actor ): string {
		return SettingsDiff::describe( $actor, $this->changes, $this->risky );
	}
}
