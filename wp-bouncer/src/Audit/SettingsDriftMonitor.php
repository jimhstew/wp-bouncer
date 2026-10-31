<?php
/**
 * Finds settings changes made while the plugin was not loaded.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

use WPBouncer\Admin\AdminController;
use WPBouncer\Installer;
use WPBouncer\Plugin;
use WPBouncer\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress adapter. Compares the stored settings with a sealed fingerprint written on every audited
 * write. A difference writes one Activity Log row (rule "settings", actor unknown, no request details),
 * queues the firewall-changes alert and replaces the fingerprint. Runs from the daily cron, from a
 * throttled admin_init and from the save path; never on the front end, and never lets an error escape.
 */
final class SettingsDriftMonitor {

	public const TRIGGER_ADMIN = 'admin';
	public const TRIGGER_CRON  = 'cron';
	public const TRIGGER_SAVE  = 'save';

	/** Tries to take the lock on the save path, and the pause between them in microseconds. */
	private const SAVE_LOCK_TRIES = 10;
	private const SAVE_LOCK_PAUSE = 200000;

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Store.
	 *
	 * @var FingerprintStore
	 */
	private FingerprintStore $store;

	/**
	 * Writes the Activity Log row.
	 *
	 * @var SettingsAuditor|null
	 */
	private ?SettingsAuditor $auditor = null;

	/**
	 * Open save-path frames (before_audited_write() pushes, after_audited_write() pops).
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private array $frames = array();

	/**
	 * Depth of save-path lock holders, so a nested audited write does not wait on itself.
	 *
	 * @var int
	 */
	private int $lock_depth = 0;

	/**
	 * Old and new values of writes seen before wp_salt() existed.
	 *
	 * @var array<string, mixed>
	 */
	private array $early = array();

	/**
	 * Set up the monitor.
	 *
	 * @param Plugin                $plugin Plugin.
	 * @param FingerprintStore|null $store  Store (tests pass their own).
	 */
	public function __construct( Plugin $plugin, ?FingerprintStore $store = null ) {
		$this->plugin = $plugin;
		$this->store  = $store ?? new FingerprintStore();
	}

	/** The admin_init entry point: managers only, at most once an hour. */
	public function on_admin_init(): void {
		try {
			if ( ! current_user_can( AdminController::CAPABILITY ) ) {
				return;
			}
			// The daily check lives in cron; a deleted cron row must not switch it off for good.
			$next = wp_next_scheduled( Installer::CRON_HOOK );
			if ( ! $next || $next > time() + DAY_IN_SECONDS + HOUR_IN_SECONDS ) {
				// Missing, or pushed out of reach by a planted cron row: put it back.
				if ( $next ) {
					wp_clear_scheduled_hook( Installer::CRON_HOOK );
				}
				Installer::schedule();
			}
			if ( ! $this->store->throttle_open() ) {
				return;
			}
			// Closed before the compare, so a slow or failing check is not repeated on every page.
			$this->store->close_throttle();
		} catch ( \Throwable $e ) {
			$this->log_failure( $e );
			return;
		}
		$this->check( self::TRIGGER_ADMIN );
	}

	/**
	 * Compare the stored settings with the fingerprint and handle a difference.
	 *
	 * @param string $trigger admin|cron|save.
	 */
	public function check( string $trigger ): void {
		try {
			$this->run_check( $trigger );
		} catch ( \Throwable $e ) {
			$this->log_failure( $e );
		}
	}

	/**
	 * The save path, first half: take the lock and compare the OLD value with the record.
	 *
	 * A difference is a change made outside the plugin since the last audited write; it is reported
	 * now, before the audit row of this save, so the save cannot mask it.
	 *
	 * @param mixed $old_raw     Raw value before the write.
	 * @param bool  $old_present Was the option there.
	 */
	public function before_audited_write( mixed $old_raw, bool $old_present ): void {
		$frame = array(
			'locked'  => false,
			'early'   => false,
			'verdict' => null,
			'stored'  => null,
			'logged'  => 0,
			'report'  => null,
			'pending' => array(),
		);
		try {
			if ( ! function_exists( 'wp_salt' ) ) {
				// Too early (another plugin is writing while pluggable.php loads): both halves run on init.
				if ( ! array_key_exists( 'old', $this->early ) ) {
					$this->early['old']         = $old_raw;
					$this->early['old_present'] = $old_present;
				}
				add_action( 'init', array( $this, 'run_early' ), 0 );
				$frame['early'] = true;
			} else {
				$this->lock_enter();
				$frame['locked'] = true;
				$this->compare_old( $frame, $old_raw, $old_present );
			}
		} catch ( \Throwable $e ) {
			$this->log_failure( $e );
		}
		$this->frames[] = $frame;
	}

	/**
	 * The save path, second half: write the record for the NEW value, release the lock, fire the hooks.
	 *
	 * @param mixed $new_raw     Raw value after the write.
	 * @param bool  $new_present Is the option there.
	 */
	public function after_audited_write( mixed $new_raw, bool $new_present ): void {
		$frame = array_pop( $this->frames );
		if ( null === $frame ) {
			return;
		}
		try {
			if ( $frame['early'] ) {
				$this->early['new']         = $new_raw;
				$this->early['new_present'] = $new_present;
				return;
			}
			$key     = $this->key();
			$new     = SettingsFingerprint::record( $new_raw, $new_present, $key, (int) $frame['logged'], $this->extra_leaves(), (array) $frame['pending'] );
			$verdict = $frame['verdict'];
			$same    = $verdict instanceof DriftVerdict && DriftVerdict::MATCH === $verdict->kind && $frame['stored'] instanceof FingerprintRecord && $frame['stored']->equals( $new ) && $frame['stored']->pending === $new->pending;
			if ( ! $same ) {
				$this->store->save( $new );
				if ( $verdict instanceof DriftVerdict && DriftVerdict::BASELINE === $verdict->kind ) {
					$this->store->set_marker( time() );
				}
			}
		} catch ( \Throwable $e ) {
			$this->log_failure( $e );
		} finally {
			if ( $frame['locked'] ) {
				$this->lock_leave();
			}
		}
		if ( is_array( $frame['report'] ) ) {
			$this->fire_hooks( $frame['report']['verdict'], self::TRIGGER_SAVE, $frame['report']['row'], $frame['report']['settings'] );
		}
	}

	/** Run a save-path pair that was held back until wp_salt() existed. */
	public function run_early(): void {
		$early       = $this->early;
		$this->early = array();
		if ( ! array_key_exists( 'old', $early ) || ! array_key_exists( 'new', $early ) ) {
			return;
		}
		$this->before_audited_write( $early['old'], (bool) $early['old_present'] );
		$this->after_audited_write( $early['new'], (bool) $early['new_present'] );
	}

	/**
	 * The check itself (see check()).
	 *
	 * @param string $trigger admin|cron|save.
	 */
	private function run_check( string $trigger ): void {
		/**
		 * Filters whether the settings drift check runs. Not applied to the save path.
		 *
		 * @param bool   $run     Default true.
		 * @param string $trigger "admin" or "cron".
		 */
		if ( self::TRIGGER_SAVE !== $trigger && ! apply_filters( 'wp_bouncer_settings_drift_check', true, $trigger ) ) {
			return;
		}
		$key     = $this->key();
		$raw_rec = $this->store->load();
		$raw_set = get_option( Settings::OPTION );
		$current = SettingsFingerprint::record( $raw_set, false !== $raw_set, $key, 0, $this->extra_leaves() );
		$stored  = FingerprintRecord::from_stored( $raw_rec );
		$marker  = null !== $stored || null !== $this->store->marker();
		$verdict = DriftDetector::compare( $stored, $current, $key, $marker );
		if ( DriftVerdict::MATCH === $verdict->kind ) {
			if ( null === $stored || empty( $stored->pending ) ) {
				return;
			}
			// A drift whose row could not be written during a save: report it now.
			$verdict = self::pending_verdict( $stored );
		} elseif ( null !== $stored ) {
			$verdict = self::merge_pending( $verdict, $stored );
		}
		if ( ! $this->store->claim_lock() ) {
			return; // Another request is on it; the drift stays detectable.
		}
		$report = false;
		$row    = true;
		try {
			$fresh = $this->store->load_fresh();
			if ( $fresh !== $raw_rec ) {
				return; // A save or another check changed the record: that request handled it.
			}
			$now = time();
			if ( $verdict->reportable() ) {
				if ( DriftVerdict::CHANGED === $verdict->kind && null !== $stored && $stored->logged > $now - HOUR_IN_SECONDS ) {
					return; // One row an hour at most; the drift is reported by the first check after the hour.
				}
				$found_by = self::found_by( $trigger );
				$row      = $this->auditor()->record_row( $verdict->reason( $found_by ), false );
				$this->plugin->alerts()->on_settings_drift( $verdict->forces_alert(), $verdict->mail_detail( $found_by, $row ), $this->normalised( $raw_set ) );
				if ( $row ) {
					$this->store->save( $current->with_logged( $key, $now ) );
				} elseif ( DriftVerdict::CHANGED === $verdict->kind && null !== $stored ) {
					// Keep the old fingerprint (and any pending drift) so the drift is found again in an hour.
					$this->store->save( $stored->with_logged( $key, $now ) );
				}
				// Any other kind without a row: the record stays as it is, so the next check reports it again.
				$report = true;
			} else {
				// A schema verdict must not clear a pending drift that has no row yet.
				$this->store->save( null !== $stored && ! empty( $stored->pending ) ? $current->with_pending( $key, $stored->pending ) : $current );
				if ( DriftVerdict::BASELINE === $verdict->kind ) {
					$this->store->set_marker( $now );
				}
			}
		} finally {
			$this->store->release_lock();
		}
		if ( $report ) {
			$this->fire_hooks( $verdict, $trigger, $row, $this->normalised( $raw_set ) );
		}
	}

	/**
	 * Save path: compare the old value and, on drift, write the row and queue the alert.
	 *
	 * @param array<string, mixed> $frame       Frame (changed).
	 * @param mixed                $old_raw     Raw value before the write.
	 * @param bool                 $old_present Was the option there.
	 */
	private function compare_old( array &$frame, mixed $old_raw, bool $old_present ): void {
		$key     = $this->key();
		$stored  = FingerprintRecord::from_stored( $this->store->load() );
		$marker  = null !== $stored || null !== $this->store->marker();
		$current = SettingsFingerprint::record( $old_raw, $old_present, $key, 0, $this->extra_leaves() );
		$verdict = DriftDetector::compare( $stored, $current, $key, $marker );
		if ( null !== $stored && $verdict->reportable() ) {
			$verdict = self::merge_pending( $verdict, $stored );
		}

		$frame['verdict'] = $verdict;
		$frame['stored']  = $stored;
		$frame['logged']  = null !== $stored ? $stored->logged : 0;
		$frame['pending'] = null !== $stored ? $stored->pending : array();
		if ( ! $verdict->reportable() ) {
			return;
		}
		// The hourly gate does not apply here: refreshing the record without a row would hide the drift.
		$found_by = self::found_by( self::TRIGGER_SAVE );
		$row      = $this->auditor()->record_row( $verdict->reason( $found_by ), false );
		$settings = $this->normalised( $old_raw );
		$this->plugin->alerts()->on_settings_drift( $verdict->forces_alert(), $verdict->mail_detail( $found_by, $row ), $settings );
		if ( $row ) {
			$frame['logged']  = time();
			$frame['pending'] = array();
		} else {
			// Without a row the drift would be lost when the new record is written: carry it in the record.
			$frame['pending'] = self::pending_for( $verdict );
		}
		$frame['report'] = array(
			'verdict'  => $verdict,
			'row'      => $row,
			'settings' => $settings,
		);
	}

	/**
	 * Leaves outside the settings option: the addresses a forced drift mail always goes to.
	 *
	 * @return array<string, string|null> Path => value (null when absent).
	 */
	private function extra_leaves(): array {
		$site = get_option( 'admin_email', false );
		$net  = is_multisite() ? get_site_option( 'admin_email', false ) : false;
		return array(
			SettingsFingerprint::SITE_EMAIL    => is_string( $site ) ? $site : null,
			SettingsFingerprint::NETWORK_EMAIL => is_string( $net ) ? $net : null,
		);
	}

	/**
	 * The "pending" field for a drift whose row failed: kind and safe paths.
	 *
	 * @param DriftVerdict $verdict Verdict.
	 * @return array<string, mixed>
	 */
	private static function pending_for( DriftVerdict $verdict ): array {
		$paths = array();
		foreach ( $verdict->paths as $path ) {
			if ( 0 !== strpos( $path, '+' ) ) { // Drop the "+N more" marker.
				$paths[] = $path;
			}
		}
		$pending = array(
			'kind'  => $verdict->kind,
			'paths' => $paths,
		);
		if ( $verdict->silences() ) {
			$pending['forced'] = true; // Sealed, so an alerts.* path cut from a long list still forces the mail.
		}
		return $pending;
	}

	/**
	 * The verdict a record's pending drift stands for.
	 *
	 * @param FingerprintRecord $stored Record with a pending field.
	 */
	private static function pending_verdict( FingerprintRecord $stored ): DriftVerdict {
		return new DriftVerdict( (string) $stored->pending['kind'], array_map( 'strval', (array) $stored->pending['paths'] ), true === ( $stored->pending['forced'] ?? false ) );
	}

	/**
	 * Add the paths of a pending "changed" drift to a new "changed" verdict, so one row names both.
	 *
	 * @param DriftVerdict      $verdict New verdict.
	 * @param FingerprintRecord $stored  Stored record.
	 */
	private static function merge_pending( DriftVerdict $verdict, FingerprintRecord $stored ): DriftVerdict {
		if ( DriftVerdict::CHANGED !== $verdict->kind || empty( $stored->pending ) ) {
			return $verdict;
		}
		$paths = array_values( array_unique( array_merge( $stored->pending['paths'], array_filter( $verdict->paths, static fn( $p ) => 0 !== strpos( $p, '+' ) ) ) ) );
		sort( $paths, SORT_STRING );
		// A pending kind other than "changed" is the more serious one: keep it.
		return new DriftVerdict( (string) $stored->pending['kind'], $paths, $verdict->silences() || true === ( $stored->pending['forced'] ?? false ) );
	}

	/**
	 * Fire the public hooks, after the record is written and the lock released.
	 *
	 * @param DriftVerdict         $verdict  Verdict.
	 * @param string               $trigger  admin|cron|save.
	 * @param bool                 $row      Was the Activity Log row written.
	 * @param array<string, mixed> $settings Current settings, normalised.
	 */
	private function fire_hooks( DriftVerdict $verdict, string $trigger, bool $row, array $settings ): void {
		try {
			// No old values exist, so listeners get an empty array.
			do_action( 'wp_bouncer_settings_changed', $verdict->paths, array(), $settings, AuditActor::resolve( null, array() ) );
			/**
			 * Fires after a settings change made outside WP Bouncer was found and recorded.
			 *
			 * @param string[] $paths       Safe key paths (empty when unknown).
			 * @param string   $kind        changed|fingerprint_missing|fingerprint_altered|keys_changed.
			 * @param string   $trigger     admin|cron|save.
			 * @param bool     $row_written False when the Activity Log row could not be written.
			 */
			do_action( 'wp_bouncer_settings_drift', $verdict->paths, $verdict->kind, $trigger, $row );
		} catch ( \Throwable $e ) {
			$this->log_failure( $e );
		}
	}

	/**
	 * Take the save-path lock (waiting about 1.8 seconds: nine pauses of 0.2 s), or go on without it.
	 */
	private function lock_enter(): void {
		if ( $this->lock_depth > 0 ) {
			++$this->lock_depth;
			return;
		}
		for ( $try = 0; $try < self::SAVE_LOCK_TRIES; $try++ ) {
			if ( $this->store->claim_lock() ) {
				break;
			}
			if ( $try < self::SAVE_LOCK_TRIES - 1 ) {
				usleep( self::SAVE_LOCK_PAUSE );
			}
		}
		// The save is authoritative: without the lock it still goes ahead.
		$this->lock_depth = 1;
	}

	/** Leave the save-path lock. */
	private function lock_leave(): void {
		if ( $this->lock_depth > 0 && 0 === --$this->lock_depth ) {
			$this->store->release_lock();
		}
	}

	/** The fingerprint key for this site. */
	private function key(): FingerprintKey {
		return new FingerprintKey( wp_salt( 'auth' ), get_current_blog_id() );
	}

	/** The auditor that writes rows (only record_row() is used, so it needs no registration). */
	private function auditor(): SettingsAuditor {
		if ( null === $this->auditor ) {
			$this->auditor = new SettingsAuditor( $this->plugin );
		}
		return $this->auditor;
	}

	/**
	 * Settings as the firewall loads them.
	 *
	 * @param mixed $raw Raw option value.
	 * @return array<string, mixed>
	 */
	private function normalised( mixed $raw ): array {
		return ( new Settings( is_array( $raw ) ? $raw : array() ) )->to_array();
	}

	/**
	 * Who found it, for the row and the mail.
	 *
	 * @param string $trigger admin|cron|save.
	 */
	private static function found_by( string $trigger ): string {
		switch ( $trigger ) {
			case self::TRIGGER_CRON:
				return 'the daily check';
			case self::TRIGGER_SAVE:
				return 'a settings save';
		}
		return 'an admin page check';
	}

	/**
	 * Note a failure in the debug log: the class name only, never a message or a value.
	 *
	 * @param \Throwable $e Error.
	 */
	private function log_failure( \Throwable $e ): void {
		if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			error_log( 'WP Bouncer: settings drift check failed: ' . get_class( $e ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- debug log only, class name only.
		}
	}
}
