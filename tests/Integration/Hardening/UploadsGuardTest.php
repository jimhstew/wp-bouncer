<?php
/**
 * UploadsGuard: the uploads/.htaccess block and the upload pre-filter.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Hardening;

use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Hardening\UploadsPolicy;
use WPBouncer\Log\BlockLog;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Hardening\UploadsGuard
 */
final class UploadsGuardTest extends IntegrationTestCase {

	/** @var UploadsGuard */
	private $guard;

	public function set_up() {
		parent::set_up();
		// The plugin's own init hook already ran once at bootstrap and left state behind.
		delete_option( UploadsGuard::STATE_OPTION );
		delete_option( UploadsGuard::PROBE_OPTION );
		wp_clear_scheduled_hook( UploadsGuard::CHECK_HOOK );
		$this->fake_request();
		$this->guard = new UploadsGuard( $this->plugin );
	}

	private function htaccess(): string {
		return $this->uploads_dir . '/.htaccess';
	}

	private function contents(): string {
		return (string) file_get_contents( $this->htaccess() );
	}

	/** A valid 1x1 GIF. */
	private function gif_bytes(): string {
		return (string) base64_decode( 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7' );
	}

	/**
	 * Write a temp upload file and describe it like $_FILES.
	 *
	 * @return array<string, mixed>
	 */
	private function upload( string $name, string $bytes ): array {
		$tmp = $this->uploads_dir . '/tmp-' . uniqid( '', true );
		file_put_contents( $tmp, $bytes );
		return array(
			'name'     => $name,
			'type'     => 'image/gif',
			'tmp_name' => $tmp,
			'error'    => 0,
			'size'     => strlen( $bytes ),
		);
	}

	private function block_rows(): array {
		global $wpdb;
		return (array) ( new BlockLog( $wpdb ) )->query( array( 'rule' => 'uploads_php' ) );
	}

	/** Make every request to the site's own uploads URL answer like this. */
	private function loopback_answers( int $status, string $body ): void {
		add_filter(
			'pre_http_request',
			static function () use ( $status, $body ) {
				return array(
					'headers'  => array(),
					'body'     => $body,
					'response' => array( 'code' => $status, 'message' => '' ),
					'cookies'  => array(),
					'filename' => null,
				);
			}
		);
	}

	/* ---------------- hooks ---------------- */

	public function test_register_hooks_init_cron_and_both_upload_prefilters(): void {
		$this->guard->register();

		$this->assertNotFalse( has_action( 'init', array( $this->guard, 'maybe_sync' ) ) );
		$this->assertNotFalse( has_action( UploadsGuard::CHECK_HOOK, array( $this->guard, 'cron_check' ) ) );
		$this->assertNotFalse( has_filter( 'wp_handle_upload_prefilter', array( $this->guard, 'filter_upload' ) ) );
		$this->assertNotFalse( has_filter( 'wp_handle_sideload_prefilter', array( $this->guard, 'filter_upload' ) ) );
	}

	/* ---------------- the .htaccess block ---------------- */

	public function test_htaccess_path_follows_the_upload_dir(): void {
		$this->assertSame( $this->htaccess(), UploadsGuard::htaccess_path() );
	}

	public function test_write_block_creates_the_file_with_markers_and_the_rules(): void {
		$this->assertTrue( UploadsGuard::write_block() );

		$this->assertTrue( UploadsGuard::block_present() );
		$text = $this->contents();
		$this->assertStringContainsString( '# BEGIN WP Bouncer', $text );
		$this->assertStringContainsString( '# END WP Bouncer', $text );
		foreach ( UploadsPolicy::htaccess_lines() as $line ) {
			$this->assertStringContainsString( $line, $text );
		}
	}

	public function test_write_block_keeps_the_owners_lines_around_it(): void {
		file_put_contents( $this->htaccess(), "# owner top\nOptions -Indexes\n" );

		UploadsGuard::write_block();

		$text = $this->contents();
		$this->assertStringStartsWith( "# owner top\nOptions -Indexes\n", $text );
		$this->assertStringContainsString( '# BEGIN WP Bouncer', $text );
	}

	public function test_write_block_twice_leaves_one_block(): void {
		UploadsGuard::write_block();
		UploadsGuard::write_block();

		$this->assertSame( 1, substr_count( $this->contents(), '# BEGIN WP Bouncer' ) );
	}

	public function test_remove_block_leaves_lines_before_and_after_it(): void {
		file_put_contents( $this->htaccess(), "# top\nOptions -Indexes\n" );
		UploadsGuard::write_block();
		file_put_contents( $this->htaccess(), "\n# bottom\nRedirect /old /new\n", FILE_APPEND );

		$this->assertTrue( UploadsGuard::remove_block() );

		$text = $this->contents();
		$this->assertStringNotContainsString( 'WP Bouncer', $text );
		$this->assertStringNotContainsString( 'FilesMatch', $text );
		$this->assertStringContainsString( 'Options -Indexes', $text );
		$this->assertStringContainsString( '# top', $text );
		$this->assertStringContainsString( '# bottom', $text );
		$this->assertStringContainsString( 'Redirect /old /new', $text );
		$this->assertFalse( UploadsGuard::block_present() );
	}

	public function test_remove_block_deletes_a_file_that_only_held_our_block(): void {
		UploadsGuard::write_block();

		$this->assertTrue( UploadsGuard::remove_block() );

		$this->assertFileDoesNotExist( $this->htaccess() );
	}

	public function test_remove_block_is_a_no_op_without_a_file_or_a_block(): void {
		$this->assertTrue( UploadsGuard::remove_block() );

		file_put_contents( $this->htaccess(), "Options -Indexes\n" );
		$this->assertTrue( UploadsGuard::remove_block() );
		$this->assertSame( "Options -Indexes\n", $this->contents() );
		$this->assertFalse( UploadsGuard::block_present() );
	}

	public function test_a_blocked_write_reports_failure(): void {
		chmod( $this->uploads_dir, 0555 );
		if ( is_writable( $this->uploads_dir ) ) {
			chmod( $this->uploads_dir, 0755 );
			$this->markTestSkipped( 'Directory permissions are not enforced here (running as root?).' );
		}

		$ok = UploadsGuard::write_block();
		chmod( $this->uploads_dir, 0755 );

		$this->assertFalse( $ok );
		$this->assertFalse( UploadsGuard::block_present() );
	}

	public function test_wants_htaccess_follows_the_settings(): void {
		$this->assertTrue( $this->guard->wants_htaccess() );

		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'htaccess' => false ) ) ) );
		$this->assertFalse( $this->guard->wants_htaccess() );

		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'enabled' => false ) ) ) );
		$this->assertFalse( $this->guard->wants_htaccess() );
	}

	public function test_sync_writes_or_removes_according_to_the_setting(): void {
		$this->assertTrue( $this->guard->sync() );
		$this->assertTrue( UploadsGuard::block_present() );

		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'htaccess' => false ) ) ) );
		$this->assertTrue( $this->guard->sync() );
		$this->assertFalse( UploadsGuard::block_present() );
	}

	public function test_maybe_sync_writes_once_records_state_and_queues_a_serving_check(): void {
		$this->guard->maybe_sync();

		$this->assertTrue( UploadsGuard::block_present() );
		$state = get_option( UploadsGuard::STATE_OPTION );
		$this->assertTrue( $state['ok'] );
		$this->assertFalse( $state['broken'] );
		$this->assertStringStartsWith( 'on:', $state['want'] );
		$this->assertNotFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ) );
	}

	public function test_maybe_sync_does_not_touch_the_file_when_nothing_changed(): void {
		$this->guard->maybe_sync();
		file_put_contents( $this->htaccess(), "# tampered\n" . $this->contents() );
		$mtime = filemtime( $this->htaccess() );
		$text  = $this->contents();

		$this->guard->maybe_sync();

		$this->assertSame( $text, $this->contents() );
		$this->assertSame( $mtime, filemtime( $this->htaccess() ) );
	}

	public function test_maybe_sync_removes_the_block_when_the_setting_is_switched_off(): void {
		$this->guard->maybe_sync();
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'htaccess' => false ) ) ) );

		$this->guard->maybe_sync();

		$this->assertFalse( UploadsGuard::block_present() );
		$this->assertSame( 'off', get_option( UploadsGuard::STATE_OPTION )['want'] );
	}

	public function test_maybe_sync_after_a_failed_write_waits_an_hour_before_retrying(): void {
		chmod( $this->uploads_dir, 0555 );
		if ( is_writable( $this->uploads_dir ) ) {
			chmod( $this->uploads_dir, 0755 );
			$this->markTestSkipped( 'Directory permissions are not enforced here (running as root?).' );
		}
		$this->guard->maybe_sync();
		$this->assertFalse( get_option( UploadsGuard::STATE_OPTION )['ok'] );
		chmod( $this->uploads_dir, 0755 );

		$this->guard->maybe_sync();
		$this->assertFalse( UploadsGuard::block_present(), 'no retry inside the hour' );

		$state         = get_option( UploadsGuard::STATE_OPTION );
		$state['time'] = time() - HOUR_IN_SECONDS - 5;
		update_option( UploadsGuard::STATE_OPTION, $state );
		$this->guard->maybe_sync();

		$this->assertTrue( UploadsGuard::block_present(), 'retried after an hour' );
		$this->assertTrue( get_option( UploadsGuard::STATE_OPTION )['ok'] );
	}

	public function test_teardown_removes_block_cron_and_options(): void {
		$this->guard->maybe_sync();
		update_option( UploadsGuard::PROBE_OPTION, array( 'result' => 'protected' ) );
		if ( is_multisite() ) { // On the main site of a network only a network admin removes the block.
			$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
			grant_super_admin( $id );
			wp_set_current_user( $id );
		}

		UploadsGuard::teardown();

		$this->assertFalse( UploadsGuard::block_present() );
		$this->assertFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ) );
		$this->assertFalse( get_option( UploadsGuard::STATE_OPTION ) );
		$this->assertFalse( get_option( UploadsGuard::PROBE_OPTION ) );
	}

	public function test_is_broken_reads_the_state(): void {
		$this->assertFalse( UploadsGuard::is_broken() );

		update_option( UploadsGuard::STATE_OPTION, array( 'want' => 'on:x', 'ok' => false, 'broken' => true, 'time' => time() ) );

		$this->assertTrue( UploadsGuard::is_broken() );
	}

	/* ---------------- serving check and probe ---------------- */

	public function test_serving_check_ok_when_the_test_file_loads(): void {
		$this->loopback_answers( 200, 'wpb-ok' );

		$this->assertSame( 'ok', $this->guard->check_serving() );
		$this->assertSame( array(), array_diff( (array) scandir( $this->uploads_dir ), array( '.', '..' ) ), 'the check file is removed again' );
	}

	public function test_serving_check_broken_on_a_server_error(): void {
		$this->loopback_answers( 500, 'Internal Server Error' );

		$this->assertSame( 'broken', $this->guard->check_serving() );
	}

	public function test_serving_check_unknown_when_the_site_cannot_reach_itself(): void {
		add_filter(
			'pre_http_request',
			static function () {
				return new \WP_Error( 'http_request_failed', 'cURL error 7' );
			}
		);

		$this->assertSame( 'unknown', $this->guard->check_serving() );
	}

	/** Make the recorded failure old enough to count as a separate one. */
	private function age_failure(): void {
		$state              = (array) get_option( UploadsGuard::STATE_OPTION );
		$state['fail_time'] = time() - UploadsGuard::RECHECK_SECONDS - 5;
		update_option( UploadsGuard::STATE_OPTION, $state );
	}

	public function test_a_5xx_followed_by_a_good_answer_keeps_the_block_and_resets_the_count(): void {
		UploadsGuard::write_block();
		$this->loopback_answers( 503, 'x' );
		$this->guard->run_serving_check();
		$this->age_failure();
		$this->assertSame( 1, (int) get_option( UploadsGuard::STATE_OPTION )['fail_streak'] );

		$this->loopback_answers( 200, 'wpb-ok' );
		$this->assertSame( 'ok', $this->guard->run_serving_check() );
		$this->assertSame( 0, (int) get_option( UploadsGuard::STATE_OPTION )['fail_streak'] );

		$this->loopback_answers( 503, 'x' );
		$this->guard->run_serving_check();
		$this->assertTrue( UploadsGuard::block_present(), 'the count started again from one' );
	}

	public function test_two_5xx_less_than_five_minutes_apart_do_not_remove_the_block(): void {
		UploadsGuard::write_block();
		$this->loopback_answers( 503, 'x' );
		$this->guard->run_serving_check();
		$this->guard->run_serving_check();

		$this->assertTrue( UploadsGuard::block_present() );
		$this->assertSame( 1, (int) get_option( UploadsGuard::STATE_OPTION )['fail_streak'] );
	}

	public function test_the_daily_sweep_deletes_stale_probe_and_check_files_only(): void {
		$old_check = $this->uploads_dir . '/wp-bouncer-check-abc123.txt';
		$old_test  = $this->uploads_dir . '/wp-bouncer-test-abc123.php';
		$fresh     = $this->uploads_dir . '/wp-bouncer-check-fresh.txt';
		$other     = $this->uploads_dir . '/photo.txt';
		$old_other = $this->uploads_dir . '/wp-bouncer-other.txt';
		foreach ( array( $old_check, $old_test, $fresh, $other, $old_other ) as $file ) {
			file_put_contents( $file, 'x' );
		}
		foreach ( array( $old_check, $old_test, $other, $old_other ) as $file ) {
			touch( $file, time() - 2 * HOUR_IN_SECONDS );
		}
		$this->guard->register();

		do_action( \WPBouncer\Installer::CRON_HOOK );

		$this->assertFileDoesNotExist( $old_check );
		$this->assertFileDoesNotExist( $old_test );
		$this->assertFileExists( $fresh );
		$this->assertFileExists( $other );
		$this->assertFileExists( $old_other );
	}

	public function test_an_inconclusive_answer_during_an_open_streak_schedules_another_look(): void {
		UploadsGuard::write_block();
		update_option( UploadsGuard::STATE_OPTION, array( 'want' => 'x', 'ok' => true, 'broken' => false, 'time' => time(), 'fail_streak' => 1, 'fail_time' => time() - 60 ) );
		wp_clear_scheduled_hook( UploadsGuard::CHECK_HOOK );
		$this->loopback_answers( 502, 'bad gateway' );

		$this->assertSame( 'unknown', $this->guard->run_serving_check() );

		$this->assertNotFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ), 'the open streak is not left hanging' );
		$this->assertSame( 1, (int) get_option( UploadsGuard::STATE_OPTION )['fail_streak'] );
	}

	public function test_a_streak_older_than_an_hour_is_dropped_by_an_inconclusive_answer(): void {
		UploadsGuard::write_block();
		update_option( UploadsGuard::STATE_OPTION, array( 'want' => 'x', 'ok' => true, 'broken' => false, 'time' => time(), 'fail_streak' => 1, 'fail_time' => time() - 2 * HOUR_IN_SECONDS ) );
		wp_clear_scheduled_hook( UploadsGuard::CHECK_HOOK );
		$this->loopback_answers( 502, 'bad gateway' );

		$this->guard->run_serving_check();

		$this->assertSame( 0, (int) get_option( UploadsGuard::STATE_OPTION )['fail_streak'] );
		$this->assertFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ) );
	}

	public function test_a_502_does_not_count_as_a_failure(): void {
		UploadsGuard::write_block();
		$this->loopback_answers( 502, 'bad gateway' );

		$this->assertSame( 'unknown', $this->guard->run_serving_check() );
		$this->assertTrue( UploadsGuard::block_present() );
		$this->assertSame( 0, (int) ( ( (array) get_option( UploadsGuard::STATE_OPTION ) )['fail_streak'] ?? 0 ) );
	}

	public function test_after_removal_a_day_later_check_puts_the_block_back_when_uploads_load(): void {
		UploadsGuard::write_block();
		$this->guard->maybe_sync();
		$this->loopback_answers( 500, 'x' );
		$this->guard->run_serving_check();
		$this->age_failure();
		$this->assertSame( 'broken', $this->guard->run_serving_check() );
		$this->assertFalse( UploadsGuard::block_present() );
		$this->assertNotFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ), 'tomorrow\'s retry is scheduled' );

		remove_all_filters( 'pre_http_request' );
		$this->loopback_answers( 200, 'wpb-ok' );
		$this->guard->cron_check();

		$this->assertTrue( UploadsGuard::block_present() );
		$this->assertFalse( UploadsGuard::is_broken() );
		$last = $this->block_rows()[0];
		$this->assertStringContainsString( 'Restored the uploads/.htaccess block', $last['reason'] );
	}

	public function test_the_daily_retry_takes_the_block_out_again_and_reschedules_if_it_still_fails(): void {
		UploadsGuard::write_block();
		$this->guard->maybe_sync();
		$this->loopback_answers( 500, 'x' );
		$this->guard->run_serving_check();
		$this->age_failure();
		$this->guard->run_serving_check();
		wp_clear_scheduled_hook( UploadsGuard::CHECK_HOOK );

		$this->guard->cron_check();

		$this->assertFalse( UploadsGuard::block_present() );
		$this->assertTrue( UploadsGuard::is_broken() );
		$this->assertGreaterThan( time() + DAY_IN_SECONDS - 60, (int) wp_next_scheduled( UploadsGuard::CHECK_HOOK ) );
	}

	public function test_run_serving_check_without_our_block_does_nothing(): void {
		$this->loopback_answers( 500, 'x' );

		$this->assertSame( 'unknown', $this->guard->run_serving_check() );
		$this->assertCount( 0, $this->block_rows() );
	}

	public function test_run_serving_check_removes_the_block_logs_and_marks_it_broken(): void {
		file_put_contents( $this->htaccess(), "Options -Indexes\n" );
		UploadsGuard::write_block();
		$this->loopback_answers( 500, 'x' );

		$this->assertSame( 'retry', $this->guard->run_serving_check(), 'one 5xx is not enough' );
		$this->assertTrue( UploadsGuard::block_present() );
		$this->assertNotFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ), 'a re-check is scheduled' );
		$this->age_failure();

		$this->assertSame( 'broken', $this->guard->run_serving_check() );

		$this->assertFalse( UploadsGuard::block_present() );
		$this->assertStringContainsString( 'Options -Indexes', $this->contents() );
		$this->assertTrue( UploadsGuard::is_broken() );
		$rows = $this->block_rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'alert', $rows[0]['action'] );
		$this->assertStringContainsString( 'Removed the uploads/.htaccess block', $rows[0]['reason'] );
	}

	public function test_a_broken_block_is_not_rewritten_by_maybe_sync(): void {
		$this->guard->maybe_sync();
		$this->loopback_answers( 500, 'x' );
		$this->guard->cron_check();
		$this->age_failure();
		$this->guard->cron_check();
		$this->assertFalse( UploadsGuard::block_present() );

		$this->guard->maybe_sync();

		$this->assertFalse( UploadsGuard::block_present(), 'stays off until the admin clicks "Write it now"' );
	}

	public function test_cron_check_leaves_a_working_block_alone(): void {
		UploadsGuard::write_block();
		$this->loopback_answers( 200, 'wpb-ok' );

		$this->guard->cron_check();

		$this->assertTrue( UploadsGuard::block_present() );
		$this->assertFalse( UploadsGuard::is_broken() );
	}

	public function test_probe_reports_protected_when_the_server_refuses_the_script(): void {
		$this->loopback_answers( 403, 'Forbidden' );

		$result = $this->guard->probe();

		$this->assertSame( 'protected', $result['result'] );
		$this->assertSame( 'HTTP 403', $result['detail'] );
		$this->assertSame( 'protected', get_option( UploadsGuard::PROBE_OPTION )['result'] );
		$this->assertSame( array(), array_diff( (array) scandir( $this->uploads_dir ), array( '.', '..' ) ), 'the test script is removed again' );
	}

	public function test_probe_reports_unprotected_when_php_ran(): void {
		$this->loopback_answers( 200, 'wpb-php-ran' );

		$this->assertSame( 'unprotected', $this->guard->probe()['result'] );
	}

	public function test_probe_reports_unknown_for_a_failed_request(): void {
		add_filter(
			'pre_http_request',
			static function () {
				return new \WP_Error( 'http_request_failed', 'timed out' );
			}
		);

		$result = $this->guard->probe();

		$this->assertSame( 'unknown', $result['result'] );
		$this->assertSame( 'timed out', $result['detail'] );
	}

	public function test_probe_reports_broken_and_removes_the_block_on_a_5xx(): void {
		UploadsGuard::write_block();
		$this->loopback_answers( 500, 'x' );

		$this->assertNotSame( 'broken', $this->guard->probe()['result'], 'a first 5xx is not enough' );
		$this->assertTrue( UploadsGuard::block_present() );
		$this->age_failure();

		$this->assertSame( 'broken', $this->guard->probe()['result'] );
		$this->assertFalse( UploadsGuard::block_present() );
	}

	/* ---------------- the upload pre-filter ---------------- */

	public function test_it_refuses_a_double_extension_php_file(): void {
		$file = $this->upload( 'photo.php.jpg', $this->gif_bytes() );

		$out = $this->guard->filter_upload( $file );

		$this->assertNotEmpty( $out['error'] );
		$this->assertStringContainsString( 'script extension .php', $out['error'] );
		$rows = $this->block_rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'blocked', $rows[0]['action'] );
		$this->assertStringContainsString( 'photo.php_.jpg', $rows[0]['reason'], 'the logged name is run through sanitize_file_name()' );
	}

	public function test_it_refuses_server_config_files(): void {
		foreach ( array( '.htaccess', '.user.ini', 'web.config' ) as $name ) {
			$out = $this->guard->filter_upload( $this->upload( $name, "x\n" ) );
			$this->assertNotEmpty( $out['error'], $name );
		}
	}

	public function test_it_refuses_a_gif_that_contains_php(): void {
		$file = $this->upload( 'logo.gif', "GIF89a<?php system(\$_GET['c']); ?>" );

		$out = $this->guard->filter_upload( $file );

		$this->assertStringContainsString( 'contains PHP code', $out['error'] );
	}

	public function test_it_refuses_php_tags_in_any_case(): void {
		$out = $this->guard->filter_upload( $this->upload( 'a.gif', 'GIF89a<?PHP echo 1;' ) );

		$this->assertNotEmpty( $out['error'] );
	}

	public function test_it_accepts_a_real_image(): void {
		$file = $this->upload( 'photo.gif', $this->gif_bytes() );

		$out = $this->guard->filter_upload( $file );

		$this->assertSame( 0, $out['error'] );
		$this->assertSame( $file, $out );
		$this->assertCount( 0, $this->block_rows() );
	}

	public function test_it_accepts_innocent_names_containing_php(): void {
		$out = $this->guard->filter_upload( $this->upload( 'my-php-notes.txt', "just text\n" ) );

		$this->assertSame( 0, $out['error'] );
	}

	public function test_it_leaves_already_failed_uploads_and_garbage_alone(): void {
		$failed = array( 'name' => 'x.php', 'tmp_name' => '', 'error' => UPLOAD_ERR_PARTIAL );
		$this->assertSame( $failed, $this->guard->filter_upload( $failed ) );
		$this->assertSame( 'nope', $this->guard->filter_upload( 'nope' ) );
	}

	public function test_it_does_nothing_when_the_check_is_switched_off(): void {
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'check_uploads' => false ) ) ) );
		$this->assertSame( 0, $this->guard->filter_upload( $this->upload( 'photo.php.jpg', 'x' ) )['error'] );

		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'enabled' => false ) ) ) );
		$this->assertSame( 0, $this->guard->filter_upload( $this->upload( 'photo.php.jpg', 'x' ) )['error'] );
	}

	public function test_it_is_applied_by_wordpress_when_sideloading_a_file(): void {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$this->guard->register();

		$f_bad  = $this->upload( 'photo.php.jpg', $this->gif_bytes() );
		$f_evil = $this->upload( 'pic.gif', 'GIF89a<?php evil(); ?>' );
		$f_good = $this->upload( 'ok.gif', $this->gif_bytes() );
		$bad    = wp_handle_sideload( $f_bad, array( 'test_form' => false ) );
		$evil   = wp_handle_sideload( $f_evil, array( 'test_form' => false ) );
		$good   = wp_handle_sideload( $f_good, array( 'test_form' => false ) );

		$this->assertArrayHasKey( 'error', $bad );
		$this->assertArrayHasKey( 'error', $evil );
		$this->assertArrayNotHasKey( 'error', $good );
		$this->assertFileExists( $good['file'] );
		$this->assertCount( 1, $this->block_rows(), 'two refusals from one IP in a minute share one log row' );
	}
}
