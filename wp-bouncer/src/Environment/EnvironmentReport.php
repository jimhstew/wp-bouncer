<?php
/**
 * Runs the checks and collects a Report.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

use WPBouncer\Environment\Checks\AutoPrependCheck;
use WPBouncer\Environment\Checks\DatabaseVersionCheck;
use WPBouncer\Environment\Checks\DebugDisplayCheck;
use WPBouncer\Environment\Checks\DebugLogCheck;
use WPBouncer\Environment\Checks\DisableFunctionsCheck;
use WPBouncer\Environment\Checks\ErrorLogLocationCheck;
use WPBouncer\Environment\Checks\FileEditCheck;
use WPBouncer\Environment\Checks\IniFlagCheck;
use WPBouncer\Environment\Checks\OpenBasedirCheck;
use WPBouncer\Environment\Checks\PhpVersionCheck;
use WPBouncer\Environment\Checks\UploadLimitsCheck;
use WPBouncer\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * One bad check (an exception, or a wrong return type) becomes an "unknown"
 * row without its message; it cannot break the others. Third-party checks
 * must have a valid, unique id that does not use the reserved wpb_ prefix.
 */
final class EnvironmentReport {

	/** Group of each built-in that is not a PHP setting (the default). */
	private const BUILTIN_GROUPS = array(
		'wpb_php_version'   => CheckResult::GROUP_VERSIONS,
		'wpb_db_version'    => CheckResult::GROUP_VERSIONS,
		'wpb_file_edit'     => CheckResult::GROUP_WORDPRESS,
		'wpb_debug_log'     => CheckResult::GROUP_WORDPRESS,
		'wpb_debug_display' => CheckResult::GROUP_WORDPRESS,
	);

	/**
	 * Built-in checks.
	 *
	 * @var CheckInterface[]
	 */
	private array $builtins;

	/**
	 * Set up the EnvironmentReport.
	 *
	 * @param CheckInterface[] $builtins Built-in checks, in display order.
	 */
	public function __construct( array $builtins ) {
		$this->builtins = array_values( array_filter( $builtins, static fn( $c ): bool => $c instanceof CheckInterface ) );
	}

	/**
	 * The built-in checks.
	 *
	 * @param Clock         $clock  Time source.
	 * @param SupportPolicy $policy Support policy.
	 * @return CheckInterface[]
	 */
	public static function builtins( Clock $clock, SupportPolicy $policy ): array {
		$https = static fn( EnvironmentInterface $env ): bool => $env->is_https();
		$cgi   = static fn( EnvironmentInterface $env ): bool => in_array( $env->sapi(), array( 'fpm-fcgi', 'cgi-fcgi' ), true );
		$info  = Severity::Info;

		return array(
			new PhpVersionCheck( $policy, $clock ),
			new DatabaseVersionCheck( $policy, $clock ),
			new IniFlagCheck( 'wpb_allow_url_include', 'allow_url_include', true, Severity::Critical, __( 'Lets PHP include code from a web address, so one file-inclusion bug can run an attacker\'s code.', 'wp-bouncer' ), __( 'Set allow_url_include = Off.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_display_errors', 'display_errors', true, Severity::Warning, __( 'Errors printed into pages reveal file paths and data. This is the value PHP has while this page loads; the front end and command line can differ because WordPress changes it when WP_DEBUG is set.', 'wp-bouncer' ), __( 'Set display_errors = Off on a live site and send errors to a log.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_display_startup_errors', 'display_startup_errors', true, Severity::Warning, __( 'Start-up errors printed into pages reveal paths. It is only a warning when display_errors is on too.', 'wp-bouncer' ), __( 'Set display_startup_errors = Off.', 'wp-bouncer' ), null, static fn( EnvironmentInterface $env ): bool => true !== IniValue::flag( $env->ini( 'display_errors' ), 'display_errors' ) ),
			new IniFlagCheck( 'wpb_log_errors', 'log_errors', false, $info, __( 'With logging off, PHP errors are not recorded anywhere, which makes problems and attacks harder to spot.', 'wp-bouncer' ), __( 'Set log_errors = On and point error_log outside the web root.', 'wp-bouncer' ) ),
			new ErrorLogLocationCheck(),
			new IniFlagCheck( 'wpb_expose_php', 'expose_php', true, $info, __( 'Adds the PHP version to response headers. It is a small help to attackers choosing exploits. Many hosts set it and cannot change it.', 'wp-bouncer' ), __( 'Set expose_php = Off if you can.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_allow_url_fopen', 'allow_url_fopen', true, $info, __( 'Lets PHP open web addresses like files. WordPress needs it, so this is for information only.', 'wp-bouncer' ), __( 'Nothing to do for a normal WordPress site.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_session_strict_mode', 'session.use_strict_mode', false, $info, __( 'Stops PHP accepting session IDs it did not create (session fixation).', 'wp-bouncer' ), __( 'Set session.use_strict_mode = 1.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_session_only_cookies', 'session.use_only_cookies', false, $info, __( 'Keeps session IDs out of web addresses.', 'wp-bouncer' ), __( 'Set session.use_only_cookies = 1.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_session_trans_sid', 'session.use_trans_sid', true, $info, __( 'Puts session IDs into web addresses, where they leak through links and logs.', 'wp-bouncer' ), __( 'Set session.use_trans_sid = 0.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_session_httponly', 'session.cookie_httponly', false, $info, __( 'Stops scripts in the page from reading the session cookie.', 'wp-bouncer' ), __( 'Set session.cookie_httponly = 1.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_session_secure', 'session.cookie_secure', false, $info, __( 'Keeps the session cookie off plain HTTP.', 'wp-bouncer' ), __( 'Set session.cookie_secure = 1 on HTTPS sites.', 'wp-bouncer' ), $https ),
			new IniFlagCheck( 'wpb_zend_assertions', 'zend.assertions', true, $info, __( 'Assertion checks are meant for development; they cost speed and can print internals.', 'wp-bouncer' ), __( 'Set zend.assertions = -1 in production.', 'wp-bouncer' ) ),
			new IniFlagCheck( 'wpb_cgi_fix_pathinfo', 'cgi.fix_pathinfo', true, $info, __( 'With some nginx set-ups, this lets a request for an uploaded image run as PHP.', 'wp-bouncer' ), __( 'Set cgi.fix_pathinfo = 0, or make sure nginx only passes real .php files to PHP.', 'wp-bouncer' ), $cgi ),
			new OpenBasedirCheck(),
			new DisableFunctionsCheck(),
			new AutoPrependCheck(),
			new UploadLimitsCheck(),
			new FileEditCheck(),
			new DebugLogCheck(),
			new DebugDisplayCheck(),
		);
	}

	/**
	 * Is a third-party check allowed to keep its id? The wpb_ prefix is reserved for the built-ins.
	 *
	 * @param string $id Check id.
	 */
	private static function valid_extra_id( string $id ): bool {
		return 1 === preg_match( '/^[a-z0-9_]{3,64}$/', $id ) && ! str_starts_with( $id, 'wpb_' );
	}

	/**
	 * Run every check.
	 *
	 * @param EnvironmentInterface $env   Environment.
	 * @param CheckInterface[]     $extra Additional (filter-supplied) checks; invalid and duplicate ids are dropped.
	 */
	public function run( EnvironmentInterface $env, array $extra = array() ): Report {
		$seen    = array();
		$entries = array();
		// id() is called once per check; a check whose id() throws is skipped.
		foreach ( $this->builtins as $check ) {
			$id = self::id_of( $check );
			if ( null !== $id && ! isset( $seen[ $id ] ) ) {
				$seen[ $id ] = true;
				$entries[]   = array( $check, $id, false );
			}
		}
		foreach ( $extra as $check ) {
			$id = $check instanceof CheckInterface ? self::id_of( $check ) : null;
			if ( null === $id || ! self::valid_extra_id( $id ) || isset( $seen[ $id ] ) ) {
				continue;
			}
			$seen[ $id ] = true;
			$entries[]   = array( $check, $id, true );
		}
		$results = array();
		foreach ( $entries as list( $check, $id, $third_party ) ) {
			$results[] = $this->run_one( $check, $id, $env, $third_party );
		}
		return new Report( $results );
	}

	/**
	 * A check's id, or null if asking throws.
	 *
	 * @param CheckInterface $check Check.
	 */
	private static function id_of( CheckInterface $check ): ?string {
		try {
			$id = $check->id();
			return is_string( $id ) ? $id : null; // @phpstan-ignore function.alreadyNarrowedType
		} catch ( \Throwable $e ) {
			unset( $e );
			return null;
		}
	}

	/**
	 * Run one check safely.
	 *
	 * The result always carries the check's own id (a check cannot report as another), and the
	 * value of a third-party check is private by default (left out of "Copy site info"). If the
	 * check fails, the "unknown" row keeps a built-in's real group, so a failed version check
	 * stays a version finding (and Site Health shows it as unconfirmed, not as good).
	 *
	 * @param CheckInterface       $check       Check.
	 * @param string               $id          Its id (already asked for).
	 * @param EnvironmentInterface $env         Environment.
	 * @param bool                 $third_party Not one of the built-ins.
	 */
	private function run_one( CheckInterface $check, string $id, EnvironmentInterface $env, bool $third_party ): CheckResult {
		try {
			$result = $check->run( $env );
			// A check may return the wrong type despite its signature (untyped third-party code).
			if ( $result instanceof CheckResult ) { // @phpstan-ignore instanceof.alwaysTrue
				if ( $result->id !== $id || ( $third_party && ! $result->is_private ) ) {
					return new CheckResult( $id, $result->group, $result->severity, $result->title, $result->value, $result->why, $result->fix, $third_party || $result->is_private, $result->dashboard_only );
				}
				return $result;
			}
		} catch ( \Throwable $e ) {
			unset( $e ); // The message is not kept: it could contain paths.
		}
		$group = $third_party ? CheckResult::GROUP_PHP : ( self::BUILTIN_GROUPS[ $id ] ?? CheckResult::GROUP_PHP );
		return new CheckResult( $id, $group, Severity::Unknown, $id, __( 'Check failed', 'wp-bouncer' ), '', '', $third_party );
	}
}
