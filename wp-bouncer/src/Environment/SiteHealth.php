<?php
/**
 * WP Bouncer's entries in Site Health.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Direct tests only (no REST calls), prefixed ids, and callbacks that never
 * look at the current user: core's scheduled check runs them with nobody logged in.
 * The wording says "by WP Bouncer's bundled support policy" and leaves the
 * verdicts core already gives (PHP version, SQL server, debug display, HTTPS) alone.
 */
final class SiteHealth {

	/**
	 * Produces the report (memoised by the caller).
	 *
	 * @var callable(): Report
	 */
	private $report;
	/**
	 * Tells whether the current user may see the Info rows (null: always).
	 *
	 * @var (callable(): bool)|null
	 */
	private $can_view;

	/**
	 * Set up SiteHealth.
	 *
	 * @param callable(): Report      $report   Report provider.
	 * @param (callable(): bool)|null $can_view May the current user see the Info rows? The tests
	 *                                         themselves never look at the user (core's cron runs them with nobody).
	 */
	public function __construct( callable $report, ?callable $can_view = null ) {
		$this->report   = $report;
		$this->can_view = $can_view;
	}

	/** Hook in. */
	public function register(): void {
		add_filter( 'site_status_tests', array( $this, 'add_tests' ) );
		add_filter( 'debug_information', array( $this, 'add_debug_information' ) );
	}

	/**
	 * Test definitions: id => [ label, test (callable) ].
	 *
	 * @return array<string, array{label: string, groups: string[], ids: string[], good: string, bad: string, fix: string}>
	 */
	private function definitions(): array {
		return array(
			'wp_bouncer_php_eol'      => array(
				'label'  => __( 'PHP version support (WP Bouncer)', 'wp-bouncer' ),
				'groups' => array( CheckResult::GROUP_VERSIONS ),
				'ids'    => array( 'wpb_php_version' ),
				'good'   => __( 'By WP Bouncer\'s bundled support policy, this PHP version still receives security fixes.', 'wp-bouncer' ),
				'bad'    => __( 'By WP Bouncer\'s bundled support policy, this PHP version no longer receives, or is about to stop receiving, security fixes. Some hosts backport fixes; check with yours.', 'wp-bouncer' ),
				'fix'    => __( 'Ask your host to move the site to a supported PHP version.', 'wp-bouncer' ),
			),
			'wp_bouncer_db_eol'       => array(
				'label'  => __( 'Database version support (WP Bouncer)', 'wp-bouncer' ),
				'groups' => array( CheckResult::GROUP_VERSIONS ),
				'ids'    => array( 'wpb_db_version' ),
				'good'   => __( 'By WP Bouncer\'s bundled support policy, this database version still receives security fixes.', 'wp-bouncer' ),
				'bad'    => __( 'By WP Bouncer\'s bundled support policy, this database version no longer receives, or is about to stop receiving, security fixes. Some hosts backport fixes; check with yours.', 'wp-bouncer' ),
				'fix'    => __( 'Ask your host to upgrade the database server.', 'wp-bouncer' ),
			),
			'wp_bouncer_php_settings' => array(
				'label'  => __( 'PHP security settings (WP Bouncer)', 'wp-bouncer' ),
				'groups' => array( CheckResult::GROUP_PHP ),
				'ids'    => array(),
				'good'   => __( 'WP Bouncer found no PHP setting that weakens the site among the settings it checks.', 'wp-bouncer' ),
				'bad'    => __( 'WP Bouncer found a PHP setting that weakens the site. See the Dashboard tab of WP Bouncer for details.', 'wp-bouncer' ),
				'fix'    => __( 'Open the WP Bouncer Dashboard tab for what to change.', 'wp-bouncer' ),
			),
			'wp_bouncer_wp_hardening' => array(
				'label'  => __( 'WordPress hardening (WP Bouncer)', 'wp-bouncer' ),
				'groups' => array( CheckResult::GROUP_WORDPRESS ),
				'ids'    => array(),
				'good'   => __( 'The code editor is off and the debug log is not in a web-readable place.', 'wp-bouncer' ),
				'bad'    => __( 'The built-in code editor is on, or the debug log is in a web-readable place. See the Dashboard tab of WP Bouncer for details.', 'wp-bouncer' ),
				'fix'    => __( 'Open the WP Bouncer Dashboard tab for what to change.', 'wp-bouncer' ),
			),
		);
	}

	/**
	 * Add the direct tests.
	 *
	 * @param mixed $tests Site Health tests.
	 * @return array<string, mixed>
	 */
	public function add_tests( $tests ): array {
		$tests           = is_array( $tests ) ? $tests : array();
		$tests['direct'] = isset( $tests['direct'] ) && is_array( $tests['direct'] ) ? $tests['direct'] : array();
		$present         = array_map( static fn( CheckResult $r ): string => $r->id, ( $this->report )()->results() );
		foreach ( $this->definitions() as $id => $def ) {
			// A test about a check a host removed with the filter is left out; a check that failed stays (as unconfirmed).
			if ( $def['ids'] && ! array_intersect( $def['ids'], $present ) ) {
				continue;
			}
			$tests['direct'][ $id ] = array(
				'label' => $def['label'],
				'test'  => fn(): array => $this->result( $id ),
			);
		}
		return $tests;
	}

	/**
	 * One test's result, in Site Health's format.
	 *
	 * @param string $id Test id.
	 * @return array<string, mixed>
	 */
	public function result( string $id ): array {
		$def    = $this->definitions()[ $id ];
		$report = ( $this->report )();
		$worst  = $report->worst( $def['groups'], true, $def['ids'] );
		// A version test with no result at all cannot say anything: unconfirmed, not good.
		if ( $def['ids'] && ! array_filter( $report->results(), static fn( CheckResult $r ): bool => in_array( $r->id, $def['ids'], true ) ) ) {
			$worst = Severity::Unknown;
		}

		if ( Severity::Critical === $worst ) {
			$status = 'critical';
		} elseif ( Severity::Warning === $worst || Severity::Notice === $worst ) {
			$status = 'recommended';
		} else {
			$status = 'good';
		}
		$description = '<p>' . esc_html( 'good' === $status ? $def['good'] : $def['bad'] ) . '</p>';
		// A version the policy cannot place (or an out-of-date policy) is never reported as "good".
		if ( Severity::Unknown === $worst && array( CheckResult::GROUP_VERSIONS ) === $def['groups'] ) {
			$status      = 'recommended';
			$description = '<p>' . esc_html__( 'WP Bouncer couldn\'t confirm this version\'s support status (it is not in the bundled policy, or the policy is out of date). Check with your host.', 'wp-bouncer' ) . '</p>';
		}
		return array(
			'label'       => $def['label'],
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'WP Bouncer', 'wp-bouncer' ),
				'color' => 'blue',
			),
			'description' => $description,
			'actions'     => 'good' === $status ? '' : '<p>' . esc_html( $def['fix'] ) . '</p>',
			'test'        => $id,
		);
	}

	/**
	 * Add the Info tab section.
	 *
	 * @param mixed $info Debug information sections.
	 * @return array<string, mixed>
	 */
	public function add_debug_information( $info ): array {
		$info = is_array( $info ) ? $info : array();
		if ( null !== $this->can_view && ! ( $this->can_view )() ) {
			return $info;
		}
		$fields = array();
		foreach ( ( $this->report )()->results() as $r ) {
			$fields[ $r->id ] = array(
				'label'   => $r->title,
				'value'   => $r->value,
				'private' => $r->is_private,
			);
		}
		$info['wp-bouncer-environment'] = array(
			'label'  => __( 'WP Bouncer: environment', 'wp-bouncer' ),
			'fields' => $fields,
		);
		return $info;
	}
}
