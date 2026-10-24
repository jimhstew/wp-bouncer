<?php
/**
 * Dashboard tab: the server environment checks (WPB-6 and WPB-7).
 *
 * Only shown to users who may manage the firewall (checked by the caller). Values
 * are safe summaries; labels come from checks and are escaped here.
 *
 * @package WPBouncer
 * @var \WPBouncer\Environment\Report $report
 */

use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\Severity;

defined( 'ABSPATH' ) || exit;

$wpb_groups = array(
	CheckResult::GROUP_VERSIONS  => __( 'PHP and database versions', 'wp-bouncer' ),
	CheckResult::GROUP_PHP       => __( 'PHP settings', 'wp-bouncer' ),
	CheckResult::GROUP_WORDPRESS => __( 'WordPress settings', 'wp-bouncer' ),
);

/**
 * Print one finding.
 *
 * @param CheckResult $r Result.
 */
$wpb_row = static function ( CheckResult $r ) use ( $wpb_groups ): void {
	$group = $wpb_groups[ $r->group ] ?? $r->group;
	?>
	<li class="wpb-env-row wpb-env-<?php echo esc_attr( $r->severity->value ); ?>">
		<strong class="wpb-env-level"><?php echo esc_html( $r->severity->label() ); ?></strong> &mdash;
		<?php echo esc_html( $r->title ); ?> &mdash; <?php echo esc_html( $r->value ); ?>
		<span class="description">(<?php echo esc_html( $group ); ?>)</span>
		<?php if ( '' !== $r->why ) : ?>
			<br><span class="description"><?php echo wp_kses_post( $r->why ); ?></span>
		<?php endif; ?>
		<?php if ( '' !== $r->fix && $r->severity->is_issue() ) : ?>
			<br><span class="description"><?php echo wp_kses_post( $r->fix ); ?></span>
		<?php endif; ?>
	</li>
	<?php
};

$wpb_by_severity = $report->by_severity();
$wpb_issues      = $report->issue_count();
?>
<section class="wpb-card" id="wpb-environment">
	<h2><?php esc_html_e( 'Server environment', 'wp-bouncer' ); ?></h2>
	<p>
		<?php
		echo esc_html(
			0 === $wpb_issues
				/* translators: %d: number of checks. */
				? sprintf( __( 'No issues found in the %d checks WP Bouncer runs.', 'wp-bouncer' ), $report->check_count() )
				/* translators: 1: number of issues, 2: number of checks. */
				: sprintf( _n( '%1$d issue found in the %2$d checks WP Bouncer runs.', '%1$d issues found in the %2$d checks WP Bouncer runs.', $wpb_issues, 'wp-bouncer' ), $wpb_issues, $report->check_count() )
		);
		?>
		<span class="description"><?php esc_html_e( 'This is a short list of common settings, not a security audit. Some hosts and distributions backport security fixes to older PHP and database versions; check with your host.', 'wp-bouncer' ); ?></span>
	</p>

	<?php foreach ( array( Severity::Critical, Severity::Warning, Severity::Notice ) as $wpb_level ) : ?>
		<?php if ( ! empty( $wpb_by_severity[ $wpb_level->value ] ) ) : ?>
			<ul class="wpb-env-list">
				<?php
				foreach ( $wpb_by_severity[ $wpb_level->value ] as $wpb_result ) {
					$wpb_row( $wpb_result );
				}
				?>
			</ul>
		<?php endif; ?>
	<?php endforeach; ?>

	<details>
		<summary><?php esc_html_e( 'All other checks', 'wp-bouncer' ); ?></summary>
		<ul class="wpb-env-list">
			<?php
			foreach ( array( Severity::Info, Severity::Unknown, Severity::Ok ) as $wpb_level ) {
				foreach ( $wpb_by_severity[ $wpb_level->value ] ?? array() as $wpb_result ) {
					$wpb_row( $wpb_result );
				}
			}
			?>
		</ul>
	</details>
</section>
