<?php
/**
 * Dashboard widget body.
 *
 * Every value from the log (ip, rule, country) is attacker-controlled: it is escaped where it is printed.
 * URIs, User-Agents, referrers and reasons are never shown here.
 *
 * @package WPBouncer
 * @var array<string, mixed> $data
 * @var int                  $rules_on
 * @var int                  $rules_total
 * @var int                  $now
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\DashboardWidget;
use WPBouncer\Admin\WidgetStats;
use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

$wpb_status   = (string) $data['status'];
$wpb_action   = (string) $data['headline_action'];
$wpb_monitor  = WidgetStats::STATUS_MONITOR === $wpb_status;
$wpb_disabled = WidgetStats::STATUS_DISABLED === $wpb_status;

if ( $wpb_monitor ) {
	$wpb_label = __( 'Would have been blocked', 'wp-bouncer' );
} elseif ( $wpb_disabled ) {
	$wpb_label = __( 'Blocked before it was switched off', 'wp-bouncer' );
} else {
	$wpb_label = __( 'Blocked', 'wp-bouncer' );
}

if ( $wpb_disabled ) {
	$wpb_status_text = __( 'Switched off', 'wp-bouncer' );
} elseif ( $wpb_monitor ) {
	$wpb_status_text = __( 'Monitor mode', 'wp-bouncer' );
} else {
	$wpb_status_text = __( 'Enforcing', 'wp-bouncer' );
}

$wpb_rule_link = static function ( string $rule ) use ( $wpb_action ): string {
	// The log filter reads the rule with sanitize_key(), so only ids that survive it can be linked.
	if ( '' === $rule || sanitize_key( $rule ) !== $rule ) {
		return '';
	}
	return AdminController::url(
		'log',
		array(
			'rule'       => rawurlencode( $rule ),
			'log_action' => rawurlencode( $wpb_action ),
		)
	);
};
?>
<div class="wpb-widget">
	<p>
		<strong><?php echo esc_html( $wpb_status_text ); ?></strong>
		<?php
		echo esc_html(
			sprintf(
				/* translators: 1: number of rules switched on, 2: total number of rules. */
				__( '(%1$s of %2$s rules on)', 'wp-bouncer' ),
				number_format_i18n( $rules_on ),
				number_format_i18n( $rules_total )
			)
		);
		?>
	</p>

	<?php if ( $wpb_disabled ) : ?>
		<p><?php esc_html_e( 'WP Bouncer is switched off in wp-config.php. The numbers below are from before it was switched off.', 'wp-bouncer' ); ?></p>
	<?php elseif ( $wpb_monitor ) : ?>
		<p><?php esc_html_e( 'Monitor mode: requests are logged, not blocked.', 'wp-bouncer' ); ?></p>
	<?php endif; ?>

	<?php if ( $data['rate_limited'] ) : ?>
		<p><?php esc_html_e( 'Logging was rate-limited during a flood, so these numbers are a lower bound.', 'wp-bouncer' ); ?></p>
	<?php endif; ?>

	<?php if ( $data['empty'] ) : ?>
		<p>
			<?php
			echo $wpb_monitor
				? esc_html__( 'Nothing logged in the last 14 days.', 'wp-bouncer' )
				: esc_html__( 'Nothing blocked in the last 14 days.', 'wp-bouncer' );
			?>
		</p>
	<?php else : ?>
		<h3><?php echo esc_html( $wpb_label ); ?></h3>
		<ul>
			<li>
				<?php
				printf(
					/* translators: %s: number of requests. */
					esc_html__( '%s in the last 24 hours', 'wp-bouncer' ),
					'<strong>' . esc_html( number_format_i18n( (int) $data['h24'] ) ) . '</strong>'
				);
				?>
				<br>
				<span class="description"><span aria-hidden="true"><?php echo esc_html( DashboardWidget::trend_arrow( (string) $data['trend24'] ) ); ?></span>
				<?php echo esc_html( DashboardWidget::trend_text( (string) $data['trend24'], (int) $data['h24'], (int) $data['h24_prev'], true ) ); ?></span>
			</li>
			<li>
				<?php
				printf(
					/* translators: %s: number of requests. */
					esc_html__( '%s in the last 7 days', 'wp-bouncer' ),
					'<strong>' . esc_html( number_format_i18n( (int) $data['d7'] ) ) . '</strong>'
				);
				?>
				<br>
				<span class="description"><span aria-hidden="true"><?php echo esc_html( DashboardWidget::trend_arrow( (string) $data['trend7'] ) ); ?></span>
				<?php echo esc_html( DashboardWidget::trend_text( (string) $data['trend7'], (int) $data['d7'], (int) $data['d7_prev'], false ) ); ?></span>
			</li>
		</ul>

		<?php
		$wpb_other = array();
		if ( 'blocked' !== $wpb_action && $data['secondary']['blocked'] > 0 ) {
			/* translators: %s: number of requests. */
			$wpb_other[] = sprintf( _n( '%s blocked', '%s blocked', (int) $data['secondary']['blocked'], 'wp-bouncer' ), number_format_i18n( (int) $data['secondary']['blocked'] ) );
		}
		if ( 'monitored' !== $wpb_action && $data['secondary']['monitored'] > 0 ) {
			/* translators: %s: number of requests. */
			$wpb_other[] = sprintf( _n( '%s would have been blocked', '%s would have been blocked', (int) $data['secondary']['monitored'], 'wp-bouncer' ), number_format_i18n( (int) $data['secondary']['monitored'] ) );
		}
		if ( $data['secondary']['lockout'] > 0 ) {
			/* translators: %s: number of lockouts. */
			$wpb_other[] = sprintf( _n( '%s lockout', '%s lockouts', (int) $data['secondary']['lockout'], 'wp-bouncer' ), number_format_i18n( (int) $data['secondary']['lockout'] ) );
		}
		if ( $wpb_other ) :
			?>
			<p class="description">
				<?php
				/* translators: %s: list such as "3 lockouts, 2 blocked". */
				echo esc_html( sprintf( __( 'Also in the last 7 days: %s', 'wp-bouncer' ), implode( ', ', $wpb_other ) ) );
				?>
			</p>
		<?php endif; ?>

		<?php if ( $data['top_rules'] ) : ?>
			<h3><?php esc_html_e( 'Top rules, last 7 days', 'wp-bouncer' ); ?></h3>
			<ul>
				<?php foreach ( $data['top_rules'] as $wpb_row ) : ?>
					<?php $wpb_url = $wpb_rule_link( $wpb_row['value'] ); ?>
					<li>
						<?php if ( '' !== $wpb_url ) : ?>
							<a href="<?php echo esc_url( $wpb_url ); ?>"><?php echo esc_html( AdminController::rule_title( $wpb_row['value'] ) ); ?></a>
						<?php else : ?>
							<?php echo esc_html( AdminController::rule_title( $wpb_row['value'] ) ); ?>
						<?php endif; ?>
						<span class="description">(<?php echo esc_html( number_format_i18n( $wpb_row['count'] ) ); ?>)</span>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>

		<?php if ( $data['top_ips'] ) : ?>
			<h3><?php esc_html_e( 'Top IP addresses, last 7 days', 'wp-bouncer' ); ?></h3>
			<ul>
				<?php foreach ( $data['top_ips'] as $wpb_row ) : ?>
					<li>
						<?php if ( IpUtils::is_valid( $wpb_row['value'] ) ) : ?>
							<a href="
							<?php
							echo esc_url(
								AdminController::url(
									'log',
									array(
										'log_ip'     => rawurlencode( $wpb_row['value'] ),
										'log_action' => rawurlencode( $wpb_action ),
									)
								)
							);
							?>
										"><?php echo esc_html( $wpb_row['value'] ); ?></a>
						<?php else : ?>
							<?php echo esc_html( $wpb_row['value'] ); ?>
						<?php endif; ?>
						<span class="description">(<?php echo esc_html( number_format_i18n( $wpb_row['count'] ) ); ?>)</span>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>

		<?php $wpb_tools_url = AdminController::url( 'tools' ); ?>
		<?php if ( null === $data['top_countries'] ) : ?>
			<p class="description">
				<?php esc_html_e( 'Countries are hidden because no geo database is loaded.', 'wp-bouncer' ); ?>
				<a href="<?php echo esc_url( $wpb_tools_url ); ?>"><?php esc_html_e( 'Import one under Tools', 'wp-bouncer' ); ?></a>
			</p>
		<?php elseif ( $data['top_countries'] ) : ?>
			<h3><?php esc_html_e( 'Top countries, last 7 days', 'wp-bouncer' ); ?></h3>
			<ul>
				<?php foreach ( $data['top_countries'] as $wpb_row ) : ?>
					<li>
						<?php if ( 1 === preg_match( '/^[A-Z]{2}$/', $wpb_row['value'] ) ) : ?>
							<a href="
							<?php
							echo esc_url(
								AdminController::url(
									'log',
									array(
										'country'    => rawurlencode( $wpb_row['value'] ),
										'log_action' => rawurlencode( $wpb_action ),
									)
								)
							);
							?>
										"><?php echo esc_html( $wpb_row['value'] ); ?></a>
						<?php else : ?>
							<?php esc_html_e( 'Unknown', 'wp-bouncer' ); ?>
						<?php endif; ?>
						<span class="description">(<?php echo esc_html( number_format_i18n( $wpb_row['count'] ) ); ?>)</span>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>

		<?php if ( $data['recent'] ) : ?>
			<h3><?php esc_html_e( 'Latest', 'wp-bouncer' ); ?></h3>
			<ul>
				<?php foreach ( $data['recent'] as $wpb_row ) : ?>
					<?php $wpb_ts = (int) strtotime( $wpb_row['created_at'] . ' UTC' ); ?>
					<li>
						<time datetime="<?php echo esc_attr( gmdate( 'c', $wpb_ts ) ); ?>" title="<?php echo esc_attr( wp_date( 'Y-m-d H:i:s', $wpb_ts ) ); ?>">
							<?php
							/* translators: %s: time span such as "5 minutes". */
							echo esc_html( sprintf( __( '%s ago', 'wp-bouncer' ), human_time_diff( $wpb_ts, $now ) ) );
							?>
						</time>
						&middot; <?php echo esc_html( $wpb_row['ip'] ); ?>
						&middot; <?php echo esc_html( AdminController::rule_title( $wpb_row['rule'] ) ); ?>
					</li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>
	<?php endif; ?>

	<?php
	$wpb_log_url      = AdminController::url( 'log' );
	$wpb_settings_url = AdminController::url( 'dashboard' );
	?>
	<p>
		<a href="<?php echo esc_url( $wpb_log_url ); ?>"><?php esc_html_e( 'View Activity Log', 'wp-bouncer' ); ?></a>
		&middot;
		<a href="<?php echo esc_url( $wpb_settings_url ); ?>"><?php esc_html_e( 'Settings', 'wp-bouncer' ); ?></a>
	</p>
</div>
