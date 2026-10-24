<?php
/**
 * Dashboard tab: rule switches and what's been blocked recently.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $settings
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Geo\Countries;
use WPBouncer\Log\BlockLogInterface;

defined( 'ABSPATH' ) || exit;

$log      = $plugin->log();
$since24  = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
$since7   = gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS );
$since30  = gmdate( 'Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS );
$per_day  = $log->per_day( 14 );
$max_day  = max( 1, max( $per_day ) );
$by_rule  = $log->top( 'rule', $since7, 10 );
$top_ips  = $log->top( 'ip', $since7, 10 );
$top_ctry = $log->top( 'country', $since7, 10 );
$stats    = array(
	__( 'Blocked, last 24 hours', 'wp-bouncer' ) => $log->count(
		array(
			'since'  => $since24,
			'action' => BlockLogInterface::ACTION_BLOCKED,
		)
	),
	__( 'Blocked, last 7 days', 'wp-bouncer' )   => $log->count(
		array(
			'since'  => $since7,
			'action' => BlockLogInterface::ACTION_BLOCKED,
		)
	),
	__( 'Blocked, last 30 days', 'wp-bouncer' )  => $log->count(
		array(
			'since'  => $since30,
			'action' => BlockLogInterface::ACTION_BLOCKED,
		)
	),
	__( 'Lockouts, last 7 days', 'wp-bouncer' )  => $log->count(
		array(
			'since'  => $since7,
			'action' => BlockLogInterface::ACTION_LOCKOUT,
		)
	),
);
?>
<div class="wpb-stats">
	<?php foreach ( $stats as $label => $value ) : ?>
		<div class="wpb-card wpb-stat">
			<div class="wpb-stat-value"><?php echo esc_html( number_format_i18n( $value ) ); ?></div>
			<div class="wpb-stat-label"><?php echo esc_html( $label ); ?></div>
		</div>
	<?php endforeach; ?>
</div>

<div class="wpb-grid">
	<section class="wpb-card">
		<h2><?php esc_html_e( 'Rules', 'wp-bouncer' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Each rule can be switched on or off on its own. Configure them on the Rules and Countries tabs.', 'wp-bouncer' ); ?></p>
		<table class="widefat striped wpb-rule-table">
			<tbody>
			<?php foreach ( AdminController::rule_labels() as $rule_id => $label ) : ?>
				<?php $on = ! empty( $settings['rules'][ $rule_id ]['enabled'] ); ?>
				<tr>
					<td>
						<strong><?php echo esc_html( $label[0] ); ?></strong><br>
						<span class="description"><?php echo esc_html( $label[1] ); ?></span>
					</td>
					<td class="wpb-rule-state">
						<span class="wpb-badge <?php echo $on ? 'wpb-badge-on' : 'wpb-badge-off'; ?>"><?php echo $on ? esc_html__( 'On', 'wp-bouncer' ) : esc_html__( 'Off', 'wp-bouncer' ); ?></span>
					</td>
					<td class="wpb-rule-toggle">
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<?php wp_nonce_field( 'wp_bouncer_toggle_rule' ); ?>
							<input type="hidden" name="action" value="wp_bouncer_toggle_rule">
							<input type="hidden" name="rule" value="<?php echo esc_attr( $rule_id ); ?>">
							<button type="submit" class="button button-small"><?php echo $on ? esc_html__( 'Turn off', 'wp-bouncer' ) : esc_html__( 'Turn on', 'wp-bouncer' ); ?></button>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</section>

	<section class="wpb-card">
		<h2><?php esc_html_e( 'Activity, last 14 days', 'wp-bouncer' ); ?></h2>
		<div class="wpb-bars" role="img" aria-label="<?php esc_attr_e( 'Events per day', 'wp-bouncer' ); ?>">
			<?php foreach ( $per_day as $day => $n ) : ?>
				<div class="wpb-bar" title="<?php echo esc_attr( $day . ': ' . number_format_i18n( $n ) ); ?>">
					<span style="height: <?php echo esc_attr( (string) round( $n / $max_day * 100 ) ); ?>%"></span>
					<em><?php echo esc_html( gmdate( 'j', strtotime( $day ) ) ); ?></em>
				</div>
			<?php endforeach; ?>
		</div>

		<h3><?php esc_html_e( 'By rule (7 days)', 'wp-bouncer' ); ?></h3>
		<?php if ( empty( $by_rule ) ) : ?>
			<p class="description"><?php esc_html_e( 'Nothing yet.', 'wp-bouncer' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<?php foreach ( $by_rule as $rule => $n ) : ?>
					<tr>
						<td><a href="<?php echo esc_url( AdminController::url( 'log', array( 'rule' => $rule ) ) ); ?>"><?php echo esc_html( AdminController::rule_title( $rule ) ); ?></a></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $n ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			</table>
		<?php endif; ?>
	</section>

	<section class="wpb-card">
		<h2><?php esc_html_e( 'Top IPs (7 days)', 'wp-bouncer' ); ?></h2>
		<?php if ( empty( $top_ips ) ) : ?>
			<p class="description"><?php esc_html_e( 'Nothing yet.', 'wp-bouncer' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<?php foreach ( $top_ips as $ip => $n ) : ?>
					<?php
					$wpb_block_url = AdminController::block_ip_url( $ip );
					?>
					<tr>
						<td><a href="<?php echo esc_url( AdminController::url( 'log', array( 's' => $ip ) ) ); ?>"><code><?php echo esc_html( $ip ); ?></code></a></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $n ) ); ?></td>
						<td class="num">
							<a class="button button-small" href="<?php echo esc_url( $wpb_block_url ); ?>"><?php esc_html_e( 'Block', 'wp-bouncer' ); ?></a>
						</td>
					</tr>
				<?php endforeach; ?>
			</table>
		<?php endif; ?>
	</section>

	<section class="wpb-card">
		<h2><?php esc_html_e( 'Top countries (7 days)', 'wp-bouncer' ); ?></h2>
		<?php if ( empty( $top_ctry ) ) : ?>
			<p class="description"><?php esc_html_e( 'Nothing yet, or no geo database loaded.', 'wp-bouncer' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<?php foreach ( $top_ctry as $code => $n ) : ?>
					<tr>
						<td><?php echo esc_html( AdminController::flag( $code ) . ' ' . Countries::name( $code ) ); ?></td>
						<td class="num"><?php echo esc_html( number_format_i18n( $n ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			</table>
		<?php endif; ?>
	</section>
</div>
