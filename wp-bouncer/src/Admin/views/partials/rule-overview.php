<?php
/**
 * Dashboard tab: the rules grouped by category, each with its state and a Turn on/off button.
 *
 * Reads the same RuleOverview as the Rules tab, so titles, categories and states cannot disagree.
 *
 * @package WPBouncer
 * @var \WPBouncer\Admin\RuleOverview $overview
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\RuleLabels;

defined( 'ABSPATH' ) || exit;
?>
<section class="wpb-card wpb-overview">
	<h2><?php esc_html_e( 'Rules', 'wp-bouncer' ); ?></h2>
	<p class="description"><?php esc_html_e( 'Each rule can be switched on or off on its own. Configure them on the Rules and Countries tabs.', 'wp-bouncer' ); ?></p>
	<?php foreach ( $overview->categories() as $wpb_category ) : ?>
		<h3 id="wpb-ov-<?php echo esc_attr( $wpb_category['slug'] ); ?>">
			<?php echo esc_html( $wpb_category['title'] ); ?>
			<span class="description">
				<?php
				echo esc_html( RuleLabels::summary( $wpb_category['on'], $wpb_category['total'] ) );
				if ( $wpb_category['attention'] > 0 ) {
					echo ' &middot; <strong class="wpb-warn">' . esc_html( RuleLabels::attention( $wpb_category['attention'] ) ) . '</strong>';
				}
				?>
			</span>
		</h3>
		<table class="widefat striped wpb-rule-table" aria-labelledby="wpb-ov-<?php echo esc_attr( $wpb_category['slug'] ); ?>">
			<tbody>
			<?php foreach ( $wpb_category['rules'] as $wpb_rule ) : ?>
				<?php $wpb_on = $wpb_rule['on']; ?>
				<tr>
					<td>
						<strong><a href="<?php echo esc_url( $wpb_rule['url'] ); ?>"><?php echo esc_html( $wpb_rule['title'] ); ?></a></strong><br>
						<?php if ( '' !== $wpb_rule['description'] ) : ?>
							<span class="description"><?php echo esc_html( $wpb_rule['description'] ); ?></span>
						<?php endif; ?>
						<?php require __DIR__ . '/rule-flags.php'; ?>
					</td>
					<td class="wpb-rule-state">
						<?php if ( $wpb_rule['unknown'] ) : ?>
							<span class="wpb-badge wpb-badge-off"><?php esc_html_e( 'Unknown', 'wp-bouncer' ); ?></span>
						<?php elseif ( $wpb_rule['removed'] ) : ?>
							<span class="wpb-badge wpb-badge-off"><?php esc_html_e( 'Removed by a plugin', 'wp-bouncer' ); ?></span>
						<?php else : ?>
							<span class="wpb-badge <?php echo $wpb_on ? 'wpb-badge-on' : 'wpb-badge-off'; ?>"><?php echo $wpb_on ? esc_html__( 'On', 'wp-bouncer' ) : esc_html__( 'Off', 'wp-bouncer' ); ?></span>
						<?php endif; ?>
					</td>
					<td class="wpb-rule-toggle">
						<?php if ( $wpb_rule['builtin'] ) : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
								<?php wp_nonce_field( 'wp_bouncer_toggle_rule' ); ?>
								<input type="hidden" name="action" value="wp_bouncer_toggle_rule">
								<input type="hidden" name="rule" value="<?php echo esc_attr( $wpb_rule['id'] ); ?>">
								<?php if ( 'uploads_php' === $wpb_rule['id'] && ! current_user_can( AdminController::FIREWALL_CAPABILITY ) ) : ?>
									<span class="description"><?php esc_html_e( 'Managed by your network administrator.', 'wp-bouncer' ); ?></span>
								<?php else : ?>
									<button type="submit" class="button button-small">
										<?php echo $wpb_on ? esc_html__( 'Turn off', 'wp-bouncer' ) : esc_html__( 'Turn on', 'wp-bouncer' ); ?>
										<span class="screen-reader-text"><?php echo esc_html( ': ' . $wpb_rule['title'] ); ?></span>
									</button>
								<?php endif; ?>
							</form>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endforeach; ?>
</section>
