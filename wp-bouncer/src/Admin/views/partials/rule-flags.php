<?php
/**
 * A rule's warning or set-up hint lines. Never relies on colour: each line starts with a text prefix.
 *
 * @package WPBouncer
 * @var array<string, mixed> $wpb_rule One rule of RuleOverview::categories().
 */

use WPBouncer\Admin\RuleStatus;

defined( 'ABSPATH' ) || exit;

// RuleOverview only fills 'reasons' together with a 'flag' (RuleStatus sets both or neither), so no flag means nothing to print.
if ( empty( $wpb_rule['flag'] ) ) {
	return;
}
$wpb_attention = RuleStatus::FLAG_ATTENTION === $wpb_rule['flag'];
foreach ( $wpb_rule['reasons'] as $wpb_reason ) :
	?>
	<p class="wpb-rule-flag <?php echo $wpb_attention ? 'is-attention' : 'is-setup'; ?>">
		<span class="dashicons <?php echo $wpb_attention ? 'dashicons-warning' : 'dashicons-info'; ?>" aria-hidden="true"></span>
		<strong><?php echo $wpb_attention ? esc_html__( 'Needs attention:', 'wp-bouncer' ) : esc_html__( 'Before switching on:', 'wp-bouncer' ); ?></strong>
		<?php echo esc_html( $wpb_reason['text'] ); ?>
		<?php if ( '' !== $wpb_reason['link_url'] && '' !== $wpb_reason['link_text'] ) : ?>
			<a href="<?php echo esc_url( $wpb_reason['link_url'] ); ?>"><?php echo esc_html( $wpb_reason['link_text'] ); ?></a>
		<?php endif; ?>
	</p>
<?php endforeach; ?>
