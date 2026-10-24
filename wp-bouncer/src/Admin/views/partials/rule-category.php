<?php
/**
 * Rules tab: one category section with its rules.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $r            Settings: the rules array.
 * @var array<string, mixed> $wpb_category One category of RuleOverview::categories().
 * @var string               $wpb_open     Built-in rule id whose settings are opened by the wpb_rule argument, or ''.
 * @var int                  $wpb_seq      Running number of rows.
 */

use WPBouncer\Admin\RuleLabels;

defined( 'ABSPATH' ) || exit;

$wpb_cat_id = 'wpb-cat-' . $wpb_category['slug'];
?>
<section class="wpb-card wpb-category" id="<?php echo esc_attr( $wpb_cat_id ); ?>" tabindex="-1" aria-labelledby="<?php echo esc_attr( $wpb_cat_id ); ?>-title">
	<h2 id="<?php echo esc_attr( $wpb_cat_id ); ?>-title"><?php echo esc_html( $wpb_category['title'] ); ?></h2>
	<p class="description"><?php echo esc_html( $wpb_category['description'] ); ?></p>
	<p class="wpb-cat-summary">
		<?php
		echo esc_html( RuleLabels::summary( $wpb_category['on'], $wpb_category['total'] ) );
		if ( $wpb_category['attention'] > 0 ) {
			echo ' &middot; <strong class="wpb-warn">' . esc_html( RuleLabels::attention( $wpb_category['attention'] ) ) . '</strong>';
		}
		?>
	</p>
	<?php
	foreach ( $wpb_category['rules'] as $wpb_rule ) {
		++$wpb_seq;
		require __DIR__ . '/rule-row.php';
	}
	?>
</section>
