<?php
/**
 * Rules tab: the country rule's status card. No inputs: its settings belong to the Countries tab,
 * and Settings::apply_form() ignores a rules.country field posted from this tab.
 *
 * @package WPBouncer
 * @var array<string, mixed> $wpb_rule The country row of RuleOverview::categories().
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

$wpb_meta = get_option( Plugin::GEO_META_OPTION, array() );
?>
<p class="wpb-country-summary"><?php echo esc_html( $wpb_rule['summary'] ); ?></p>
<p class="description">
	<?php
	if ( ! empty( $wpb_meta['rows'] ) ) {
		/* translators: %s: number of IP ranges. */
		printf( esc_html__( 'Geo database: %s IP ranges loaded.', 'wp-bouncer' ), esc_html( number_format_i18n( (int) $wpb_meta['rows'] ) ) );
	} else {
		esc_html_e( 'No geo database loaded.', 'wp-bouncer' );
	}
	?>
</p>
<p><a class="button" href="<?php echo esc_url( AdminController::url( 'countries' ) ); ?>"><?php esc_html_e( 'Configure on the Countries tab', 'wp-bouncer' ); ?></a></p>
