<?php
/**
 * Activity Log tab.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin $plugin
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\LogListTable;
use WPBouncer\Admin\ThreatMapPanel;

defined( 'ABSPATH' ) || exit;

$plugin->log_writer()->flush_summary(); // A quiet site still records an earlier flood.
$table = new LogListTable( $plugin->log() );
$table->prepare_items();

$wpb_range = AdminController::log_date_range();
$wpb_notes = array(
	'invalid'  => __( 'A date was not valid, so it was ignored. Use the date pickers or the format YYYY-MM-DD.', 'wp-bouncer' ),
	'reversed' => __( 'The end date is before the start date, so the date filter was ignored.', 'wp-bouncer' ),
	'capped'   => __( 'The date range is limited to 365 days, so the start date was moved.', 'wp-bouncer' ),
);
if ( isset( $wpb_notes[ $wpb_range->note ] ) ) {
	echo '<div class="notice notice-warning inline"><p>' . esc_html( $wpb_notes[ $wpb_range->note ] ) . '</p></div>';
}
( new ThreatMapPanel( $plugin ) )->render( AdminController::log_filters_from_request(), $wpb_range );
?>
<form method="get" class="wpb-log-form">
	<input type="hidden" name="page" value="<?php echo esc_attr( AdminController::SLUG ); ?>">
	<input type="hidden" name="tab" value="log">
	<?php
	$table->search_box( __( 'Search IP, URL, reason', 'wp-bouncer' ), 'wpb-log' );
	$table->display();
	?>
</form>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpb-clear-log" onsubmit="return confirm('<?php echo esc_js( __( 'Delete every log entry? This cannot be undone.', 'wp-bouncer' ) ); ?>');">
	<?php wp_nonce_field( 'wp_bouncer_clear_log' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_clear_log">
	<?php submit_button( __( 'Clear log', 'wp-bouncer' ), 'delete', 'submit', false ); ?>
</form>
