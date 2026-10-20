<?php
/**
 * Activity Log tab.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin $plugin
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\LogListTable;

defined( 'ABSPATH' ) || exit;

$table = new LogListTable( $plugin->log() );
$table->prepare_items();
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
