<?php
/**
 * Traffic tab: every request that reached WordPress, and its settings.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $settings
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\TrafficListTable;

defined( 'ABSPATH' ) || exit;

$wpb_t       = $settings['traffic'];
$wpb_log     = $plugin->traffic_log();
$wpb_since24 = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpb-card">
	<?php wp_nonce_field( 'wp_bouncer_save' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_save">
	<input type="hidden" name="tab" value="traffic">
	<div class="wpb-rule-head">
		<label class="wpb-switch"><input type="checkbox" name="wp_bouncer[traffic][enabled]" value="1" <?php checked( $wpb_t['enabled'] ); ?>><span class="wpb-slider" aria-hidden="true"></span><span class="screen-reader-text"><?php esc_html_e( 'Enabled', 'wp-bouncer' ); ?></span></label>
		<div>
			<h2><?php esc_html_e( 'Record traffic', 'wp-bouncer' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Every request that reaches WordPress: when, from which IP, what kind of client, which URL, the response code and the referring page. Images, CSS and JS served directly by your web server are not included.', 'wp-bouncer' ); ?></p>
		</div>
	</div>
	<p>
		<label for="wpb-traffic-days"><?php esc_html_e( 'Keep requests for', 'wp-bouncer' ); ?></label>
		<select id="wpb-traffic-days" name="wp_bouncer[traffic][retention_days]">
			<?php for ( $wpb_d = 1; $wpb_d <= 7; $wpb_d++ ) : ?>
				<option value="<?php echo (int) $wpb_d; ?>" <?php selected( (int) $wpb_t['retention_days'], $wpb_d ); ?>>
					<?php
					/* translators: %d: number of days. */
					echo esc_html( sprintf( _n( '%d day', '%d days', $wpb_d, 'wp-bouncer' ), $wpb_d ) );
					?>
				</option>
			<?php endfor; ?>
		</select>
	</p>
	<label><input type="checkbox" name="wp_bouncer[traffic][skip_background]" value="1" <?php checked( $wpb_t['skip_background'] ); ?>> <?php esc_html_e( 'Skip WordPress\'s own background requests (WP-Cron and the admin Heartbeat), which arrive every minute or so', 'wp-bouncer' ); ?></label><br>
	<label><input type="checkbox" name="wp_bouncer[traffic][skip_admins]" value="1" <?php checked( $wpb_t['skip_admins'] ); ?>> <?php esc_html_e( 'Skip logged-in administrators', 'wp-bouncer' ); ?></label>
	<p class="description"><?php esc_html_e( 'Each recorded request is one database write. On a busy site without a fast database, keep the retention short or leave this off. Passwords, reset keys and tokens are removed from URLs before they are saved. IP addresses are personal data in many countries; mention this log in your privacy policy.', 'wp-bouncer' ); ?></p>
	<?php submit_button( __( 'Save traffic settings', 'wp-bouncer' ), 'primary', 'submit', false ); ?>
</form>

<?php if ( ! $wpb_t['enabled'] ) : ?>
	<div class="notice notice-info inline"><p><?php esc_html_e( 'Traffic recording is off. Switch it on above to start recording.', 'wp-bouncer' ); ?></p></div>
<?php endif; ?>

<?php
$wpb_4xx = $wpb_log->count(
	array(
		'since'  => $wpb_since24,
		'status' => '4xx',
	)
);
?>
<div class="wpb-stats">
	<div class="wpb-card wpb-stat"><div class="wpb-stat-value"><?php echo esc_html( number_format_i18n( $wpb_log->count( array( 'since' => $wpb_since24 ) ) ) ); ?></div><div class="wpb-stat-label"><?php esc_html_e( 'Requests, last 24 hours', 'wp-bouncer' ); ?></div></div>
	<div class="wpb-card wpb-stat"><div class="wpb-stat-value"><?php echo esc_html( number_format_i18n( $wpb_log->unique_ips( $wpb_since24 ) ) ); ?></div><div class="wpb-stat-label"><?php esc_html_e( 'Different IPs, last 24 hours', 'wp-bouncer' ); ?></div></div>
	<div class="wpb-card wpb-stat"><div class="wpb-stat-value"><?php echo esc_html( number_format_i18n( $wpb_4xx ) ); ?></div><div class="wpb-stat-label"><?php esc_html_e( '4xx responses (not found, blocked), last 24 hours', 'wp-bouncer' ); ?></div></div>
	<div class="wpb-card wpb-stat">
		<div class="wpb-stat-label"><?php esc_html_e( 'Clients, last 24 hours', 'wp-bouncer' ); ?></div>
		<?php foreach ( array_slice( $wpb_log->by_client( $wpb_since24 ), 0, 4, true ) as $wpb_type => $wpb_n ) : ?>
			<div><a href="<?php echo esc_url( AdminController::url( 'traffic', array( 'client' => $wpb_type ) ) ); ?>"><?php echo esc_html( AdminController::client_label( $wpb_type ) ); ?></a>: <?php echo esc_html( number_format_i18n( $wpb_n ) ); ?></div>
		<?php endforeach; ?>
	</div>
</div>

<?php
$wpb_table = new TrafficListTable( $wpb_log );
$wpb_table->prepare_items();
?>
<form method="get" class="wpb-log-form">
	<input type="hidden" name="page" value="<?php echo esc_attr( AdminController::SLUG ); ?>">
	<input type="hidden" name="tab" value="traffic">
	<?php
	$wpb_filters = AdminController::traffic_filters_from_request();
	if ( ! empty( $wpb_filters['ip'] ) ) {
		printf( '<input type="hidden" name="ip" value="%s">', esc_attr( $wpb_filters['ip'] ) );
		printf(
			'<p>%s <a href="%s">%s</a></p>',
			/* translators: %s: IP address. */
			esc_html( sprintf( __( 'Showing requests from %s.', 'wp-bouncer' ), $wpb_filters['ip'] ) ),
			esc_url( AdminController::url( 'traffic' ) ),
			esc_html__( 'Show all', 'wp-bouncer' )
		);
	}
	$wpb_table->search_box( __( 'Search IP, URL, referrer, User-Agent', 'wp-bouncer' ), 'wpb-traffic' );
	$wpb_table->display();
	?>
</form>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpb-clear-log" onsubmit="return confirm('<?php echo esc_js( __( 'Delete every recorded request? This cannot be undone.', 'wp-bouncer' ) ); ?>');">
	<?php wp_nonce_field( 'wp_bouncer_clear_traffic' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_clear_traffic">
	<?php submit_button( __( 'Clear traffic log', 'wp-bouncer' ), 'delete', 'submit', false ); ?>
</form>
