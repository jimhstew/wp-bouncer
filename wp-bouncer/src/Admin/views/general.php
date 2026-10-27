<?php
/**
 * General tab: mode, IP detection, allowlist, logging, geo source, email alerts.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $settings
 */

defined( 'ABSPATH' ) || exit;

$your_ip = $plugin->client_ip();
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'wp_bouncer_save' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_save">
	<input type="hidden" name="tab" value="general">

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Mode', 'wp-bouncer' ); ?></th>
			<td>
				<fieldset>
					<label><input type="radio" name="wp_bouncer[mode]" value="enforce" <?php checked( $settings['mode'], 'enforce' ); ?>> <strong><?php esc_html_e( 'Enforce', 'wp-bouncer' ); ?></strong>: <?php esc_html_e( 'block matching requests.', 'wp-bouncer' ); ?></label><br>
					<label><input type="radio" name="wp_bouncer[mode]" value="monitor" <?php checked( $settings['mode'], 'monitor' ); ?>> <strong><?php esc_html_e( 'Monitor', 'wp-bouncer' ); ?></strong>: <?php esc_html_e( 'only log what would have been blocked. Use this for a few days after setup to check for false positives.', 'wp-bouncer' ); ?></label>
				</fieldset>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-ip-source"><?php esc_html_e( 'Client IP source', 'wp-bouncer' ); ?></label></th>
			<td>
				<select id="wpb-ip-source" name="wp_bouncer[ip_source]">
					<?php
					$sources = array(
						'remote_addr'      => __( 'REMOTE_ADDR (direct connection, the default)', 'wp-bouncer' ),
						'x_forwarded_for'  => __( 'X-Forwarded-For (load balancer / reverse proxy)', 'wp-bouncer' ),
						'cf_connecting_ip' => __( 'CF-Connecting-IP (Cloudflare)', 'wp-bouncer' ),
						'x_real_ip'        => __( 'X-Real-IP (nginx proxy)', 'wp-bouncer' ),
					);
					foreach ( $sources as $value => $label ) {
						printf( '<option value="%s" %s>%s</option>', esc_attr( $value ), selected( $settings['ip_source'], $value, false ), esc_html( $label ) );
					}
					?>
				</select>
				<p class="description">
					<?php
					/* translators: %s: detected IP address. */
					printf( esc_html__( 'Your IP as currently detected: %s. If this shows your proxy\'s address instead of yours, change the source.', 'wp-bouncer' ), '<code>' . esc_html( ! empty( $your_ip ) ? $your_ip : '?' ) . '</code>' );
					?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-proxies"><?php esc_html_e( 'Trusted proxies', 'wp-bouncer' ); ?></label></th>
			<td>
				<textarea id="wpb-proxies" name="wp_bouncer[trusted_proxies]" rows="4" class="large-text code" placeholder="173.245.48.0/20"><?php echo esc_textarea( implode( "\n", $settings['trusted_proxies'] ) ); ?></textarea>
				<p class="description"><?php esc_html_e( 'IPs or CIDR ranges of your proxy or CDN, one per line. The IP header above is only believed when the request comes from one of these. With a header selected and this list empty, the header is ignored, the connection address is used, and IP bans and lockouts are suspended (login attempts are logged; rate limiting is effectively off). A proxy header from an unlisted private or local address also suspends bans; from an unlisted public address it does not (that address is treated as the visitor), so list your CDN\'s ranges. Ranges wider than /8 (IPv4) or /16 (IPv6) are ignored.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-allowlist"><?php esc_html_e( 'Allowlist', 'wp-bouncer' ); ?></label></th>
			<td>
				<textarea id="wpb-allowlist" name="wp_bouncer[allowlist]" rows="5" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['allowlist'] ) ); ?></textarea>
				<p class="description">
					<?php esc_html_e( 'IPs or CIDR ranges that skip every rule, one per line. Loopback requests (WP-Cron, health checks) skip every rule only when they carry no proxy header (X-Forwarded-For, X-Real-IP, CF-Connecting-IP or Forwarded), and a loopback address is never banned. Ranges wider than /8 (IPv4) or /16 (IPv6) are ignored.', 'wp-bouncer' ); ?>
					<?php if ( $your_ip ) : ?>
						<button type="button" class="button button-small" data-wpb-add-ip="#wpb-allowlist"><?php esc_html_e( 'Add my IP', 'wp-bouncer' ); ?></button>
					<?php endif; ?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-retention"><?php esc_html_e( 'Keep log entries for', 'wp-bouncer' ); ?></label></th>
			<td>
				<input id="wpb-retention" type="number" min="1" max="365" name="wp_bouncer[log_retention_days]" value="<?php echo esc_attr( (string) $settings['log_retention_days'] ); ?>" class="small-text"> <?php esc_html_e( 'days', 'wp-bouncer' ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-message"><?php esc_html_e( 'Block page message', 'wp-bouncer' ); ?></label></th>
			<td>
				<textarea id="wpb-message" name="wp_bouncer[block_message]" rows="2" class="large-text"><?php echo esc_textarea( $settings['block_message'] ); ?></textarea>
				<p class="description"><?php esc_html_e( 'Plain text shown to blocked visitors, with a reference number that matches the log entry.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Country lookup', 'wp-bouncer' ); ?></th>
			<td>
				<fieldset>
					<label><input type="radio" name="wp_bouncer[geo_source]" value="database" <?php checked( $settings['geo_source'], 'database' ); ?>> <?php esc_html_e( 'Local geo database (import one under Tools)', 'wp-bouncer' ); ?></label><br>
					<label><input type="radio" name="wp_bouncer[geo_source]" value="header" <?php checked( $settings['geo_source'], 'header' ); ?>> <?php esc_html_e( 'Header or server variable set by my CDN or web server, falling back to the local database', 'wp-bouncer' ); ?></label>
				</fieldset>
				<p>
					<label for="wpb-geo-header"><?php esc_html_e( 'Header / variable name:', 'wp-bouncer' ); ?></label>
					<input id="wpb-geo-header" type="text" name="wp_bouncer[geo_header]" value="<?php echo esc_attr( $settings['geo_header'] ); ?>" class="regular-text code">
				</p>
				<p class="description"><?php esc_html_e( 'For example CF-IPCountry (Cloudflare), GEOIP_COUNTRY_CODE (nginx/Apache GeoIP module) or MM_COUNTRY_CODE. Only use a header if visitors can\'t bypass the CDN to reach your server, since clients can forge headers.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
	</table>

	<h2 id="wpb-alerts"><?php esc_html_e( 'Email alerts', 'wp-bouncer' ); ?></h2>
	<p class="description"><?php esc_html_e( 'Attackers who get in usually create an administrator account or install a plugin as a backdoor. Get an email when that happens, so you find out the same day.', 'wp-bouncer' ); ?></p>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Send alerts', 'wp-bouncer' ); ?></th>
			<td>
				<fieldset>
					<label><input type="checkbox" name="wp_bouncer[alerts][enabled]" value="1" <?php checked( $settings['alerts']['enabled'] ); ?>> <strong><?php esc_html_e( 'Email me when:', 'wp-bouncer' ); ?></strong></label><br>
					<label class="wpb-indent"><input type="checkbox" name="wp_bouncer[alerts][new_admin]" value="1" <?php checked( $settings['alerts']['new_admin'] ); ?>> <?php esc_html_e( 'an administrator account is created, or an account is promoted to administrator', 'wp-bouncer' ); ?></label><br>
					<label class="wpb-indent"><input type="checkbox" name="wp_bouncer[alerts][plugin_changes]" value="1" <?php checked( $settings['alerts']['plugin_changes'] ); ?>> <?php esc_html_e( 'a plugin is installed, activated, deactivated or deleted (including WP Bouncer itself being deactivated)', 'wp-bouncer' ); ?></label><br>
					<label class="wpb-indent"><input type="checkbox" name="wp_bouncer[alerts][plugin_updates]" value="1" <?php checked( $settings['alerts']['plugin_updates'] ); ?>> <?php esc_html_e( 'a plugin is updated (off by default: updates are routine)', 'wp-bouncer' ); ?></label><br>
					<label class="wpb-indent"><input type="checkbox" name="wp_bouncer[alerts][firewall_changes]" value="1" <?php checked( $settings['alerts']['firewall_changes'] ); ?>> <?php esc_html_e( 'the firewall is weakened (mode, allowlist, trusted proxies, IP source or a rule switched off), or WP_BOUNCER_DISABLE is on', 'wp-bouncer' ); ?></label><br>
					<label class="wpb-indent"><input type="checkbox" name="wp_bouncer[alerts][admin_login_location]" value="1" <?php checked( $settings['alerts']['admin_login_location'] ); ?>> 
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: number of days. */
							__( 'an administrator logs in from a new location (a country or network not seen for that account in the last %d days)', 'wp-bouncer' ),
							\WPBouncer\AdminLogins\AdminLoginRecorder::window_days()
						)
					);
					?>
					</label>
				</fieldset>
				<p class="description"><?php esc_html_e( 'Changes made in one go arrive as one email. At most 20 emails are sent per hour (administrator login alerts have their own limit of 10 per hour, and at most 3 per account); every alert is also written to the Activity Log.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-alert-to"><?php esc_html_e( 'Send to', 'wp-bouncer' ); ?></label></th>
			<td>
				<textarea id="wpb-alert-to" name="wp_bouncer[alerts][recipients]" rows="2" class="large-text code" placeholder="<?php echo esc_attr( (string) get_option( 'admin_email' ) ); ?>"><?php echo esc_textarea( implode( "\n", $settings['alerts']['recipients'] ) ); ?></textarea>
				<p class="description">
					<?php
					/* translators: %s: the site's admin email address. */
					printf( esc_html__( 'Email addresses, one per line (up to 10). Leave empty to use the site\'s admin email, %s.', 'wp-bouncer' ), '<code>' . esc_html( (string) get_option( 'admin_email' ) ) . '</code>' );
					?>
					<button type="submit" class="button button-small" form="wpb-test-alert-form"><?php esc_html_e( 'Send a test email', 'wp-bouncer' ); ?></button>
				</p>
				<p class="description"><?php esc_html_e( 'Save first if you changed the addresses. Alerts use WordPress\'s normal mail sending; many hosts need an SMTP plugin for mail to arrive.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Administrator logins', 'wp-bouncer' ); ?></th>
			<td>
				<label><input type="checkbox" name="wp_bouncer[alerts][record_admin_logins]" value="1" <?php checked( $settings['alerts']['record_admin_logins'] ); ?>> <?php esc_html_e( 'Record administrator logins in the Activity Log', 'wp-bouncer' ); ?></label>
				<p class="description"><?php esc_html_e( 'Turning this off also stops the new-location email and the per-account location history. Application-password and XML-RPC logins are recorded once per hour per network. With no geo database, only the network is compared.', 'wp-bouncer' ); ?></p>
				<?php if ( 'remote_addr' !== $settings['ip_source'] && empty( $settings['trusted_proxies'] ) ) : ?>
					<p class="description"><strong><?php esc_html_e( 'Location checks are skipped until a trusted proxy is configured.', 'wp-bouncer' ); ?></strong></p>
				<?php endif; ?>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="wpb-test-alert-form">
	<?php wp_nonce_field( 'wp_bouncer_test_alert' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_test_alert">
</form>
