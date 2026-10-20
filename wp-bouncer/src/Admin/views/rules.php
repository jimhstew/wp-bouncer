<?php
/**
 * Rules tab: one panel per rule, each with its own on/off switch.
 *
 * @package WPBouncer
 * @var array<string, mixed> $settings
 */

use WPBouncer\Admin\AdminController;

defined( 'ABSPATH' ) || exit;

$r      = $settings['rules'];
$labels = AdminController::rule_labels();

/**
 * Print a rule panel's heading with its switch.
 *
 * @param string $id Rule id.
 */
$heading = static function ( string $id ) use ( $r, $labels ): void {
	echo '<div class="wpb-rule-head">';
	AdminController::rule_switch( $id, ! empty( $r[ $id ]['enabled'] ) );
	echo '<div><h2>' . esc_html( $labels[ $id ][0] ) . '</h2><p class="description">' . esc_html( $labels[ $id ][1] ) . '</p></div></div>';
};
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpb-rules-form">
	<?php wp_nonce_field( 'wp_bouncer_save' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_save">
	<input type="hidden" name="tab" value="rules">

	<section class="wpb-card wpb-rule" id="rule-ip_blocklist">
		<?php $heading( 'ip_blocklist' ); ?>
		<label for="wpb-ips"><?php esc_html_e( 'Blocked IPs and ranges (one per line):', 'wp-bouncer' ); ?></label>
		<textarea id="wpb-ips" name="wp_bouncer[rules][ip_blocklist][ips]" rows="6" class="large-text code" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;2001:db8::/32"><?php echo esc_textarea( implode( "\n", $r['ip_blocklist']['ips'] ) ); ?></textarea>
	</section>

	<section class="wpb-card wpb-rule" id="rule-login_lockout">
		<?php $heading( 'login_lockout' ); ?>
		<p>
			<?php
			printf(
				/* translators: 1: attempts input, 2: window input, 3: lockout input. */
				esc_html__( 'Lock out an IP after %1$s failed logins within %2$s minutes, for %3$s minutes.', 'wp-bouncer' ),
				'<input type="number" min="1" max="100" class="small-text" name="wp_bouncer[rules][login_lockout][max_attempts]" value="' . esc_attr( (string) $r['login_lockout']['max_attempts'] ) . '" aria-label="' . esc_attr__( 'Attempts', 'wp-bouncer' ) . '">',
				'<input type="number" min="1" max="1440" class="small-text" name="wp_bouncer[rules][login_lockout][window_minutes]" value="' . esc_attr( (string) $r['login_lockout']['window_minutes'] ) . '" aria-label="' . esc_attr__( 'Window in minutes', 'wp-bouncer' ) . '">',
				'<input type="number" min="1" max="43200" class="small-text" name="wp_bouncer[rules][login_lockout][lockout_minutes]" value="' . esc_attr( (string) $r['login_lockout']['lockout_minutes'] ) . '" aria-label="' . esc_attr__( 'Lockout in minutes', 'wp-bouncer' ) . '">'
			); // phpcs:ignore WordPress.Security.EscapeOutput -- inputs escaped above.
			?>
		</p>
		<label for="wpb-banned-users"><?php esc_html_e( 'Usernames that cause an immediate lockout (one per line):', 'wp-bouncer' ); ?></label>
		<textarea id="wpb-banned-users" name="wp_bouncer[rules][login_lockout][banned_usernames]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $r['login_lockout']['banned_usernames'] ) ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Don\'t list a username that a real account on this site uses.', 'wp-bouncer' ); ?></p>
		<label><input type="checkbox" name="wp_bouncer[rules][login_lockout][generic_errors]" value="1" <?php checked( $r['login_lockout']['generic_errors'] ); ?>> <?php esc_html_e( 'Show one generic error for a wrong username or a wrong password, so attackers can\'t tell which usernames exist.', 'wp-bouncer' ); ?></label>
	</section>

	<section class="wpb-card wpb-rule" id="rule-xmlrpc">
		<?php $heading( 'xmlrpc' ); ?>
		<fieldset>
			<label><input type="radio" name="wp_bouncer[rules][xmlrpc][mode]" value="block_all" <?php checked( $r['xmlrpc']['mode'], 'block_all' ); ?>> <?php esc_html_e( 'Block all XML-RPC requests (recommended unless you use an app or service that needs it)', 'wp-bouncer' ); ?></label><br>
			<label><input type="radio" name="wp_bouncer[rules][xmlrpc][mode]" value="block_abuse" <?php checked( $r['xmlrpc']['mode'], 'block_abuse' ); ?>> <?php esc_html_e( 'Allow XML-RPC, but block system.multicall (mass password guessing) and pingbacks (DDoS reflection)', 'wp-bouncer' ); ?></label>
		</fieldset>
	</section>

	<section class="wpb-card wpb-rule" id="rule-user_agent">
		<?php $heading( 'user_agent' ); ?>
		<label><input type="checkbox" name="wp_bouncer[rules][user_agent][block_empty]" value="1" <?php checked( $r['user_agent']['block_empty'] ); ?>> <?php esc_html_e( 'Block requests that send no User-Agent at all', 'wp-bouncer' ); ?></label>
		<p><label for="wpb-ua"><?php esc_html_e( 'Blocked User-Agent patterns (one per line). Plain text matches anywhere, ignoring case. Wrap in slashes for a regular expression, e.g. /^curl\//i', 'wp-bouncer' ); ?></label></p>
		<textarea id="wpb-ua" name="wp_bouncer[rules][user_agent][patterns]" rows="8" class="large-text code"><?php echo esc_textarea( implode( "\n", $r['user_agent']['patterns'] ) ); ?></textarea>
	</section>

	<section class="wpb-card wpb-rule" id="rule-waf">
		<?php $heading( 'waf' ); ?>
		<fieldset class="wpb-inline">
			<label><input type="checkbox" name="wp_bouncer[rules][waf][sqli]" value="1" <?php checked( $r['waf']['sqli'] ); ?>> <?php esc_html_e( 'SQL injection', 'wp-bouncer' ); ?></label>
			<label><input type="checkbox" name="wp_bouncer[rules][waf][xss]" value="1" <?php checked( $r['waf']['xss'] ); ?>> <?php esc_html_e( 'Cross-site scripting', 'wp-bouncer' ); ?></label>
			<label><input type="checkbox" name="wp_bouncer[rules][waf][traversal]" value="1" <?php checked( $r['waf']['traversal'] ); ?>> <?php esc_html_e( 'Path traversal / file inclusion', 'wp-bouncer' ); ?></label>
			<label><input type="checkbox" name="wp_bouncer[rules][waf][code_injection]" value="1" <?php checked( $r['waf']['code_injection'] ); ?>> <?php esc_html_e( 'PHP / command injection', 'wp-bouncer' ); ?></label>
		</fieldset>
		<p><label for="wpb-waf-excl"><?php esc_html_e( 'Parameter names to never inspect (one per line), for forms that legitimately submit code or HTML:', 'wp-bouncer' ); ?></label></p>
		<textarea id="wpb-waf-excl" name="wp_bouncer[rules][waf][excluded_params]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $r['waf']['excluded_params'] ) ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Administrators are never inspected.', 'wp-bouncer' ); ?></p>
	</section>

	<section class="wpb-card wpb-rule" id="rule-user_enumeration">
		<?php $heading( 'user_enumeration' ); ?>
		<label><input type="checkbox" name="wp_bouncer[rules][user_enumeration][block_author_scan]" value="1" <?php checked( $r['user_enumeration']['block_author_scan'] ); ?>> <?php esc_html_e( 'Block ?author=N scans', 'wp-bouncer' ); ?></label><br>
		<label><input type="checkbox" name="wp_bouncer[rules][user_enumeration][block_rest_users]" value="1" <?php checked( $r['user_enumeration']['block_rest_users'] ); ?>> <?php esc_html_e( 'Block the REST API user list (/wp-json/wp/v2/users) for logged-out visitors', 'wp-bouncer' ); ?></label>
		<p class="description"><?php esc_html_e( 'The users sitemap is also removed while this rule is on.', 'wp-bouncer' ); ?></p>
	</section>

	<section class="wpb-card wpb-rule" id="rule-rate_limit">
		<?php $heading( 'rate_limit' ); ?>
		<p>
			<?php
			printf(
				/* translators: 1: requests input, 2: seconds input, 3: ban input. */
				esc_html__( 'Ban an IP that makes more than %1$s requests in %2$s seconds, for %3$s minutes.', 'wp-bouncer' ),
				'<input type="number" min="10" max="100000" class="small-text" name="wp_bouncer[rules][rate_limit][max_requests]" value="' . esc_attr( (string) $r['rate_limit']['max_requests'] ) . '" aria-label="' . esc_attr__( 'Requests', 'wp-bouncer' ) . '">',
				'<input type="number" min="1" max="3600" class="small-text" name="wp_bouncer[rules][rate_limit][window_seconds]" value="' . esc_attr( (string) $r['rate_limit']['window_seconds'] ) . '" aria-label="' . esc_attr__( 'Seconds', 'wp-bouncer' ) . '">',
				'<input type="number" min="1" max="1440" class="small-text" name="wp_bouncer[rules][rate_limit][ban_minutes]" value="' . esc_attr( (string) $r['rate_limit']['ban_minutes'] ) . '" aria-label="' . esc_attr__( 'Ban minutes', 'wp-bouncer' ) . '">'
			); // phpcs:ignore WordPress.Security.EscapeOutput -- inputs escaped above.
			?>
		</p>
		<p class="description"><?php esc_html_e( 'Only requests handled by WordPress count; images, CSS and JS served by the web server do not. Without a persistent object cache (Redis/Memcached) each counted request writes to the database, so leave this off on busy sites without one.', 'wp-bouncer' ); ?></p>
	</section>

	<p class="description">
		<?php
		printf(
			/* translators: %s: link to the Countries tab. */
			esc_html__( 'Country blocking is configured on the %s tab.', 'wp-bouncer' ),
			'<a href="' . esc_url( AdminController::url( 'countries' ) ) . '">' . esc_html__( 'Countries', 'wp-bouncer' ) . '</a>'
		);
		?>
	</p>

	<?php submit_button(); ?>
</form>
