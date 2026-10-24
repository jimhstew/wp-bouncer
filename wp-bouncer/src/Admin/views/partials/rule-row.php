<?php
/**
 * Rules tab: one rule row (switch, title, state, warnings) and its settings disclosure.
 *
 * THE CONTRACT: the settings inside the <details> are always rendered and never disabled by
 * this plugin's markup, so a closed panel still submits. Settings::apply_form() switches a rule
 * off if its inputs are missing from the POST. Do not lazy-load or disable hidden inputs. The
 * round-trip tests (tests/Integration/Admin/RulesTabTest.php) guard this. The only inputs that
 * may be disabled are those a sub-site admin may not change on multisite (the server pins them).
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $r        Settings: the rules array.
 * @var array<string, mixed> $wpb_rule One rule of RuleOverview::categories().
 * @var string               $wpb_open Built-in rule id opened by the wpb_rule argument, or ''.
 * @var int                  $wpb_seq  Running number of rows (ids for rows with no anchor).
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\RuleStatus;

defined( 'ABSPATH' ) || exit;

$wpb_id       = (string) $wpb_rule['id'];
$wpb_row_id   = $wpb_rule['anchor'] ?? 'wpb-rule-extra-' . $wpb_seq;
$wpb_title_id = $wpb_row_id . '-title';
$wpb_has_form = $wpb_rule['builtin'] && null === $wpb_rule['external_tab'];
$wpb_locked   = 'uploads_php' === $wpb_id && ! current_user_can( AdminController::FIREWALL_CAPABILITY );
$wpb_is_open  = $wpb_has_form && ( RuleStatus::FLAG_ATTENTION === $wpb_rule['flag'] || $wpb_id === $wpb_open );
$wpb_live     = ! $wpb_rule['unknown'] && ! $wpb_rule['removed'];
if ( $wpb_rule['unknown'] ) {
	$wpb_state = __( 'Unknown', 'wp-bouncer' );
} elseif ( $wpb_rule['removed'] ) {
	$wpb_state = __( 'Removed by a plugin', 'wp-bouncer' );
} else {
	$wpb_state = $wpb_rule['on'] ? __( 'On', 'wp-bouncer' ) : __( 'Off', 'wp-bouncer' );
}
?>
<div class="wpb-rule" id="<?php echo esc_attr( $wpb_row_id ); ?>" tabindex="-1" role="group" aria-labelledby="<?php echo esc_attr( $wpb_title_id ); ?>">
	<div class="wpb-rule-head">
		<?php if ( $wpb_has_form ) : ?>
			<?php AdminController::rule_switch( $wpb_id, $wpb_rule['on'], $wpb_locked, $wpb_rule['title'] ); ?>
		<?php endif; ?>
		<div class="wpb-rule-text">
			<h3 id="<?php echo esc_attr( $wpb_title_id ); ?>"><?php echo esc_html( $wpb_rule['title'] ); ?></h3>
			<?php if ( ! $wpb_rule['builtin'] ) : ?>
				<code class="wpb-rule-id"><?php echo esc_html( $wpb_id ); ?></code>
			<?php endif; ?>
			<span class="wpb-state"<?php echo $wpb_live ? ' data-saved="' . ( $wpb_rule['on'] ? 'on' : 'off' ) . '"' : ''; ?>><?php echo esc_html( $wpb_state ); ?></span>
			<?php if ( '' !== $wpb_rule['description'] ) : ?>
				<p class="description"><?php echo esc_html( $wpb_rule['description'] ); ?></p>
			<?php endif; ?>
			<?php if ( $wpb_locked ) : ?>
				<p class="description"><?php esc_html_e( 'Managed by your network administrator.', 'wp-bouncer' ); ?></p>
			<?php endif; ?>
			<?php if ( ! $wpb_rule['builtin'] ) : ?>
				<p class="description"><?php esc_html_e( 'Managed by the plugin that added it.', 'wp-bouncer' ); ?></p>
			<?php endif; ?>
			<?php require __DIR__ . '/rule-flags.php'; ?>
			<?php
			if ( null !== $wpb_rule['external_tab'] ) {
				require __DIR__ . '/../rules/country.php';
			}
			?>
		</div>
	</div>
	<?php if ( $wpb_has_form ) : ?>
		<details class="wpb-rule-settings"<?php echo $wpb_is_open ? ' open' : ''; ?>>
			<summary><?php esc_html_e( 'Settings', 'wp-bouncer' ); ?><span class="screen-reader-text">: <?php echo esc_html( $wpb_rule['title'] ); ?></span></summary>
			<div class="wpb-rule-body">
				<?php
				// Only ids from the built-in catalog ever reach a file path (has_form implies builtin).
				require __DIR__ . '/../rules/' . $wpb_id . '.php';
				?>
			</div>
		</details>
	<?php endif; ?>
</div>
