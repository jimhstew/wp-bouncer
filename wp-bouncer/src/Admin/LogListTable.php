<?php
/**
 * WP_List_Table for the Activity Log screen.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Geo\Countries;
use WPBouncer\Log\BlockLog;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Support\CounterSubject;
use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( '\WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Paged, sortable, filterable table of blocks, lockouts, monitored matches and alerts.
 */
final class LogListTable extends \WP_List_Table {

	/**
	 * Log store.
	 *
	 * @var BlockLog
	 */
	private BlockLog $log;

	/**
	 * Set up the LogListTable.
	 *
	 * @param BlockLog $log Log store.
	 */
	public function __construct( BlockLog $log ) {
		$this->log = $log;
		parent::__construct(
			array(
				'singular' => 'entry',
				'plural'   => 'entries',
				'ajax'     => false,
			)
		);
	}

	/** {@inheritDoc} */
	public function get_columns() {
		return array(
			'created_at' => __( 'Time', 'wp-bouncer' ),
			'ip'         => __( 'IP', 'wp-bouncer' ),
			'country'    => __( 'Country', 'wp-bouncer' ),
			'rule'       => __( 'Rule', 'wp-bouncer' ),
			'action'     => __( 'Action', 'wp-bouncer' ),
			'reason'     => __( 'Reason', 'wp-bouncer' ),
			'request'    => __( 'Request', 'wp-bouncer' ),
			'user_agent' => __( 'User-Agent', 'wp-bouncer' ),
		);
	}

	/** {@inheritDoc} */
	protected function get_sortable_columns() {
		return array(
			'created_at' => array( 'created_at', true ),
			'ip'         => array( 'ip', false ),
			'country'    => array( 'country', false ),
			'rule'       => array( 'rule', false ),
			'action'     => array( 'action', false ),
		);
	}

	/**
	 * Load the rows for the current page.
	 *
	 * @return void
	 */
	public function prepare_items() {
		$per_page = 50;
		$filters  = AdminController::log_filters_from_request();
		// phpcs:disable WordPress.Security.NonceVerification -- read-only list parameters, sanitised here and never used to change state.
		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : 'created_at';
		$order   = isset( $_GET['order'] ) ? sanitize_key( wp_unslash( $_GET['order'] ) ) : 'desc';
		// phpcs:enable WordPress.Security.NonceVerification

		$this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns(), 'created_at' );
		$this->items           = $this->log->query( $filters, $per_page, $this->get_pagenum(), $orderby, strtoupper( $order ) );
		$this->set_pagination_args(
			array(
				'total_items' => $this->log->count( $filters ),
				'per_page'    => $per_page,
			)
		);
	}

	/**
	 * Message shown when there are no rows.
	 *
	 * @return void
	 */
	public function no_items() {
		esc_html_e( 'Nothing has been turned away yet.', 'wp-bouncer' );
	}

	/**
	 * Filter dropdowns and export/clear buttons above the table.
	 *
	 * @param string $which top|bottom.
	 * @return void
	 */
	protected function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}
		$filters = AdminController::log_filters_from_request();
		echo '<div class="alignleft actions">';

		echo '<label class="screen-reader-text" for="wpb-filter-rule">' . esc_html__( 'Filter by rule', 'wp-bouncer' ) . '</label>';
		echo '<select name="rule" id="wpb-filter-rule"><option value="">' . esc_html__( 'All rules', 'wp-bouncer' ) . '</option>';
		foreach ( AdminController::log_rule_labels() as $id => $label ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $id ), selected( $filters['rule'] ?? '', $id, false ), esc_html( $label ) );
		}
		echo '</select>';

		echo '<label class="screen-reader-text" for="wpb-filter-action">' . esc_html__( 'Filter by action', 'wp-bouncer' ) . '</label>';
		echo '<select name="log_action" id="wpb-filter-action"><option value="">' . esc_html__( 'All actions', 'wp-bouncer' ) . '</option>';
		foreach ( array( BlockLogInterface::ACTION_BLOCKED, BlockLogInterface::ACTION_LOCKOUT, BlockLogInterface::ACTION_MONITORED, BlockLogInterface::ACTION_ALERT ) as $action ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $action ), selected( $filters['action'] ?? '', $action, false ), esc_html( AdminController::action_label( $action ) ) );
		}
		echo '</select>';

		submit_button( __( 'Filter', 'wp-bouncer' ), '', 'filter_action', false );
		echo '</div>';

		$args   = array_merge( AdminController::log_filters_to_args( $filters ), array( 'action' => 'wp_bouncer_export_log' ) );
		$export = wp_nonce_url( add_query_arg( $args, admin_url( 'admin-post.php' ) ), 'wp_bouncer_export_log' );
		echo '<div class="alignleft actions"><a class="button" href="' . esc_url( $export ) . '">' . esc_html__( 'Export CSV', 'wp-bouncer' ) . '</a></div>';
	}

	/**
	 * Fallback column renderer.
	 *
	 * @param array<string, string> $item        Row.
	 * @param string                $column_name Column.
	 * @return string
	 */
	protected function column_default( $item, $column_name ) {
		return esc_html( $item[ $column_name ] ?? '' );
	}

	/**
	 * Local time with the UTC value in a tooltip.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_created_at( $item ) {
		$local = get_date_from_gmt( $item['created_at'], get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );
		return sprintf( '<time datetime="%1$sZ" title="%1$s UTC">%2$s</time>', esc_attr( str_replace( ' ', 'T', $item['created_at'] ) ), esc_html( $local ) );
	}

	/**
	 * IP with "filter" and "block" row actions.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_ip( $item ) {
		$ip      = $item['ip'];
		$actions = array(
			'filter' => sprintf( '<a href="%s">%s</a>', esc_url( AdminController::url( 'log', array( 's' => $ip ) ) ), esc_html__( 'Show all', 'wp-bouncer' ) ),
			'block'  => sprintf(
				'<a href="%s">%s</a>',
				esc_url( AdminController::block_ip_url( $ip ) ),
				esc_html__( 'Block IP', 'wp-bouncer' )
			),
		);
		// The firewall counts and bans an IPv6 client by its network, and the log shows one address per network.
		$subject = CounterSubject::of( $ip );
		if ( IpUtils::is_ipv6( $ip ) && AdminController::is_subject_network( $subject ) ) {
			$actions['block_net'] = sprintf(
				'<a href="%s">%s</a>',
				esc_url( AdminController::block_ip_url( $subject ) ),
				/* translators: %d: IPv6 prefix length, such as 64. */
				esc_html( sprintf( __( 'Block /%d', 'wp-bouncer' ), (int) substr( $subject, (int) strrpos( $subject, '/' ) + 1 ) ) )
			);
		}
		return '<code>' . esc_html( $ip ) . '</code>' . $this->row_actions( $actions );
	}

	/**
	 * Flag and code.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_country( $item ) {
		if ( '' === $item['country'] ) {
			return '<span aria-hidden="true">—</span>';
		}
		return sprintf( '<span title="%s">%s %s</span>', esc_attr( Countries::name( $item['country'] ) ), esc_html( AdminController::flag( $item['country'] ) ), esc_html( $item['country'] ) );
	}

	/**
	 * Rule title.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_rule( $item ) {
		return esc_html( AdminController::rule_title( $item['rule'] ) );
	}

	/**
	 * Badge.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_action( $item ) {
		return sprintf( '<span class="wpb-badge wpb-badge-%s">%s</span>', esc_attr( $item['action'] ), esc_html( AdminController::action_label( $item['action'] ) ) );
	}

	/**
	 * Method + URI.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_request( $item ) {
		if ( '' === $item['uri'] ) {
			return '';
		}
		return sprintf( '<code class="wpb-trunc" title="%2$s">%1$s %2$s</code>', esc_html( $item['method'] ), esc_attr( $item['uri'] ) );
	}

	/**
	 * Truncated User-Agent.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_user_agent( $item ) {
		return sprintf( '<span class="wpb-trunc" title="%1$s">%1$s</span>', esc_attr( $item['user_agent'] ) );
	}
}
