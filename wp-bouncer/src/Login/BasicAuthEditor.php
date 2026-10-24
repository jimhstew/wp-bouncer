<?php
/**
 * Recognises a request that carries a valid application password of an editor.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Login;

defined( 'ABSPATH' ) || exit;

/**
 * Checks Basic credentials at plugins_loaded, before core would.
 *
 * Core accepts application passwords only once REST_REQUEST is defined, which is
 * after the firewall has run, so the WAF can't ask WordPress who the user is.
 * This looks at the credentials itself and has no side effects: it never calls
 * wp_authenticate_application_password(), fires no authentication hooks, counts
 * no failures, updates no "last used" data and doesn't touch the current user.
 *
 * It only runs where core itself accepts application passwords (REST and XML-RPC
 * requests); on any other path credentials mean nothing. Cheap checks come first and
 * hashing last: the request must not be refused (another site, a blocked country), the
 * user must exist, must be able to edit posts, must be allowed application passwords, and
 * the client must not be locked out. A wrong password is reported through the on_failure
 * callback (the plugin counts it as a login failure on the client's counter subject), so the
 * lockout closes after a few tries and this stops hashing; core's own count for the same
 * request is skipped by the plugin. Nothing is stored per password.
 * At most 20 stored passwords are compared. Early exits do one dummy fast-hash check, so
 * timing doesn't tell an attacker which test failed.
 */
final class BasicAuthEditor {

	/** The most stored passwords of one user that are compared. */
	public const MAX_PASSWORDS = 20;

	/**
	 * Server variables.
	 *
	 * @var array<string, mixed>
	 */
	private array $server;

	/**
	 * Is this a request core authenticates with application passwords (REST or XML-RPC)?
	 *
	 * @var callable
	 */
	private $is_api_request;

	/**
	 * Is the request refused anyway (another site, a blocked country)?
	 *
	 * @var callable
	 */
	private $is_refused;

	/**
	 * Tells whether the client is locked out.
	 *
	 * @var callable
	 */
	private $locked_out;

	/**
	 * Called with the user name when a password was checked and didn't match.
	 *
	 * @var callable|null
	 */
	private $on_failure;

	/**
	 * Result of the check.
	 *
	 * @var array{editor: bool, admin: bool}|null
	 */
	private ?array $result = null;

	/**
	 * Constructor.
	 *
	 * @param array<string, mixed> $server         Server variables (slashes removed).
	 * @param callable             $is_api_request Returns true on REST and XML-RPC requests.
	 * @param callable             $is_refused     Returns true when the request is refused anyway.
	 * @param callable             $locked_out     Returns true when the client is locked out of logging in.
	 * @param callable|null        $on_failure     Called with the user name after a wrong password (null: nothing).
	 */
	public function __construct( array $server, callable $is_api_request, callable $is_refused, callable $locked_out, ?callable $on_failure = null ) {
		$this->server         = $server;
		$this->is_api_request = $is_api_request;
		$this->is_refused     = $is_refused;
		$this->locked_out     = $locked_out;
		$this->on_failure     = $on_failure;
	}

	/**
	 * Basic credentials in the server variables, read the way core reads them.
	 *
	 * Core needs PHP_AUTH_USER and PHP_AUTH_PW together; failing that it copies a
	 * well-formed "Basic" Authorization header (HTTP_AUTHORIZATION, else
	 * REDIRECT_HTTP_AUTHORIZATION) that decodes to "user:password".
	 *
	 * @param array<string, mixed> $server Server variables.
	 * @return array{0: string, 1: string}|null [ user name, password ], or null when there are none.
	 */
	public static function credentials( array $server ): ?array {
		if ( isset( $server['PHP_AUTH_USER'] ) || isset( $server['PHP_AUTH_PW'] ) ) {
			if ( isset( $server['PHP_AUTH_USER'], $server['PHP_AUTH_PW'] ) && is_string( $server['PHP_AUTH_USER'] ) && is_string( $server['PHP_AUTH_PW'] ) ) {
				return array( $server['PHP_AUTH_USER'], $server['PHP_AUTH_PW'] );
			}
			return null;
		}
		$header = $server['HTTP_AUTHORIZATION'] ?? $server['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
		if ( ! is_string( $header ) || 1 !== preg_match( '%^Basic [a-z\d/+]*={0,2}$%i', $header ) ) {
			return null;
		}
		$decoded = base64_decode( substr( $header, 6 ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- decoding a Basic header, not obfuscating.
		if ( ! str_contains( $decoded, ':' ) ) {
			return null;
		}
		return explode( ':', $decoded, 2 );
	}

	/** Do the credentials belong to a user who can edit posts, with a valid application password? */
	public function is_editor(): bool {
		return $this->check()['editor'];
	}

	/** Do the credentials belong to a user who can manage options, with a valid application password? */
	public function is_admin(): bool {
		return $this->check()['admin'];
	}

	/**
	 * Run the check once.
	 *
	 * @return array{editor: bool, admin: bool}
	 */
	private function check(): array {
		if ( null !== $this->result ) {
			return $this->result;
		}
		$this->result = array(
			'editor' => false,
			'admin'  => false,
		);

		// Where core won't look at the credentials, they mean nothing: no lookup, no hashing.
		if ( ! (bool) call_user_func( $this->is_api_request ) ) {
			return $this->result;
		}
		$credentials = self::credentials( $this->server );
		if ( null === $credentials || ! class_exists( '\WP_Application_Passwords' ) ) {
			return $this->result;
		}
		if ( (bool) call_user_func( $this->is_refused ) ) {
			return $this->stop();
		}

		$user = get_user_by( 'login', $credentials[0] );
		if ( ! $user && is_email( $credentials[0] ) ) {
			$user = get_user_by( 'email', $credentials[0] );
		}
		if ( ! $user || ! $user->has_cap( 'edit_posts' ) || ( is_multisite() && ! empty( $user->spam ) ) ) {
			return $this->stop();
		}
		if ( ! wp_is_application_passwords_available() || ! wp_is_application_passwords_available_for_user( $user ) || (bool) call_user_func( $this->locked_out ) ) {
			return $this->stop();
		}

		// As core does: only letters and digits count, so the spaces in the displayed form are ignored.
		$password = (string) preg_replace( '/[^a-z\d]/i', '', $credentials[1] );
		if ( '' === $password ) {
			return $this->fail( $credentials[0] );
		}

		$stored = array_slice( \WP_Application_Passwords::get_user_application_passwords( $user->ID ), 0, self::MAX_PASSWORDS );
		foreach ( $stored as $item ) {
			if ( ! isset( $item['password'] ) || ! is_string( $item['password'] ) || ! \WP_Application_Passwords::check_password( $password, $item['password'] ) ) {
				continue;
			}
			// Let other plugins veto the password, as core does, on a throwaway error object.
			$error = new \WP_Error();
			/** This action is documented in wp-includes/user.php */
			do_action( 'wp_authenticate_application_password_errors', $error, $user, $item, $password );
			if ( $error->has_errors() ) {
				return $this->result;
			}
			$this->result = array(
				'editor' => true,
				'admin'  => $user->has_cap( 'manage_options' ),
			);
			return $this->result;
		}
		return $this->fail( $credentials[0] );
	}

	/**
	 * A password was checked and didn't match: report it, so the plugin counts one login failure.
	 *
	 * @param string $username User name as sent.
	 * @return array{editor: bool, admin: bool}
	 */
	private function fail( string $username ): array {
		if ( null !== $this->on_failure ) {
			call_user_func( $this->on_failure, $username );
		}
		return $this->result;
	}

	/**
	 * Leave without a match, after one dummy hash check so the exit takes about as long as the others.
	 *
	 * @return array{editor: bool, admin: bool}
	 */
	private function stop(): array {
		if ( function_exists( 'wp_fast_hash' ) && function_exists( 'wp_verify_fast_hash' ) ) {
			static $hash = null;
			if ( null === $hash ) {
				$hash = wp_fast_hash( 'wp-bouncer-timing' );
			}
			wp_verify_fast_hash( 'wp-bouncer-timing-probe', $hash );
		}
		return $this->result;
	}
}
