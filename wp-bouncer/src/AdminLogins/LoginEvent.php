<?php
/**
 * One administrator login.
 *
 * @package WPBouncer
 */

namespace WPBouncer\AdminLogins;

defined( 'ABSPATH' ) || exit;

/**
 * Immutable value, pure PHP. The method constants are the English labels
 * stored in the Activity Log.
 */
final class LoginEvent {

	public const METHOD_INTERACTIVE     = 'interactive password';
	public const METHOD_INTERACTIVE_2FA = 'interactive password + two-factor';
	public const METHOD_APP_REST        = 'application password (REST)';
	public const METHOD_APP_XMLRPC      = 'application password (XML-RPC)';
	public const METHOD_XMLRPC_PASSWORD = 'password (XML-RPC)';
	private const REASON_MAX            = 255;
	private const LOGIN_MAX             = 60;

	/**
	 * User ID.
	 *
	 * @var int
	 */
	public readonly int $user_id;
	/**
	 * Login name, control characters removed, at most 60 characters.
	 *
	 * @var string
	 */
	public readonly string $login;
	/**
	 * Client IP.
	 *
	 * @var string
	 */
	public readonly string $ip;
	/**
	 * Network range of the IP.
	 *
	 * @var string
	 */
	public readonly string $range;
	/**
	 * Country code or ''.
	 *
	 * @var string
	 */
	public readonly string $country;
	/**
	 * One of the METHOD_* constants.
	 *
	 * @var string
	 */
	public readonly string $method;
	/**
	 * Unix time.
	 *
	 * @var int
	 */
	public readonly int $time;

	/**
	 * Set up the LoginEvent.
	 *
	 * @param int    $user_id User ID.
	 * @param string $login   Login name.
	 * @param string $ip      Client IP.
	 * @param string $range   Network range.
	 * @param string $country Country code or ''.
	 * @param string $method  One of the METHOD_* constants.
	 * @param int    $time    Unix time.
	 * @throws \InvalidArgumentException For an unknown method.
	 */
	public function __construct( int $user_id, string $login, string $ip, string $range, string $country, string $method, int $time ) {
		if ( ! in_array( $method, self::methods(), true ) ) {
			throw new \InvalidArgumentException( 'Unknown login method.' );
		}
		// Control and format characters (C0, C1, bidi overrides, zero-width) could imitate another user or hide text.
		$this->user_id = $user_id;
		$this->login   = mb_substr( self::clean_login( $login ), 0, self::LOGIN_MAX );
		$this->ip      = $ip;
		$this->range   = $range;
		$this->country = $country;
		$this->method  = $method;
		$this->time    = $time;
	}

	/**
	 * A login name that is safe to show in a log row or an email: control and format characters
	 * (C0, C1, bidi overrides, zero-width) could imitate another user or hide text.
	 *
	 * @param string $login Login name.
	 */
	public static function clean_login( string $login ): string {
		return trim( (string) preg_replace( '/[\p{Cc}\p{Cf}]+/u', ' ', $login ) );
	}

	/**
	 * Every valid method.
	 *
	 * @return string[]
	 */
	public static function methods(): array {
		return array(
			self::METHOD_INTERACTIVE,
			self::METHOD_INTERACTIVE_2FA,
			self::METHOD_APP_REST,
			self::METHOD_APP_XMLRPC,
			self::METHOD_XMLRPC_PASSWORD,
		);
	}

	/**
	 * The fixed text every row for a user starts with.
	 *
	 * @param int $user_id User ID.
	 */
	public static function reason_prefix( int $user_id ): string {
		return 'User ID ' . $user_id . ':';
	}

	/**
	 * Text for the Activity Log row.
	 *
	 * @param string $note Extra text, or ''.
	 */
	public function reason( string $note = '' ): string {
		$text = self::reason_prefix( $this->user_id ) . ' ' . $this->login . ' — ' . $this->method;
		if ( '' !== $note ) {
			$text .= ' — ' . $note;
		}
		return mb_substr( $text, 0, self::REASON_MAX );
	}

	/**
	 * Detail line for the alert email. No email address or secret.
	 *
	 * @param LoginAssessment $a Assessment.
	 */
	public function email_detail( LoginAssessment $a ): string {
		$new = array();
		if ( $a->new_range ) {
			$new[] = 'IP range ' . $this->range;
		}
		if ( $a->new_country ) {
			$new[] = 'country ' . $this->country;
		}
		return sprintf( 'User: %s (user ID %d). Method: %s. New: %s.', $this->login, $this->user_id, $this->method, implode( ', ', $new ) );
	}

	/**
	 * The shape passed to hooks.
	 *
	 * @return array{user_id: int, login: string, ip: string, range: string, country: string, method: string, time: int}
	 */
	public function to_array(): array {
		return array(
			'user_id' => $this->user_id,
			'login'   => $this->login,
			'ip'      => $this->ip,
			'range'   => $this->range,
			'country' => $this->country,
			'method'  => $this->method,
			'time'    => $this->time,
		);
	}
}
