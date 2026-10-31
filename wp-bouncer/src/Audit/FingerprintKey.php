<?php
/**
 * Keyed hashing for the settings fingerprint.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP. Derives a MAC key from a secret (the adapter passes wp_salt( 'auth' )) and never exposes
 * or stores it. Every value is a truncated HMAC-SHA256, so nothing in a record can be reversed
 * without the secret.
 */
final class FingerprintKey {

	/** Hex characters kept from each MAC (128 bits). */
	private const MAC_LENGTH = 32;

	/**
	 * Derived MAC key (raw bytes).
	 *
	 * @var string
	 */
	private string $key;

	/**
	 * Site id, bound into the seal.
	 *
	 * @var int
	 */
	private int $blog_id;

	/**
	 * Set up the key.
	 *
	 * @param string $secret  Secret, such as wp_salt( 'auth' ).
	 * @param int    $blog_id Site id.
	 */
	public function __construct( string $secret, int $blog_id ) {
		$this->key     = hash_hmac( 'sha256', 'wp_bouncer_fp_key_v1', $secret, true );
		$this->blog_id = $blog_id;
	}

	/**
	 * Short identifier of the key, so a changed secret is told from an altered record.
	 *
	 * @return string Eight hex characters.
	 */
	public function kid(): string {
		return substr( hash_hmac( 'sha256', 'wp_bouncer_fp_kid_v1', $this->key ), 0, 8 );
	}

	/**
	 * MAC of one leaf.
	 *
	 * @param string $path      Settings key path.
	 * @param string $canonical Canonical encoding of the value.
	 * @return string 32 hex characters.
	 */
	public function leaf( string $path, string $canonical ): string {
		return substr( hash_hmac( 'sha256', "wp_bouncer_fp_v1\n" . $path . "\n" . $canonical, $this->key ), 0, self::MAC_LENGTH );
	}

	/**
	 * Seal over the whole record.
	 *
	 * @param array{v: int, kid: string, logged: int, leaves: array<string, string>, pending?: array<string, mixed>} $fields Record fields (not the seal).
	 * @return string 32 hex characters.
	 */
	public function seal( array $fields ): string {
		$leaves = $fields['leaves'];
		ksort( $leaves, SORT_STRING );
		$data = "wp_bouncer_fp_seal_v1\n" . $fields['v'] . "\n" . $fields['kid'] . "\n" . $this->blog_id . "\n" . $fields['logged'] . "\n" . json_encode( $leaves ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- pure PHP class, no WordPress calls; the leaves are ASCII.
		if ( $fields['v'] >= 2 ) {
			$data .= "\n" . json_encode( $fields['pending'] ?? array() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- pure PHP class; kind and safe paths only.
		}
		return substr( hash_hmac( 'sha256', $data, $this->key ), 0, self::MAC_LENGTH );
	}
}
