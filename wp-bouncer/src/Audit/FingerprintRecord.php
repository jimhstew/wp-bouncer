<?php
/**
 * A sealed settings fingerprint.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP, immutable. Holds one MAC per settings leaf and a seal over everything.
 */
final class FingerprintRecord {

	/** Record format version. 2 adds the "pending" field and the admin email leaves. */
	public const VERSION = 2;

	/** Oldest format still read (its seal has no "pending"; it has no email leaves). */
	private const MIN_VERSION = 1;

	/** Kinds a pending drift can have. */
	private const PENDING_KINDS = array( 'changed', 'fingerprint_missing', 'fingerprint_altered', 'keys_changed' );

	/** Longest stored text read back. */
	private const MAX_BYTES = 65536;

	/**
	 * Key id.
	 *
	 * @var string
	 */
	public readonly string $kid;

	/**
	 * Time of the last drift row (0 = never).
	 *
	 * @var int
	 */
	public readonly int $logged;

	/**
	 * Leaf MACs by path.
	 *
	 * @var array<string, string>
	 */
	public readonly array $leaves;

	/**
	 * Seal.
	 *
	 * @var string
	 */
	public readonly string $seal;

	/**
	 * Format version this record was written in.
	 *
	 * @var int
	 */
	public readonly int $version;

	/**
	 * A drift found whose Activity Log row could not be written: kind and safe paths (empty = none).
	 *
	 * @var array<string, mixed>
	 */
	public readonly array $pending;

	/**
	 * Set up the record.
	 *
	 * @param string                $kid    Key id.
	 * @param int                   $logged Time of the last drift row.
	 * @param array<string, string> $leaves Leaf MACs.
	 * @param string                $seal   Seal.
	 * @param array<string, mixed>  $pending Pending drift (kind and paths), or empty.
	 * @param int                   $version Format version.
	 */
	public function __construct( string $kid, int $logged, array $leaves, string $seal, array $pending = array(), int $version = self::VERSION ) {
		$this->pending = $pending;
		$this->version = $version;
		$this->kid     = $kid;
		$this->logged  = $logged;
		$this->leaves  = $leaves;
		$this->seal    = $seal;
	}

	/**
	 * Build and seal a record.
	 *
	 * @param FingerprintKey        $key    Key.
	 * @param int                   $logged Time of the last drift row.
	 * @param array<string, string> $leaves Leaf MACs.
	 * @param array<string, mixed>  $pending Pending drift (kind and paths), or empty.
	 * @param int                   $version Format version to write (only a kept format 1 record passes 1).
	 */
	public static function sealed( FingerprintKey $key, int $logged, array $leaves, array $pending = array(), int $version = self::VERSION ): self {
		ksort( $leaves, SORT_STRING );
		$kid = $key->kid();
		if ( $version < 2 ) {
			$pending = array();
		}
		return new self(
			$kid,
			$logged,
			$leaves,
			$key->seal(
				array(
					'v'       => $version,
					'kid'     => $kid,
					'logged'  => $logged,
					'leaves'  => $leaves,
					'pending' => $pending,
				)
			),
			$pending,
			$version
		);
	}

	/**
	 * Same leaves, new "logged" time, sealed again.
	 *
	 * @param FingerprintKey $key    Key.
	 * @param int            $logged Time of the last drift row.
	 */
	public function with_logged( FingerprintKey $key, int $logged ): self {
		return self::sealed( $key, $logged, $this->leaves, $this->pending, $this->version );
	}

	/**
	 * Same leaves and time, with a pending drift (or none), sealed again.
	 *
	 * @param FingerprintKey       $key     Key.
	 * @param array<string, mixed> $pending Kind and safe paths, or empty.
	 */
	public function with_pending( FingerprintKey $key, array $pending ): self {
		return self::sealed( $key, $this->logged, $this->leaves, $pending, $this->version );
	}

	/**
	 * Array form.
	 *
	 * @return array<string, mixed>
	 */
	public function to_array(): array {
		$out = array(
			'v'      => $this->version,
			'kid'    => $this->kid,
			'logged' => $this->logged,
			'leaves' => $this->leaves,
		);
		if ( $this->version >= 2 ) {
			$out['pending'] = $this->pending;
		}
		$out['seal'] = $this->seal;
		return $out;
	}

	/**
	 * JSON text to store (ASCII only).
	 */
	public function to_json(): string {
		return (string) json_encode( $this->to_array() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- pure PHP class, no WordPress calls; the content is ASCII.
	}

	/**
	 * Read a stored record.
	 *
	 * @param mixed $stored What the options API returned: a JSON string, or anything else (false when missing).
	 * @return self|null Null when missing, not a JSON string, the wrong version or malformed.
	 */
	public static function from_stored( mixed $stored ): ?self {
		if ( ! is_string( $stored ) || '' === $stored || strlen( $stored ) > self::MAX_BYTES ) {
			return null;
		}
		$data = json_decode( $stored, true, 5 );
		$ver  = is_array( $data ) ? ( $data['v'] ?? null ) : null;
		if ( ! is_int( $ver ) || $ver < self::MIN_VERSION || $ver > self::VERSION ) {
			return null;
		}
		$kid    = $data['kid'] ?? null;
		$logged = $data['logged'] ?? null;
		$leaves = $data['leaves'] ?? null;
		$seal   = $data['seal'] ?? null;
		if ( ! is_string( $kid ) || 1 !== preg_match( '/^[0-9a-f]{8}$/', $kid ) || ! is_int( $logged ) || $logged < 0 || ! is_array( $leaves ) || ! is_string( $seal ) || 1 !== preg_match( '/^[0-9a-f]{32}$/', $seal ) ) {
			return null;
		}
		foreach ( $leaves as $path => $mac ) {
			if ( ! is_string( $mac ) || 1 !== preg_match( '/^[0-9a-f]{32}$/', $mac ) || 1 !== preg_match( '/^[A-Za-z0-9_.-]{1,64}$/', (string) $path ) ) {
				return null;
			}
		}
		$pending = array();
		if ( $ver >= 2 ) {
			$pending = self::read_pending( $data['pending'] ?? null );
			if ( null === $pending ) {
				return null;
			}
		}
		// Each path and MAC was checked above.
		return new self( $kid, $logged, $leaves, $seal, $pending, $ver );
	}

	/**
	 * Check the pending field of a stored record.
	 *
	 * @param mixed $pending Decoded value.
	 * @return array<string, mixed>|null Canonical pending, or null when malformed.
	 */
	private static function read_pending( mixed $pending ): ?array {
		if ( array() === $pending ) {
			return array();
		}
		if ( ! is_array( $pending ) || 2 !== count( $pending ) || ! isset( $pending['kind'], $pending['paths'] ) || ! is_string( $pending['kind'] ) || ! in_array( $pending['kind'], self::PENDING_KINDS, true ) || ! is_array( $pending['paths'] ) || count( $pending['paths'] ) > 25 ) {
			return null;
		}
		$paths = array();
		foreach ( $pending['paths'] as $path ) {
			if ( ! is_string( $path ) || 1 !== preg_match( '/^[A-Za-z0-9_.+ -]{1,64}$/', $path ) ) {
				return null;
			}
			$paths[] = $path;
		}
		return array(
			'kind'  => $pending['kind'],
			'paths' => $paths,
		);
	}

	/**
	 * Is the seal right for this key?
	 *
	 * @param FingerprintKey $key Key.
	 */
	public function seal_valid( FingerprintKey $key ): bool {
		$expect = $key->seal(
			array(
				'v'       => $this->version,
				'kid'     => $this->kid,
				'logged'  => $this->logged,
				'leaves'  => $this->leaves,
				'pending' => $this->pending,
			)
		);
		return hash_equals( $expect, $this->seal );
	}

	/**
	 * Do both records describe the same leaves (ignoring "logged" and the seal)?
	 *
	 * @param self $other Other record.
	 */
	public function equals( self $other ): bool {
		$a = $this->leaves;
		$b = $other->leaves;
		ksort( $a, SORT_STRING );
		ksort( $b, SORT_STRING );
		return $a === $b;
	}
}
