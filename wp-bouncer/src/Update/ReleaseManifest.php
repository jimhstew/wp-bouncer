<?php
/**
 * The update.json file published with each GitHub release.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Update;

defined( 'ABSPATH' ) || exit;

/**
 * Describes the latest release. Built by scripts/build-manifest.php and
 * attached to every GitHub release, for example:
 *
 *   {
 *     "version": "1.1.0",
 *     "package": "https://github.com/jimhstew/wp-bouncer/releases/download/v1.1.0/wp-bouncer-1.1.0.zip",
 *     "sha256": "9f2c…",
 *     "requires": "7.0",
 *     "requires_php": "8.3",
 *     "tested": "7.1",
 *     "released": "2026-10-20",
 *     "changelog": "### Added\n- Automatic updates from GitHub releases."
 *   }
 *
 * Anything that doesn't validate makes from_json() return null, and the
 * plugin then simply reports no update. Pure PHP, no WordPress calls.
 */
final class ReleaseManifest {

	/**
	 * Version number.
	 *
	 * @var string
	 */
	private string $version;
	/**
	 * Download URL of the zip.
	 *
	 * @var string
	 */
	private string $package;
	/**
	 * SHA-256 checksum of the zip.
	 *
	 * @var string
	 */
	private string $sha256;
	/**
	 * Minimum WordPress version.
	 *
	 * @var string
	 */
	private string $requires;
	/**
	 * Minimum PHP version.
	 *
	 * @var string
	 */
	private string $requires_php;
	/**
	 * WordPress version tested up to.
	 *
	 * @var string
	 */
	private string $tested;
	/**
	 * Release date.
	 *
	 * @var string
	 */
	private string $released;
	/**
	 * Changelog text.
	 *
	 * @var string
	 */
	private string $changelog;

	/**
	 * Set up the ReleaseManifest.
	 *
	 * @param array<string, string> $f Validated fields.
	 */
	private function __construct( array $f ) {
		$this->version      = $f['version'];
		$this->package      = $f['package'];
		$this->sha256       = $f['sha256'];
		$this->requires     = $f['requires'];
		$this->requires_php = $f['requires_php'];
		$this->tested       = $f['tested'];
		$this->released     = $f['released'];
		$this->changelog    = $f['changelog'];
	}

	/**
	 * Parse and validate a manifest.
	 *
	 * @param string $json           Raw update.json.
	 * @param string $package_prefix The package URL must be this prefix followed by
	 *                               v<version>/wp-bouncer-<version>.zip, e.g. a prefix of
	 *                               https://github.com/<owner>/<repo>/releases/download/.
	 */
	public static function from_json( string $json, string $package_prefix ): ?self {
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) ) {
			return null;
		}
		$text = static function ( string $key ) use ( $data ): string {
			return isset( $data[ $key ] ) && is_scalar( $data[ $key ] ) ? trim( (string) $data[ $key ] ) : '';
		};

		$f = array(
			'version'      => $text( 'version' ),
			'package'      => $text( 'package' ),
			'sha256'       => strtolower( $text( 'sha256' ) ),
			'requires'     => $text( 'requires' ),
			'requires_php' => $text( 'requires_php' ),
			'tested'       => $text( 'tested' ),
			'released'     => $text( 'released' ),
			'changelog'    => isset( $data['changelog'] ) && is_string( $data['changelog'] ) ? $data['changelog'] : '',
		);

		if ( ! self::is_version( $f['version'] ) ) {
			return null;
		}
		// The package must be exactly the URL the release process produces. Exact
		// equality removes dot-segment, %2e and query-string tricks without parsing.
		if ( '' === $package_prefix || false !== strpos( $package_prefix, '..' ) || self::expected_package( $package_prefix, $f['version'] ) !== $f['package'] ) {
			return null;
		}
		if ( ! preg_match( '/^[0-9a-f]{64}$/', $f['sha256'] ) ) {
			return null;
		}
		foreach ( array( 'requires', 'requires_php', 'tested' ) as $key ) {
			if ( '' !== $f[ $key ] && ! preg_match( '/^\d+(\.\d+){0,2}$/', $f[ $key ] ) ) {
				$f[ $key ] = '';
			}
		}
		if ( '' !== $f['released'] && ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $f['released'] ) ) {
			$f['released'] = '';
		}
		if ( strlen( $f['changelog'] ) > 20000 ) {
			$f['changelog'] = substr( $f['changelog'], 0, 20000 );
		}
		return new self( $f );
	}

	/**
	 * The one package URL a release of $version may use.
	 *
	 * @param string $package_prefix Download prefix, ending in a slash.
	 * @param string $version        Release version from the manifest.
	 */
	public static function expected_package( string $package_prefix, string $version ): string {
		return $package_prefix . 'v' . $version . '/wp-bouncer-' . $version . '.zip';
	}

	/**
	 * Whether a string is a plain dotted version.
	 *
	 * Accepts values such as 1.2.3, optionally with a -beta.1 style suffix.
	 *
	 * @param string $v Candidate version.
	 * @return bool
	 */
	public static function is_version( string $v ): bool {
		return (bool) preg_match( '/^\d+\.\d+(\.\d+)?(-[0-9A-Za-z.]+)?$/', $v );
	}

	/**
	 * Is this release newer than $installed?
	 *
	 * @param string $installed Installed version.
	 * @return bool
	 */
	public function is_newer_than( string $installed ): bool {
		return version_compare( $this->version, $installed, '>' );
	}

	/** Release version. */
	public function version(): string {
		return $this->version;
	}

	/** Download URL of the plugin zip. */
	public function package(): string {
		return $this->package;
	}

	/** Expected SHA-256 of the zip, lowercase hex. */
	public function sha256(): string {
		return $this->sha256;
	}

	/**
	 * Whether a site on these versions can run this release.
	 *
	 * Fails closed: a manifest with a missing or malformed `requires` or
	 * `requires_php` is treated as incompatible, because scripts/build-manifest.php
	 * always writes both from the plugin header. Pre-release suffixes on the
	 * site's versions ("7.0-RC1", "8.3.0-dev") are ignored, so a release
	 * candidate of the minimum counts as meeting it.
	 *
	 * @param string $wp_version  The site's WordPress version.
	 * @param string $php_version The site's PHP version.
	 */
	public function is_compatible( string $wp_version, string $php_version ): bool {
		if ( '' === $this->requires || '' === $this->requires_php ) {
			return false;
		}
		$wp  = preg_replace( '/-.*$/', '', $wp_version );
		$php = preg_replace( '/-.*$/', '', $php_version );
		return version_compare( (string) $wp, $this->requires, '>=' ) && version_compare( (string) $php, $this->requires_php, '>=' );
	}

	/** Minimum WordPress version, or ''. */
	public function requires(): string {
		return $this->requires;
	}

	/** Minimum PHP version, or ''. */
	public function requires_php(): string {
		return $this->requires_php;
	}

	/** WordPress version tested up to, or ''. */
	public function tested(): string {
		return $this->tested;
	}

	/** Release date (YYYY-MM-DD), or ''. */
	public function released(): string {
		return $this->released;
	}

	/** Changelog for this release as Markdown. */
	public function changelog(): string {
		return $this->changelog;
	}

	/**
	 * The changelog as safe HTML for the "View details" window.
	 *
	 * Handles the subset of Markdown the changelog uses: ## / ### headings,
	 * "- " bullets, `code`, **bold** and paragraphs. Everything is escaped
	 * first, so the manifest can't inject markup.
	 */
	public function changelog_html(): string {
		$html    = '';
		$in_list = false;
		$lines   = preg_split( '/\r?\n/', $this->changelog );
		foreach ( false !== $lines ? $lines : array() as $line ) {
			$line = rtrim( $line );
			if ( preg_match( '/^\s*[-*] (.+)$/', $line, $m ) ) {
				if ( ! $in_list ) {
					$html   .= '<ul>';
					$in_list = true;
				}
				$html .= '<li>' . self::inline( $m[1] ) . '</li>';
				continue;
			}
			if ( $in_list && preg_match( '/^\s{2,}\S/', $line ) ) {
				// Continuation of the previous bullet.
				$html = substr( $html, 0, -5 ) . ' ' . self::inline( trim( $line ) ) . '</li>';
				continue;
			}
			if ( $in_list ) {
				$html   .= '</ul>';
				$in_list = false;
			}
			if ( '' === trim( $line ) ) {
				continue;
			}
			if ( preg_match( '/^#{1,6}\s+(.+)$/', $line, $m ) ) {
				$html .= '<h4>' . self::inline( $m[1] ) . '</h4>';
			} else {
				$html .= '<p>' . self::inline( $line ) . '</p>';
			}
		}
		if ( $in_list ) {
			$html .= '</ul>';
		}
		return $html;
	}

	/**
	 * Escape a line, then apply `code` and **bold**.
	 *
	 * @param string $text Markdown text.
	 */
	private static function inline( string $text ): string {
		$text = htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
		$text = (string) preg_replace( '/`([^`]+)`/', '<code>$1</code>', $text );
		return (string) preg_replace( '/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $text );
	}
}
