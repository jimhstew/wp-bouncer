<?php
/**
 * What "no PHP in uploads" means, as pure functions.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * The commonest way a WordPress site gets backdoored: a weak upload form in
 * some plugin lets an attacker put a .php file in wp-content/uploads, and
 * then they run it by visiting its URL. Two defences:
 *
 * 1. Stop the web server running PHP from the uploads folder (htaccess_lines()).
 *    This works whichever plugin let the file in.
 * 2. Refuse uploads through WordPress's own upload handling that are PHP
 *    in disguise (dangerous_name(), contains_php()).
 *
 * No WordPress calls here; UploadsGuard does the file writing and hooking.
 */
final class UploadsPolicy {

	/** Extensions the web server might run as code. */
	public const SCRIPT_EXTENSIONS = array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'pgif', 'shtml', 'cgi', 'pl', 'py', 'asp', 'aspx', 'jsp' );

	/** File names that change how the server treats the folder. */
	private const SERVER_FILES = array( '.htaccess', '.user.ini', 'php.ini', 'web.config', '.htpasswd' );

	/** Marker name for the block written into uploads/.htaccess. */
	public const MARKER = 'WP Bouncer';

	/**
	 * Lines for uploads/.htaccess (Apache 2.2/2.4 and LiteSpeed).
	 *
	 * Uses access rules only. "php_flag engine off" is avoided on purpose:
	 * it causes a 500 error on servers that run PHP through PHP-FPM.
	 *
	 * @return string[]
	 */
	public static function htaccess_lines(): array {
		return array(
			'# Do not run scripts uploaded to this folder.',
			'<FilesMatch "\.(?i:php[0-9]?|phtml|pht|phar|phps|pgif|shtml|cgi|pl|py|asp|aspx|jsp)$">',
			'	<IfModule mod_authz_core.c>',
			'		Require all denied',
			'	</IfModule>',
			'	<IfModule !mod_authz_core.c>',
			'		Order allow,deny',
			'		Deny from all',
			'	</IfModule>',
			'</FilesMatch>',
		);
	}

	/** The same protection for nginx, which ignores .htaccess. */
	public static function nginx_snippet(): string {
		return "location ~* ^/wp-content/uploads/.*\\.(php[0-9]?|phtml|pht|phar|phps|pgif|shtml|cgi|pl|py|asp|aspx|jsp)$ {\n    deny all;\n}";
	}

	/**
	 * Why a file name is dangerous, or null if it's fine.
	 *
	 * Catches double extensions such as "photo.php.jpg" as well as plain
	 * ".php", since some server setups run any file with ".php" anywhere in
	 * its name.
	 *
	 * @param string $name Uploaded file name.
	 */
	public static function dangerous_name( string $name ): ?string {
		$name = strtolower( trim( basename( str_replace( '\\', '/', $name ) ) ) );
		if ( in_array( $name, self::SERVER_FILES, true ) ) {
			return 'server configuration file (' . $name . ')';
		}
		$parts = explode( '.', $name );
		array_shift( $parts ); // The part before the first dot isn't an extension.
		foreach ( $parts as $ext ) {
			if ( in_array( $ext, self::SCRIPT_EXTENSIONS, true ) ) {
				return 'script extension .' . $ext;
			}
		}
		return null;
	}

	/**
	 * Does the text hold "<?php", or a "<?=" that opens PHP code?
	 *
	 * A bare "<?=" occurs by chance in compressed data (photos, video), so
	 * what counts depends on the kind of file:
	 *
	 * - Binary media and archives ($binary true): the "<?=" must be followed,
	 *   within 256 bytes, by a run of printable ASCII (random bytes almost never
	 *   make one) that holds a terminator ("?>" or ";") and a PHP-looking token
	 *   ("$", "(" or a backtick). Expected false positives in random data: about
	 *   one "<?=" per 16 MB, and about 1 in 10,000 of those passes the run test,
	 *   so a 50 MB video has roughly a 3-in-10,000 chance of a false match.
	 * - Everything else: "<?=" followed by optional whitespace and anything but ">".
	 *
	 * @param string $data   Bytes to check.
	 * @param bool   $binary True for a media or archive file whose extension and signature agree (see is_binary_media()).
	 */
	public static function has_php_tag( string $data, bool $binary = false ): bool {
		if ( false !== stripos( $data, '<?php' ) ) {
			return true;
		}
		$pos = strpos( $data, '<?=' );
		if ( false === $pos ) {
			return false;
		}
		if ( ! $binary ) {
			return 1 === preg_match( '/<\?=\s*[^>\s]/', $data );
		}
		while ( false !== $pos ) {
			$after = substr( $data, $pos + 3, 256 );
			if ( 1 === preg_match( '/^[\x09\x0a\x0d\x20-\x7e]+/', $after, $m ) && 1 === preg_match( '/;|\?>/', $m[0] ) && 1 === preg_match( '/[$(`]/', $m[0] ) ) {
				return true;
			}
			$pos = strpos( $data, '<?=', $pos + 3 );
		}
		return false;
	}

	/**
	 * Extensions of media and archive files whose content is compressed or binary, with the
	 * signatures their first bytes must start with. "ftyp" means that word at offset 4.
	 */
	private const MEDIA_SIGNATURES = array(
		'jpg'  => array( "\xff\xd8\xff" ),
		'jpeg' => array( "\xff\xd8\xff" ),
		'jpe'  => array( "\xff\xd8\xff" ),
		'png'  => array( "\x89PNG" ),
		'gif'  => array( 'GIF8' ),
		'bmp'  => array( 'BM' ),
		'tif'  => array( "II*\x00", "MM\x00*" ),
		'tiff' => array( "II*\x00", "MM\x00*" ),
		'webp' => array( 'RIFF' ),
		'avi'  => array( 'RIFF' ),
		'wav'  => array( 'RIFF' ),
		'mp4'  => array( 'ftyp' ),
		'm4v'  => array( 'ftyp' ),
		'm4a'  => array( 'ftyp' ),
		'mov'  => array( 'ftyp' ),
		'3gp'  => array( 'ftyp' ),
		'heic' => array( 'ftyp' ),
		'heif' => array( 'ftyp' ),
		'avif' => array( 'ftyp' ),
		'mp3'  => array( 'ID3', "\xff\xfb", "\xff\xf3", "\xff\xf2" ),
		'ogg'  => array( 'OggS' ),
		'oga'  => array( 'OggS' ),
		'ogv'  => array( 'OggS' ),
		'webm' => array( "\x1a\x45\xdf\xa3" ),
		'mkv'  => array( "\x1a\x45\xdf\xa3" ),
		'flac' => array( 'fLaC' ),
		'zip'  => array( "PK\x03\x04", "PK\x05\x06" ),
		'docx' => array( "PK\x03\x04" ),
		'xlsx' => array( "PK\x03\x04" ),
		'pptx' => array( "PK\x03\x04" ),
		'odt'  => array( "PK\x03\x04" ),
		'gz'   => array( "\x1f\x8b" ),
		'rar'  => array( 'Rar!' ),
		'7z'   => array( "7z\xbc\xaf" ),
		'pdf'  => array( '%PDF' ),
	);

	/**
	 * May this file be scanned with the relaxed "<?=" rule used for compressed media?
	 *
	 * Magic bytes are chosen by the sender, so they are not enough. The file name must
	 * have no extension a server could run (see dangerous_name()), its last extension
	 * must be a known media or archive type, and the first bytes must be that type's
	 * signature. Anything else, including an unknown extension or no name, is scanned strictly.
	 *
	 * @param string $head     First bytes of the file (at least 12 are used).
	 * @param string $filename Name the file will be stored under.
	 */
	public static function is_binary_media( string $head, string $filename ): bool {
		if ( '' === $filename || null !== self::dangerous_name( $filename ) ) {
			return false;
		}
		$ext = strtolower( (string) pathinfo( str_replace( '\\', '/', $filename ), PATHINFO_EXTENSION ) );
		if ( ! isset( self::MEDIA_SIGNATURES[ $ext ] ) ) {
			return false;
		}
		foreach ( self::MEDIA_SIGNATURES[ $ext ] as $magic ) {
			$at = 'ftyp' === $magic ? 4 : 0;
			if ( substr( $head, $at, strlen( $magic ) ) === $magic ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Does the file contain a PHP opening tag ("<?php" in any case, or "<?=")?
	 *
	 * Reads in chunks with an overlap so a tag split across two chunks is
	 * still found. Files larger than $max_bytes are only checked up to that point.
	 *
	 * @param string $path      File to check.
	 * @param int    $max_bytes How much to read.
	 * @param string $filename  Name the file will be stored under; decides how strict the "<?=" rule is (see is_binary_media()).
	 */
	public static function contains_php( string $path, int $max_bytes = 52428800, string $filename = '' ): bool {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions -- a failed open is handled by the false check below; plugin-owned local file, WP_Filesystem cannot stream.
		if ( false === $handle ) {
			return false;
		}
		$tail   = '';
		$read   = 0;
		$found  = false;
		$binary = false;
		while ( ! feof( $handle ) && $read < $max_bytes ) {
			$chunk = fread( $handle, max( 1, min( 1048576, $max_bytes - $read ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads only the first bytes of a local file with a size cap; WP_Filesystem has no partial read.
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			if ( 0 === $read ) {
				$binary = self::is_binary_media( $chunk, $filename );
			}
			$read += strlen( $chunk );
			$scan  = $tail . $chunk;
			if ( self::has_php_tag( $scan, $binary ) ) {
				$found = true;
				break;
			}
			$tail = substr( $chunk, -300 ); // Longer than a tag plus the 256 bytes of context checked after "<?=".
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads only the first bytes of a local file with a size cap; WP_Filesystem has no partial read.
		return $found;
	}

	/**
	 * Interpret the result of requesting a plain text file placed in uploads,
	 * with the .htaccess block in place.
	 *
	 * @param int    $status   HTTP status (0 when the request failed).
	 * @param string $body     Response body.
	 * @param string $expected The file's contents.
	 * @return string 'ok' (the file loaded), 'broken' (a 500 or 503: the server
	 *                rejects the block) or 'unknown'.
	 */
	public static function interpret_serving( int $status, string $body, string $expected ): string {
		if ( 200 === $status && false !== strpos( $body, $expected ) ) {
			return 'ok';
		}
		// Only the server's own errors count: 502 and 504 come from a proxy or overload, not from the block.
		return 500 === $status || 503 === $status ? 'broken' : 'unknown';
	}

	/**
	 * Interpret the result of requesting a test script placed in uploads.
	 *
	 * @param int    $status HTTP status (0 when the request failed).
	 * @param string $body   Response body.
	 * @param string $marker Text the script prints only if PHP ran it.
	 * Only a refusal (401/403) or the file coming back as plain text counts as
	 * protected. Anything else (a 404, a 500, a redirect) proves nothing.
	 *
	 * @return string 'protected', 'unprotected' or 'unknown'.
	 */
	public static function interpret_probe( int $status, string $body, string $marker ): string {
		if ( 200 === $status ) {
			if ( false !== strpos( $body, $marker ) ) {
				return 'unprotected';
			}
			// The script's own source: the server handed it out as text instead of running it.
			return self::has_php_tag( $body ) ? 'protected' : 'unknown';
		}
		if ( 401 === $status || 403 === $status ) {
			return 'protected';
		}
		return 'unknown';
	}
}
