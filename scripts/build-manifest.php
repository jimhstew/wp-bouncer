<?php
/**
 * Writes update.json (and the release notes) for a built plugin zip.
 *
 * Run by `make manifest` and by the release workflow:
 *
 *   php scripts/build-manifest.php --zip builds/wp-bouncer-1.1.0.zip
 *
 * Options:
 *   --zip FILE           Built plugin zip (required).
 *   --plugin-dir DIR     Plugin source, for the version and requirements. Default: wp-bouncer
 *   --changelog FILE     Keep-a-Changelog file. Default: documentation/CHANGELOG.md
 *   --repo OWNER/NAME    GitHub repository. Default: jimhstew/wp-bouncer
 *   --package-url URL    Override the download URL (the e2e tests use a local server).
 *   --out FILE           Where to write update.json. Default: next to the zip.
 *   --notes-out FILE     Where to write the release notes. Default: next to the zip, release-notes.md
 *
 * The plugin reads update.json from
 * https://github.com/<repo>/releases/latest/download/update.json, so it must be
 * uploaded to the release together with the zip.
 *
 * @package WPBouncer\Tools
 */

$opts = getopt( '', array( 'zip:', 'plugin-dir:', 'changelog:', 'repo:', 'package-url:', 'out:', 'notes-out:' ) );

$fail = static function ( string $message ): void {
	fwrite( STDERR, "build-manifest: {$message}\n" );
	exit( 1 );
};

$root       = dirname( __DIR__ );
$zip        = $opts['zip'] ?? '';
$plugin_dir = $opts['plugin-dir'] ?? $root . '/wp-bouncer';
$changelog  = $opts['changelog'] ?? $root . '/documentation/CHANGELOG.md';
$repo       = $opts['repo'] ?? 'jimhstew/wp-bouncer';

if ( '' === $zip || ! is_file( $zip ) ) {
	$fail( 'pass --zip with the built plugin zip' );
}
if ( ! preg_match( '#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $repo ) ) {
	$fail( "--repo must look like owner/name, got {$repo}" );
}

/**
 * Read a "Name: value" header from a plugin file or readme.txt.
 *
 * @param string $file   File.
 * @param string $header Header name.
 */
function wpb_header( string $file, string $header ): string {
	$text = (string) file_get_contents( $file );
	return preg_match( '/^[ \t\/*#@]*' . preg_quote( $header, '/' ) . ':\s*(.+)$/mi', $text, $m ) ? trim( $m[1] ) : '';
}

$main    = $plugin_dir . '/wp-bouncer.php';
$readme  = $plugin_dir . '/readme.txt';
$version = wpb_header( $main, 'Version' );
if ( ! preg_match( '/^\d+\.\d+(\.\d+)?(-[0-9A-Za-z.]+)?$/', $version ) ) {
	$fail( "no usable Version header in {$main}" );
}
if ( basename( $zip ) !== "wp-bouncer-{$version}.zip" ) {
	$fail( basename( $zip ) . " does not match the plugin version {$version}" );
}

// The section of the changelog for this version, without its heading.
$notes = '';
if ( is_file( $changelog ) ) {
	$text = (string) file_get_contents( $changelog );
	if ( preg_match( '/^## \[' . preg_quote( $version, '/' ) . '\][^\n]*\n(.*?)(?=^## \[|\z)/ms', $text, $m ) ) {
		$notes = trim( $m[1] );
	}
}
if ( '' === $notes ) {
	$fail( "no '## [{$version}]' section in {$changelog}. Add release notes before releasing." );
}

$package  = $opts['package-url'] ?? "https://github.com/{$repo}/releases/download/v{$version}/wp-bouncer-{$version}.zip";
$manifest = array(
	'version'      => $version,
	'package'      => $package,
	'sha256'       => hash_file( 'sha256', $zip ),
	'requires'     => wpb_header( $main, 'Requires at least' ),
	'requires_php' => wpb_header( $main, 'Requires PHP' ),
	'tested'       => wpb_header( $readme, 'Tested up to' ),
	'released'     => gmdate( 'Y-m-d' ),
	'changelog'    => $notes,
);

$dir       = dirname( $zip );
$out       = $opts['out'] ?? $dir . '/update.json';
$notes_out = $opts['notes-out'] ?? $dir . '/release-notes.md';

file_put_contents( $out, json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
file_put_contents(
	$notes_out,
	$notes . "\n\n---\nInstall: download **wp-bouncer-{$version}.zip** below and upload it under Plugins → Add New Plugin → Upload Plugin. "
	. "Sites already running 1.1.0 or later see this update on their Plugins screen.\n\nSHA-256 of the zip: `{$manifest['sha256']}`\n"
);

echo "Wrote {$out} ({$version}, sha256 {$manifest['sha256']})\n";
