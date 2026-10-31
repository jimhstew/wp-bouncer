<?php
/**
 * Generates wp-bouncer/assets/map/world.svg and wp-bouncer/src/ThreatMap/Centroids.php (WPB-11).
 *
 * Offline tool, not shipped. Needs ext-json and ext-dom. The Natural Earth inputs are untrusted
 * downloads: they must sit in their own directory (never in the repo), and their SHA-256 must
 * match INPUT_SHA256 or the script stops.
 *
 *   mkdir /path/to/ne-input && cd /path/to/ne-input
 *   curl -fLO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_110m_admin_0_countries.geojson
 *   curl -fLO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_50m_admin_0_countries.geojson
 *   php scripts/build-world-map.php --in /path/to/ne-input
 *
 * Output is deterministic. See documentation/architecture/threat-map.md section 8.
 *
 * @package WPBouncer
 */

define( 'ABSPATH', __DIR__ . '/' ); // Stub so Countries.php loads outside WordPress.

require_once dirname( __DIR__ ) . '/wp-bouncer/src/Geo/Countries.php';
require_once __DIR__ . '/map/SvgAllowlist.php';

use WPBouncer\Geo\Countries;
use WPBouncer\Tooling\SvgAllowlist;

const NE_TAG       = 'v5.1.2';
const NE_BASE_URL  = 'https://raw.githubusercontent.com/nvkelso/natural-earth-vector/' . NE_TAG . '/geojson/';
const INPUT_SHA256 = array(
	'ne_110m_admin_0_countries.geojson' => '6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f',
	'ne_50m_admin_0_countries.geojson'  => '3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb',
);
// Natural Earth ADM0_A3 => alpha-2, for features whose ISO_A2_EH and ISO_A2 are both -99.
const CODE_OVERRIDES = array(
	'KOS' => 'XK',
);
const WIDTH_UNITS = 1000.0;
const PAD         = 4.0;
const TOLERANCE   = 0.35;

/**
 * Equal Earth projection, central meridian 0. Returns [x, y] with y pointing up.
 *
 * @param float $lon Degrees.
 * @param float $lat Degrees.
 * @return float[]
 */
function wpb_equal_earth( float $lon, float $lat ): array {
	$a1    = 1.340264;
	$a2    = -0.081106;
	$a3    = 0.000893;
	$a4    = 0.003796;
	$theta = asin( sqrt( 3 ) / 2 * sin( deg2rad( $lat ) ) );
	$t2    = $theta * $theta;
	$t6    = $t2 * $t2 * $t2;
	$x     = 2 * sqrt( 3 ) * deg2rad( $lon ) * cos( $theta ) / ( 3 * ( $a1 + 3 * $a2 * $t2 + $t6 * ( 7 * $a3 + 9 * $a4 * $t2 ) ) );
	$y     = $theta * ( $a1 + $a2 * $t2 + $t6 * ( $a3 + $a4 * $t2 ) );
	return array( $x, $y );
}

/**
 * Read a verified GeoJSON input.
 *
 * @param string $dir  Input directory.
 * @param string $file File name (a key of INPUT_SHA256).
 * @return array<string,mixed>
 */
function wpb_load_input( string $dir, string $file ): array {
	$path = rtrim( $dir, '/' ) . '/' . $file;
	if ( ! is_file( $path ) ) {
		fwrite( STDERR, "Missing input: $path\n" );
		exit( 1 );
	}
	if ( hash_file( 'sha256', $path ) !== INPUT_SHA256[ $file ] ) {
		fwrite( STDERR, "SHA-256 mismatch for $file; refusing to use it.\n" );
		exit( 1 );
	}
	$data = json_decode( (string) file_get_contents( $path ), true );
	if ( ! is_array( $data ) || ! isset( $data['features'] ) || ! is_array( $data['features'] ) ) {
		fwrite( STDERR, "Not a GeoJSON FeatureCollection: $file\n" );
		exit( 1 );
	}
	return $data;
}

/**
 * ISO alpha-2 code of a feature, or '' when unusable.
 *
 * @param array<string,mixed> $props Feature properties.
 * @return string
 */
function wpb_feature_code( array $props ): string {
	foreach ( array( 'ISO_A2_EH', 'ISO_A2' ) as $key ) {
		$v = $props[ $key ] ?? '-99';
		if ( is_string( $v ) && 1 === preg_match( '/^[A-Z]{2}$/', $v ) ) {
			return $v;
		}
	}
	return CODE_OVERRIDES[ $props['ADM0_A3'] ?? '' ] ?? '';
}

/**
 * Douglas-Peucker simplification (iterative).
 *
 * @param array<int,float[]> $pts Points.
 * @param float              $tol Tolerance in output units.
 * @return array<int,float[]>
 */
function wpb_simplify( array $pts, float $tol ): array {
	$n = count( $pts );
	if ( $n < 3 ) {
		return $pts;
	}
	$keep  = array_fill( 0, $n, false );
	$keep[0]      = true;
	$keep[ $n - 1 ] = true;
	$stack = array( array( 0, $n - 1 ) );
	while ( $stack ) {
		list( $a, $b ) = array_pop( $stack );
		$max = 0.0;
		$idx = -1;
		$dx  = $pts[ $b ][0] - $pts[ $a ][0];
		$dy  = $pts[ $b ][1] - $pts[ $a ][1];
		$len = sqrt( $dx * $dx + $dy * $dy );
		for ( $i = $a + 1; $i < $b; $i++ ) {
			$px = $pts[ $i ][0] - $pts[ $a ][0];
			$py = $pts[ $i ][1] - $pts[ $a ][1];
			$d  = $len > 0 ? abs( $dx * $py - $dy * $px ) / $len : sqrt( $px * $px + $py * $py );
			if ( $d > $max ) {
				$max = $d;
				$idx = $i;
			}
		}
		if ( $idx >= 0 && $max > $tol ) {
			$keep[ $idx ] = true;
			$stack[]      = array( $a, $idx );
			$stack[]      = array( $idx, $b );
		}
	}
	$out = array();
	foreach ( $pts as $i => $p ) {
		if ( $keep[ $i ] ) {
			$out[] = $p;
		}
	}
	return $out;
}

/**
 * Format tenths as a decimal string with one place.
 *
 * @param int $tenths Value times ten.
 * @return string
 */
function wpb_fmt( int $tenths ): string {
	return rtrim( rtrim( sprintf( '%.1F', $tenths / 10 ), '0' ), '.' ) ?: '0';
}

// ---------------------------------------------------------------------------------------------

$opts = getopt( '', array( 'in:' ) );
if ( ! isset( $opts['in'] ) || ! is_string( $opts['in'] ) ) {
	fwrite( STDERR, "Usage: php scripts/build-world-map.php --in <dir>\n" );
	exit( 2 );
}
$repo = dirname( __DIR__ );

$countries_geo = wpb_load_input( $opts['in'], 'ne_110m_admin_0_countries.geojson' );
$labels_geo    = wpb_load_input( $opts['in'], 'ne_50m_admin_0_countries.geojson' );

$list = array_keys( array_diff_key( Countries::all(), Countries::SPECIAL ) );
$list = array_values( array_diff( $list, array( 'AQ' ) ) );

// 1. Outlines: collect projected rings per country (y flipped later).
$rings   = array();
$skipped = array();
foreach ( $countries_geo['features'] as $f ) {
	$code = wpb_feature_code( $f['properties'] ?? array() );
	if ( '' === $code || ! in_array( $code, $list, true ) ) {
		$skipped[] = ( $f['properties']['NAME'] ?? '?' );
		continue;
	}
	$geom  = $f['geometry'] ?? array();
	$polys = 'Polygon' === ( $geom['type'] ?? '' ) ? array( $geom['coordinates'] ) : ( $geom['coordinates'] ?? array() );
	foreach ( $polys as $poly ) {
		foreach ( $poly as $ring ) {
			$proj = array();
			foreach ( $ring as $c ) {
				$proj[] = wpb_equal_earth( (float) $c[0], (float) $c[1] );
			}
			$rings[ $code ][] = $proj;
		}
	}
}
ksort( $rings, SORT_STRING );

// 2. Points: 50m label points, then the supplement.
// Dependencies can share a code with their country (Ashmore and Cartier Is. is AU through
// ISO_A2_EH), so the feature whose own ISO_A2 is the code wins; otherwise the first one.
$points = array(); // code => [lon, lat].
$own    = array(); // code => true when the point came from a feature whose ISO_A2 is the code.
foreach ( $labels_geo['features'] as $f ) {
	$p    = $f['properties'] ?? array();
	$code = wpb_feature_code( $p );
	if ( '' === $code || ! in_array( $code, $list, true ) || ! isset( $p['LABEL_X'], $p['LABEL_Y'] ) ) {
		continue;
	}
	$is_own = ( $p['ISO_A2'] ?? '' ) === $code;
	if ( isset( $points[ $code ] ) && ( isset( $own[ $code ] ) || ! $is_own ) ) {
		continue;
	}
	$points[ $code ] = array( (float) $p['LABEL_X'], (float) $p['LABEL_Y'] );
	if ( $is_own ) {
		$own[ $code ] = true;
	}
}
$supp = json_decode( (string) file_get_contents( __DIR__ . '/map/centroid-supplement.json' ), true );
foreach ( $supp as $code => $entry ) {
	if ( '_' === $code[0] || isset( $points[ $code ] ) ) {
		continue;
	}
	if ( ! in_array( $code, $list, true ) ) {
		fwrite( STDERR, "Supplement code not in Countries: $code\n" );
		exit( 1 );
	}
	$points[ $code ] = array( (float) $entry['lonlat'][0], (float) $entry['lonlat'][1] );
}
$missing = array_diff( $list, array_keys( $points ) );
if ( $missing ) {
	fwrite( STDERR, 'No point for: ' . implode( ' ', $missing ) . "\n" );
	exit( 1 );
}
ksort( $points, SORT_STRING );

// 3. Scale and extents. x spans the full -180..180 equator; y spans outlines and points.
$xmax  = wpb_equal_earth( 180.0, 0.0 )[0];
$scale = ( WIDTH_UNITS - 2 * PAD ) / ( 2 * $xmax );
$ymin  = INF;
$ymax  = -INF;
foreach ( $rings as $rs ) {
	foreach ( $rs as $r ) {
		foreach ( $r as $p ) {
			$ymin = min( $ymin, $p[1] );
			$ymax = max( $ymax, $p[1] );
		}
	}
}
foreach ( $points as $ll ) {
	$y    = wpb_equal_earth( $ll[0], $ll[1] )[1];
	$ymin = min( $ymin, $y );
	$ymax = max( $ymax, $y );
}
$height = (int) ceil( ( $ymax - $ymin ) * $scale + 2 * PAD );
$to_vb  = static function ( array $p ) use ( $scale, $xmax, $ymax ): array {
	return array( ( $p[0] + $xmax ) * $scale + PAD, ( $ymax - $p[1] ) * $scale + PAD );
};

// 4. SVG paths.
$paths = '';
foreach ( $rings as $code => $rs ) {
	$d = '';
	foreach ( $rs as $r ) {
		$pts = array_map( $to_vb, $r );
		$minx = min( array_column( $pts, 0 ) );
		$maxx = max( array_column( $pts, 0 ) );
		$miny = min( array_column( $pts, 1 ) );
		$maxy = max( array_column( $pts, 1 ) );
		if ( $maxx - $minx < 1 && $maxy - $miny < 1 ) {
			continue;
		}
		$pts = wpb_simplify( $pts, TOLERANCE );
		if ( count( $pts ) > 1 && $pts[0] === $pts[ count( $pts ) - 1 ] ) {
			array_pop( $pts );
		}
		if ( count( $pts ) < 3 ) {
			continue;
		}
		$ix = (int) round( $pts[0][0] * 10 );
		$iy = (int) round( $pts[0][1] * 10 );
		$d .= 'M' . wpb_fmt( $ix ) . ' ' . wpb_fmt( $iy ) . 'l';
		$seg = array();
		$px  = $ix;
		$py  = $iy;
		for ( $i = 1, $n = count( $pts ); $i < $n; $i++ ) {
			$cx = (int) round( $pts[ $i ][0] * 10 );
			$cy = (int) round( $pts[ $i ][1] * 10 );
			if ( $cx === $px && $cy === $py ) {
				continue;
			}
			$seg[] = wpb_fmt( $cx - $px ) . ' ' . wpb_fmt( $cy - $py );
			$px    = $cx;
			$py    = $cy;
		}
		if ( ! $seg ) {
			$d = substr( $d, 0, (int) strrpos( $d, 'M' ) );
			continue;
		}
		$d .= implode( ' ', $seg ) . 'z';
	}
	if ( '' !== $d ) {
		$paths .= '<path d="' . $d . '"/>' . "\n";
	}
}
$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 ' . $height . '" width="1000" height="' . $height . '" aria-hidden="true" focusable="false">' . "\n"
	. '<g fill="#dcdcde" stroke="#ffffff" stroke-width="0.5" stroke-linejoin="round">' . "\n"
	. $paths . '</g>' . "\n</svg>\n";

$problems = SvgAllowlist::check( $svg );
if ( $problems ) {
	fwrite( STDERR, "Allowlist check failed:\n  " . implode( "\n  ", $problems ) . "\n" );
	exit( 1 );
}

// 5. Centroids.php.
$rows = '';
foreach ( $points as $code => $ll ) {
	$p     = $to_vb( wpb_equal_earth( $ll[0], $ll[1] ) );
	$rows .= sprintf( "\t\t'%s' => array( %s, %s ),\n", $code, sprintf( '%.1F', $p[0] ), sprintf( '%.1F', $p[1] ) );
}
$hashes = '';
foreach ( INPUT_SHA256 as $file => $hash ) {
	$hashes .= " *   $file  $hash\n";
}
$php = "<?php\n"
	. "/**\n"
	. " * Country anchor points for the threat map. GENERATED by scripts/build-world-map.php: do not edit.\n"
	. " *\n"
	. " * Source: Natural Earth " . NE_TAG . " (public domain), 50m admin-0 label points, plus\n"
	. " * scripts/map/centroid-supplement.json. Equal Earth projection, viewBox units.\n"
	. " * Inputs (SHA-256):\n"
	. $hashes
	. " *\n"
	. " * @package WPBouncer\n"
	. " */\n\n"
	. "namespace WPBouncer\\ThreatMap;\n\n"
	. "defined( 'ABSPATH' ) || exit;\n\n"
	. "/**\n * Map anchor points, in the viewBox of assets/map/world.svg.\n */\n"
	. "final class Centroids {\n\n"
	. "\t/**\n\t * ViewBox width.\n\t */\n\tpublic const WIDTH = 1000;\n\n"
	. "\t/**\n\t * ViewBox height.\n\t */\n\tpublic const HEIGHT = $height;\n\n"
	. "\t/**\n\t * Data source.\n\t */\n\tpublic const SOURCE = 'Natural Earth " . NE_TAG . "';\n\n"
	. "\t/**\n\t * Valid codes that have no point on the map.\n\t */\n\tpublic const UNPLACED = array( 'AQ' );\n\n"
	. "\t/**\n\t * ISO alpha-2 => [ x, y ].\n\t */\n\tpublic const POINTS = array(\n"
	. $rows
	. "\t);\n\n"
	. "\t/**\n\t * Anchor point of a country.\n\t *\n\t * @param string \$code ISO alpha-2 code, upper case.\n\t * @return array{0: float, 1: float}|null [ x, y ] in viewBox units, or null when not on the map.\n\t */\n"
	. "\tpublic static function point( string \$code ): ?array {\n\t\treturn self::POINTS[ \$code ] ?? null;\n\t}\n\n"
	. "\t/**\n\t * Codes that have a point.\n\t *\n\t * @return string[]\n\t */\n"
	. "\tpublic static function codes(): array {\n\t\treturn array_keys( self::POINTS );\n\t}\n}\n";

file_put_contents( $repo . '/wp-bouncer/assets/map/world.svg', $svg );
file_put_contents( $repo . '/wp-bouncer/src/ThreatMap/Centroids.php', $php );

printf(
	"world.svg %d bytes, Centroids.php %d bytes, height %d, %d paths, %d points.\nSkipped (no code or not in Countries): %s\n",
	strlen( $svg ),
	strlen( $php ),
	$height,
	substr_count( $paths, '<path' ),
	count( $points ),
	implode( ', ', $skipped )
);
