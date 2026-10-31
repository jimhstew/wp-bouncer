<?php
/**
 * Allowlist checker for the generated base map (not shipped).
 *
 * Pure PHP (ext-dom only). Used by scripts/build-world-map.php before writing and by the
 * PHPUnit test on the committed file.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Tooling;

/**
 * Accepts only the exact SVG shape the generator emits.
 */
final class SvgAllowlist {

	private const ELEMENTS = array(
		'svg'  => array( 'xmlns', 'viewBox', 'width', 'height', 'aria-hidden', 'focusable' ),
		'g'    => array( 'fill', 'stroke', 'stroke-width', 'stroke-linejoin' ),
		'path' => array( 'd' ),
	);

	private const VALUES = array(
		'xmlns'           => '#^http://www\.w3\.org/2000/svg$#',
		'viewBox'         => '#^0 0 [0-9.]+ [0-9.]+$#',
		'width'           => '#^[0-9.]+$#',
		'height'          => '#^[0-9.]+$#',
		'aria-hidden'     => '#^true$#',
		'focusable'       => '#^false$#',
		'fill'            => '#^\#[0-9a-f]{6}$#',
		'stroke'          => '#^\#[0-9a-f]{6}$#',
		'stroke-width'    => '#^[0-9.]+$#',
		'stroke-linejoin' => '#^round$#',
		'd'               => '#^[MmLlHhVvZz0-9 .,\-]+$#',
	);

	/**
	 * Check an SVG document.
	 *
	 * @param string $svg SVG source.
	 * @return string[] Problems found; empty when the file passes.
	 */
	public static function check( string $svg ): array {
		$errors = array();
		if ( false !== stripos( $svg, '<!DOCTYPE' ) || false !== stripos( $svg, '<!ENTITY' ) ) {
			return array( 'DOCTYPE or ENTITY declaration' );
		}
		if ( false !== stripos( $svg, 'data:' ) ) {
			$errors[] = 'data: URL';
		}
		$prev = libxml_use_internal_errors( true );
		$doc  = new \DOMDocument();
		$ok   = $doc->loadXML( $svg, LIBXML_NONET );
		libxml_clear_errors();
		libxml_use_internal_errors( $prev );
		if ( ! $ok || null === $doc->documentElement ) {
			return array_merge( $errors, array( 'not well-formed XML' ) );
		}
		if ( null !== $doc->doctype ) {
			return array_merge( $errors, array( 'DOCTYPE present' ) );
		}
		if ( 'svg' !== $doc->documentElement->nodeName ) {
			$errors[] = 'root is not svg';
		}
		self::walk( $doc, $errors );
		return array_values( array_unique( $errors ) );
	}

	/**
	 * Recursively check nodes.
	 *
	 * @param \DOMNode $node   Node.
	 * @param string[] $errors Collected problems.
	 */
	private static function walk( \DOMNode $node, array &$errors ): void {
		foreach ( $node->childNodes as $child ) {
			if ( XML_TEXT_NODE === $child->nodeType && '' === trim( (string) $child->nodeValue ) ) {
				continue;
			}
			if ( XML_ELEMENT_NODE !== $child->nodeType ) {
				$errors[] = 'forbidden node type ' . $child->nodeType;
				continue;
			}
			$name = $child->nodeName;
			if ( ! isset( self::ELEMENTS[ $name ] ) ) {
				$errors[] = 'forbidden element ' . $name;
				continue;
			}
			/** @var \DOMElement $child */
			foreach ( $child->attributes as $attr ) {
				$an = $attr->nodeName;
				if ( ! in_array( $an, self::ELEMENTS[ $name ], true ) ) {
					$errors[] = "forbidden attribute {$an} on {$name}";
				} elseif ( 1 !== preg_match( self::VALUES[ $an ], $attr->nodeValue ) ) {
					$errors[] = "bad value for {$an}";
				}
			}
			self::walk( $child, $errors );
		}
	}
}
