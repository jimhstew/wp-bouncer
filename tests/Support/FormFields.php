<?php
/**
 * What a browser would submit for a form in an HTML page.
 *
 * Used by the integration tests and the e2e suite to prove that "render the Rules tab, submit it
 * unchanged, save" changes no setting. It follows the HTML rules for successful controls:
 * disabled controls and unchecked checkboxes and radios are left out, textareas and selects are
 * included, controls are taken in document order, and a control belongs to the form named by its
 * form="" attribute when it has one, otherwise to its closest ancestor form. Whether an element
 * is hidden (inside a closed <details>, for example) makes no difference: browsers submit it.
 *
 * Command line (used by tests/e2e/run.sh):
 *
 *   php tests/Support/FormFields.php <html-file> <form-selector> [field-name-to-leave-out ...]
 *
 * prints the fields as an application/x-www-form-urlencoded body.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

/** Extract the successful controls of one form. */
final class FormFields {

	/**
	 * The controls of a form, in order.
	 *
	 * @param string $html     Page HTML.
	 * @param string $selector "form.some-class" or "#form-id".
	 * @param bool   $all      True to list every enabled named control, checked or not (for completeness checks).
	 * @return list<array{0: string, 1: string}> [ name, value ] pairs.
	 */
	public static function pairs( string $html, string $selector, bool $all = false ): array {
		$doc = new \DOMDocument();
		$was = libxml_use_internal_errors( true );
		$doc->loadHTML( '<?xml encoding="utf-8" ?>' . $html );
		libxml_clear_errors();
		libxml_use_internal_errors( $was );
		$xpath = new \DOMXPath( $doc );

		if ( 0 === strpos( $selector, '#' ) ) {
			$query = sprintf( '//form[@id=%s]', self::literal( substr( $selector, 1 ) ) );
		} elseif ( preg_match( '/^form\.([A-Za-z0-9_-]+)$/', $selector, $m ) ) {
			$query = sprintf( "//form[contains(concat(' ', normalize-space(@class), ' '), %s)]", self::literal( ' ' . $m[1] . ' ' ) );
		} else {
			throw new \InvalidArgumentException( 'Unsupported selector: ' . $selector );
		}
		$forms = $xpath->query( $query );
		if ( ! $forms || 1 !== $forms->length ) {
			throw new \RuntimeException( 'Expected exactly one form for ' . $selector . ', found ' . ( $forms ? $forms->length : 0 ) );
		}
		/** @var \DOMElement $form */
		$form    = $forms->item( 0 );
		$form_id = $form->getAttribute( 'id' );

		$out = array();
		foreach ( $xpath->query( '//input | //textarea | //select' ) ?: array() as $control ) {
			/** @var \DOMElement $control */
			if ( $control->hasAttribute( 'form' ) ) {
				if ( '' === $form_id || $control->getAttribute( 'form' ) !== $form_id ) {
					continue;
				}
			} elseif ( ! self::inside( $control, $form ) ) {
				continue;
			}
			if ( $control->hasAttribute( 'disabled' ) || '' === $control->getAttribute( 'name' ) ) {
				continue;
			}
			$name = $control->getAttribute( 'name' );

			if ( 'textarea' === $control->nodeName ) {
				$text = $control->textContent;
				// The HTML parser drops one newline right after <textarea>.
				$out[] = array( $name, 0 === strpos( $text, "\n" ) ? substr( $text, 1 ) : $text );
				continue;
			}
			if ( 'select' === $control->nodeName ) {
				foreach ( self::selected_options( $xpath, $control ) as $value ) {
					$out[] = array( $name, $value );
				}
				continue;
			}
			$type = strtolower( $control->getAttribute( 'type' ) );
			if ( in_array( $type, array( 'submit', 'button', 'reset', 'image', 'file' ), true ) ) {
				continue;
			}
			if ( in_array( $type, array( 'checkbox', 'radio' ), true ) ) {
				if ( ! $all && ! $control->hasAttribute( 'checked' ) ) {
					continue;
				}
				$out[] = array( $name, $control->hasAttribute( 'value' ) ? $control->getAttribute( 'value' ) : 'on' );
				continue;
			}
			$out[] = array( $name, $control->getAttribute( 'value' ) );
		}
		return $out;
	}

	/**
	 * The fields as PHP would see them in $_POST (not slashed).
	 *
	 * @param string $html     Page HTML.
	 * @param string $selector Form selector.
	 * @return array<string, mixed>
	 */
	public static function of( string $html, string $selector ): array {
		parse_str( self::encode( self::pairs( $html, $selector ) ), $post );
		return $post;
	}

	/**
	 * Names of every enabled named control, checked or not, for completeness checks.
	 *
	 * @param string $html     Page HTML.
	 * @param string $selector Form selector.
	 * @return string[]
	 */
	public static function names( string $html, string $selector ): array {
		return array_column( self::pairs( $html, $selector, true ), 0 );
	}

	/**
	 * Fields as a urlencoded body.
	 *
	 * @param list<array{0: string, 1: string}> $pairs Pairs.
	 */
	public static function encode( array $pairs ): string {
		$parts = array();
		foreach ( $pairs as $pair ) {
			$parts[] = rawurlencode( $pair[0] ) . '=' . rawurlencode( $pair[1] );
		}
		return implode( '&', $parts );
	}

	/**
	 * Is the node inside the ancestor?
	 *
	 * @param \DOMNode $node     Node.
	 * @param \DOMNode $ancestor Ancestor.
	 */
	private static function inside( \DOMNode $node, \DOMNode $ancestor ): bool {
		for ( $p = $node->parentNode; $p; $p = $p->parentNode ) {
			if ( $p->isSameNode( $ancestor ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Values of the selected options of a select (the first option if none is marked).
	 *
	 * @param \DOMXPath   $xpath   XPath.
	 * @param \DOMElement $select  Select.
	 * @return string[]
	 */
	private static function selected_options( \DOMXPath $xpath, \DOMElement $select ): array {
		$options  = $xpath->query( './/option', $select ) ?: array();
		$values   = array();
		$first    = null;
		foreach ( $options as $option ) {
			/** @var \DOMElement $option */
			if ( $option->hasAttribute( 'disabled' ) ) {
				continue;
			}
			$value = $option->hasAttribute( 'value' ) ? $option->getAttribute( 'value' ) : trim( $option->textContent );
			$first = $first ?? $value;
			if ( $option->hasAttribute( 'selected' ) ) {
				$values[] = $value;
			}
		}
		if ( array() === $values && null !== $first && ! $select->hasAttribute( 'multiple' ) ) {
			$values[] = $first;
		}
		return $values;
	}

	/**
	 * An XPath string literal.
	 *
	 * @param string $value Text.
	 */
	private static function literal( string $value ): string {
		return false === strpos( $value, "'" ) ? "'" . $value . "'" : '"' . $value . '"';
	}
}

if ( PHP_SAPI === 'cli' && isset( $argv[0] ) && realpath( $argv[0] ) === __FILE__ ) {
	if ( $argc < 3 || ! is_readable( $argv[1] ) ) {
		fwrite( STDERR, "Usage: php FormFields.php <html-file> <form-selector>\n" );
		exit( 2 );
	}
	$drop  = array_slice( $argv, 3 );
	$pairs = array_filter(
		FormFields::pairs( (string) file_get_contents( $argv[1] ), $argv[2] ),
		static fn ( array $pair ): bool => ! in_array( $pair[0], $drop, true )
	);
	echo FormFields::encode( array_values( $pairs ) ); // phpcs:ignore
}
