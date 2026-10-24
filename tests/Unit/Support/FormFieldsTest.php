<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use WPBouncer\Tests\Support\FormFields;

/**
 * The test helper that stands in for a browser: it must follow the HTML rules, or the Rules tab round-trip proves nothing.
 *
 * @covers \WPBouncer\Tests\Support\FormFields
 */
final class FormFieldsTest extends TestCase {

	private const HTML = <<<'HTML'
<form class="a" id="main" method="post">
	<input type="hidden" name="action" value="save">
	<input type="checkbox" name="on" value="1" checked>
	<input type="checkbox" name="off" value="1">
	<input type="checkbox" name="bare" checked>
	<input type="radio" name="mode" value="x"><input type="radio" name="mode" value="y" checked>
	<input type="number" name="n" value="7" disabled>
	<input type="text" name="list[]" value="a"><input type="text" name="list[]" value="b">
	<input type="text" value="no name">
	<textarea name="t">
first
second &amp; third</textarea>
	<select name="s"><option value="1">one</option><option value="2" selected>two</option></select>
	<select name="s2"><option>first</option><option>second</option></select>
	<details><summary>Settings</summary><input type="text" name="hidden_in_details" value="still sent"></details>
	<input type="submit" name="submit" value="Save">
	<button name="b" value="1">Go</button>
	<input type="file" name="f">
</form>
<form class="b"><input name="other" value="x"></form>
<input name="elsewhere" form="main" value="e">
<input name="elsewhere2" form="b" value="e">
HTML;

	public function test_it_returns_the_successful_controls_in_document_order(): void {
		$pairs = FormFields::pairs( self::HTML, 'form.a' );

		$this->assertSame(
			array(
				array( 'action', 'save' ),
				array( 'on', '1' ),
				array( 'bare', 'on' ),
				array( 'mode', 'y' ),
				array( 'list[]', 'a' ),
				array( 'list[]', 'b' ),
				array( 't', "first\nsecond & third" ),
				array( 's', '2' ),
				array( 's2', 'first' ),
				array( 'hidden_in_details', 'still sent' ),
				array( 'elsewhere', 'e' ),
			),
			$pairs
		);
	}

	public function test_names_lists_unchecked_controls_too_but_not_disabled_ones(): void {
		$names = FormFields::names( self::HTML, '#main' );

		$this->assertContains( 'off', $names );
		$this->assertNotContains( 'n', $names );
		$this->assertNotContains( 'other', $names );
	}

	public function test_of_builds_nested_arrays_like_php_does(): void {
		$post = FormFields::of( '<form id="f"><input name="a[b][c]" value="1"><input name="a[b][d][]" value="x"><input name="a[b][d][]" value="y"></form>', '#f' );

		$this->assertSame( array( 'a' => array( 'b' => array( 'c' => '1', 'd' => array( 'x', 'y' ) ) ) ), $post );
	}

	public function test_a_missing_or_ambiguous_form_is_an_error(): void {
		$this->expectException( \RuntimeException::class );
		FormFields::pairs( self::HTML, 'form.nope' );
	}

	public function test_a_selector_it_does_not_understand_is_an_error(): void {
		$this->expectException( \InvalidArgumentException::class );
		FormFields::pairs( self::HTML, 'div > form' );
	}
}
