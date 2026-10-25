# WPB-10b: Drag-to-resize columns on the Activity Log and Traffic tabs (design)

Status: design, 2026-10-24. Spec: `documentation/backlog.md` → WPB-10b (AC1–12). Security: `documentation/security/wpb-10b-column-resize.md`. Release 1.2.1.
Nothing is stored on the server, so there are no options, tables, hooks, REST/AJAX routes or nonces, and the data-engineer is not needed. Nothing touches the firewall path or the front end.

## 1. Files

| File | Change |
|---|---|
| `wp-bouncer/assets/columns.js` (new) | All resize behaviour. Vanilla ES5-style IIFE like `admin.js`, no deps, ≤ ~4 KB unminified |
| `wp-bouncer/assets/admin.css` | Handle, fixed-layout, focus, forced-colors and ≤782px rules (§4) |
| `src/Admin/ColumnResize.php` (new) | `final class ColumnResize`: `TABS = ['log','traffic']`, `DEFAULT_MIN = 60`, `annotate( string $html, array $labels, array $mins ): string` |
| `src/Admin/LogListTable.php`, `TrafficListTable.php` | `print_column_headers()` override, `RESIZE_MIN` const, hidden reset button in `extra_tablenav( 'top' )` |
| `src/Admin/AdminController.php` | Conditional enqueue + `wpBouncerCols` localisation in `enqueue_assets()` |
| `tests/Integration/Admin/*`, `tests/Unit/Assets/ColumnsScriptTest.php`, `tests/js/columns.test.js`, `tests/e2e/run.sh` | §5 |

## 2. PHP changes (presentation layer)

**Header markup.** WP_List_Table has no filter for `<th>` attributes, and copying core's `print_column_headers()` would drift across WP versions. Each table overrides it and post-processes core's own output:

```php
public function print_column_headers( $with_id = true ) {
	if ( ! $with_id ) { parent::print_column_headers( false ); return; } // tfoot: untouched
	ob_start(); parent::print_column_headers( true );
	echo ColumnResize::annotate( (string) ob_get_clean(), $this->get_columns(), self::RESIZE_MIN ); // phpcs:ignore -- core output, attributes added by WP_HTML_Tag_Processor
}
```

`annotate()` walks `<th>` tags with `WP_HTML_Tag_Processor` (WP 6.2+). For each `th` whose `id` is a key of `get_columns()` (the server-side allowlist; the processor escapes values) it sets `data-wpb-col` = id, `data-wpb-min` = `RESIZE_MIN[id] ?? 60`, and `data-wpb-label` = `wp_strip_all_tags( label )`. Other `th` tags are left alone. Mins: Log `country`, `action` 44; Traffic `status` 44; the rest 60. Handles are **not** rendered in PHP. A handle that does nothing without JS would be a dead focusable control, so JS builds them (SB-03).

**Reset control.** `extra_tablenav( 'top' )` adds `<div class="alignleft actions"><button type="button" class="button wpb-cols-reset" hidden>` + `esc_html__( 'Reset column widths' )`. It is rendered hidden and JS shows it, the same pattern as the Rules tab's Expand-all bar.

**Enqueue.** Inside `enqueue_assets()`, after the existing hook check:
```php
$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display decision only
if ( in_array( $tab, ColumnResize::TABS, true ) ) { wp_enqueue_script( 'wp-bouncer-cols', $url . 'assets/columns.js', array(), Plugin::VERSION, array( 'in_footer' => true, 'strategy' => 'defer' ) ); wp_localize_script( 'wp-bouncer-cols', 'wpBouncerCols', array( 'table' => $tab, 'i18n' => array( 'resize' => /* translators: %s: column name. */ __( 'Resize %s column' ), 'px' => /* translators: %d: width in pixels. */ __( '%d pixels' ) ) ) ); }
```
`wpBouncer` (and `geoNonce`) are unchanged and not passed to the new script. The table id is the tab slug, a constant from the allowlist.

## 3. JS structure (`columns.js`)

```
(function () {
  var core = { parse(raw,min,max)→int|null, key(table,col)→string|null, step(key,shift,dir)→int|'min'|'max'|'reset'|null, fit(ws,mins,stored,budget)→ws };
  if (typeof module === 'object' && module.exports) { module.exports = core; return; }   // node tests only
  … DOM wiring below …
})();
```
- **Boot.** Read `window.wpBouncerCols`. Bail unless `table` is `log` or `traffic`, and find `table.wp-list-table` inside `.wp-bouncer`. Columns = `thead th[data-wpb-col]` whose key matches `^[a-z0-9_]{1,32}$` (SB-04). Lookups compare `th.dataset.wpbCol` and never build selectors.
- **Storage.** Key `wpb_cols:<table>:<col>` (owner decision). The value is a plain integer string. `parse()` accepts only `^\d{1,4}$`, then clamps to [min, max]; anything else is `removeItem`'d. Every `getItem`/`setItem`/`removeItem` is in try/catch (private mode, quota). Reset walks `localStorage.key(i)` backwards and removes keys that start with exactly `wpb_cols:<table>:`, never `clear()` (SB-09).
- **Visible set.** Visible = the column's `th` has `getClientRects().length` and no `hidden` class. The **last visible column is the filler**: it gets no handle and no width and takes the rest of the row. That way the row always equals the container (AC2) and the last column's trailing edge, which is the table edge, has nothing to drag. Tradeoff: Log `user_agent` / Traffic `user` are made wider by narrowing the others.
- **apply()** (load, window resize via rAF, media change, column toggle, reset):
  1. Remove `wpb-cols-fixed` and every inline `th.style.width`, which gives the auto layout from 1.2.0.
  2. If `mq.matches` (`matchMedia('(max-width: 782px)')`): remove the `wpb-cols-on` class, hide handles and reset, stop (AC7).
  3. Add `wpb-cols-on` and show the reset button. If no visible non-filler column has a valid stored width, stop: auto layout is the default.
  4. Measure each visible `th` (`getBoundingClientRect().width`, border-box). `budget = table.clientWidth − fillerMin`. `fit()`: start from the stored width or the measured one, clamp to min, and if Σ > budget shrink the unstored columns to their min first, then the stored ones proportionally (display only, never saved).
  5. Set `th.style.width = n + 'px'` (validated number only, SB-02) on every non-filler column, then add `wpb-cols-fixed`. Update each handle's `aria-valuenow`/`-valuemax`/`-valuetext`.
  The first drag or key press on an auto-layout table runs steps 4–5 with no stored widths ("freeze"), so switching to `table-layout: fixed` causes no jump. `max(col) = budget − Σ other non-filler widths`.
- **Handle.** `createElement('span')` appended to the `th`, never inside the sort `<a>`. Attributes: `class="wpb-col-handle"`, `tabindex=0`, `role=separator`, `aria-orientation=vertical`, `aria-valuemin`, and `aria-label` = `i18n.resize.replace('%s', th.dataset.wpbLabel)` via `setAttribute` (SB-06). The label comes from `data-wpb-label` and not from `textContent`, because WP's sortable headers contain screen-reader "Sort ascending." text.
- **Pointer** (SB-08). Listeners are bound once per handle, with none on `document`. `pointerdown` (trusted, button 0): `preventDefault`, `stopPropagation`, freeze, `setPointerCapture`, store `{id, x0, w0}`. `pointermove` acts only while that state exists: `w = clamp(w0 + (x − x0) * dir)`. `pointerup` saves. `pointerup`/`pointercancel`/`lostpointercapture` clear the state and the `wpb-col-dragging` body class. `click` on a handle calls `stopPropagation` + `preventDefault`. `dblclick` resets that column. Untrusted events are ignored.
- **Keyboard.** `step()`: ArrowRight/ArrowLeft give ±10 (Shift ±50) × `dir`, Home gives min, End gives max, Escape resets the column (removes the key, then `apply()`). Each change saves and updates `aria-valuenow` and `aria-valuetext` (`i18n.px`). A focused separator's value change is the polite announcement (AC3 "or"). There is no extra live region, to stay within the size budget.
- **RTL** (AC8). `dir = getComputedStyle(table).direction === 'rtl' ? -1 : 1`. Both pointer deltas and arrow keys are multiplied by `dir`, so a drag or arrow toward the trailing edge always widens the column. Only widths are stored. CSS uses logical properties, so the handle sits on the left in RTL.
- **Screen Options** (AC6). `change` on `.hide-column-tog` → `apply()` on the next frame. Hidden columns keep their stored keys but are skipped. Note: in 1.2.0 these tabs show **no** column toggles. The table is built inside the view after the screen meta has rendered, and `_column_headers` passes `array()` for hidden columns. So this path is defensive, and adding Screen Options is out of scope.

## 4. CSS (`admin.css`, after the WPB-10a block)

- `.wpb-cols-on th[data-wpb-col]{position:relative}`. Reserve the 24px handle strip at the trailing edge so it never covers a sort link: `.wpb-cols-on th[data-wpb-col]:not(.sortable):not(.sorted){padding-inline-end:24px}` and `.wpb-cols-on th[data-wpb-col] > a{margin-inline-end:24px}` (AC1).
- `.wpb-col-handle{position:absolute;inset-block:0;inset-inline-end:0;width:24px;cursor:col-resize;touch-action:none;user-select:none}`, with a 2px `::after` line at the inline-end edge (`#c3c4c7`, `#2271b1` on hover, active and focus). `body.wpb-col-dragging{cursor:col-resize;user-select:none}`.
- `.wpb-col-handle:focus-visible{outline:2px solid #2271b1;outline-offset:-2px}`.
- `.wpb-cols-fixed{table-layout:fixed}` and `.wpb-cols-fixed th{box-sizing:border-box;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}`. These apply **only once widths apply**. The `.wpb-trunc` clipping from WPB-10a already holds under a fixed layout.
- `.wpb-cols-reset[hidden]{display:none}`, because `.button` would otherwise override `hidden`.
- `@media (forced-colors: active)`: `.wpb-col-handle::after{background:CanvasText}` and focus `outline-color:Highlight`.
- `@media (max-width: 782px)`: `.wpb-col-handle,.wpb-cols-reset{display:none}` and `.wpb-cols-fixed{table-layout:auto}` (a fallback if JS misses the change).

## 5. Test plan

**PHP integration** (`AdminScreensTest`, `AdminControllerTest`, WP matrix):
- `wp-bouncer-cols` is enqueued for `tab=log` and `tab=traffic`, with `wpBouncerCols.table` equal to the tab. It is not enqueued for dashboard, general, rules, countries or tools, for a missing `tab`, for a bogus value (`logx`, `traffic/../`), or for another hook suffix (`index.php`). The `wpBouncer` keys are identical to 1.2.0, and `wpBouncerCols` contains no nonce.
- Rendered log and traffic tabs: every `thead th` with an id has `data-wpb-col` equal to its id, and that id is in `get_columns()`. `data-wpb-min` is an integer. `tfoot th` have no `data-wpb-*`. The sort links (`orderby=`) are unchanged. There is exactly one `button.wpb-cols-reset[type=button][hidden]`. No `wpb-col-handle` in the PHP output. The WPB-10a `.wpb-trunc` cells are still present.
- `ColumnResize::annotate()` leaves `th` tags with unknown ids untouched, returns the input unchanged when no ids match, and escapes a crafted label containing `"<>&` in `data-wpb-label`.

**Unit, no WordPress** (`tests/Unit/Assets/ColumnsScriptTest.php`, runs in `make test`/CI). This is the SB-11 static check: `columns.js` contains none of `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`, `cssText`, `setAttribute('style'`, `localStorage.clear`, `jQuery`. It is smaller than 4,500 bytes, and `admin.js` does not mention `wpb_cols`.

**JS logic.** The repo has **no JS test runner, no Node in CI and no browser in e2e** (`run.sh` uses curl). The lightest option is Node's built-in runner, `node --test tests/js/`: no npm, no `package.json`, no `node_modules`, and Node is preinstalled on GitHub's Ubuntu runners. devops adds `make test-js` (skipped with a notice if `node` is missing) and one CI step. The tests `require()` the shipped `columns.js`, which returns `core`. Cases:
- `parse()` with `"<img src=x onerror=alert(1)>"`, `"-5"`, `"1e9"`, `"NaN"`, `"12px;background:url(//x)"`, `"{"`, `""`, `null`, `"240"`, `"30"` (clamped to min) and `"9999"` (clamped to max).
- `key()` rejects `Request`, `a-b`, a 33-character key and an unknown table.
- `step()`: every key and Shift combination in LTR and RTL.
- `fit()`: over-budget shrink order, mins respected, and the stored widths untouched when they fit.
If the owner declines Node in CI, the same file runs locally and the manual checklist covers it.

**e2e** (`run.sh` "Admin screens"): logged-in GET of the log and traffic tabs contains `assets/columns.js?ver=` and `data-wpb-col="request"`. The rules and dashboard tabs do not contain it. GET of the asset returns 200 from the built zip.

**Security note (RT-05).** A crafted `tab` value such as `traffic/../` is normalised with `sanitize_key()` before it is compared, the same way `render()` does (`AdminController::enqueue_assets()` and `render()`). The script is therefore enqueued only when the normalised value is `log` or `traffic`, and `wpBouncerCols.table` is always one of those two allowlisted values. The last visible column is the fill column: it takes the rest of the row and has no handle (§3).

**Manual browser checklist** (Chrome, Firefox, Safari; record in the PR). Drag widens and narrows live with no overlap and no horizontal scroll. Header text still sorts, and pressing the handle never sorts. Arrow keys, Shift+Arrow, Home, End and Esc work. Double-click resets the column. The reset button clears only that table's keys: seed `wpb_cols:traffic:request` and an unrelated key and check both survive a Log reset. Widths persist after reload. `request` keeps separate widths on the two tabs. Hiding a column (devtools: add `hidden` to a `th`) re-lays out. At ≤782px there are no handles, the layout is auto and clipping holds. RTL (site language he_IL): handles on the left and mirrored drag and keys. Forced colors (Chrome emulation or Windows contrast theme): handle and focus are visible. NVDA or VoiceOver read the name and the value changes. The SB-11 seeds in devtools: no dialog or request. With `Storage.prototype.setItem` throwing, the page still works. Zoom 200%.

## 6. Security recommendations

| ID | Decision |
|---|---|
| SB-01 | **Adopted, stricter.** The value is an integer string checked with `^\d{1,4}$` (no `JSON.parse` needed), then clamped; bad values are removed; all storage calls are in try/catch. |
| SB-02 | **Adopted.** Only `th.style.width = n + 'px'` with a validated number. |
| SB-03 | **Adopted.** Handles are built with `createElement`/`setAttribute`. The reset button is server-rendered with `esc_html__()`, which is equally safe and keeps the no-JS page unchanged. |
| SB-04 | **Adopted.** `data-wpb-col` comes from `get_columns()` ids through `WP_HTML_Tag_Processor`. JS checks the regex and the two table ids, and uses `dataset` comparison, not selectors. |
| SB-05 | **Adopted.** Strict `in_array` on the `sanitize_key`'d tab. The handle is named `wp-bouncer-cols` to match `wp-bouncer-admin`. No secrets are passed. |
| SB-06 | **Adopted.** `wp_localize_script()`. The `%s` label comes from the escaped `data-wpb-label` instead of `textContent`, because of the hidden sort text in the headers. It is inserted with `setAttribute` only. |
| SB-07 | **Adopted** for the new code. The existing inline `onsubmit` confirm on the clear-log forms predates this item and is out of scope (backlog candidate). |
| SB-08 | **Adopted, variant.** Pointer listeners are bound once per handle and act only during a captured drag. The state is cleared on up, cancel and lost capture, and there are no document listeners to leak. `isTrusted` is checked. |
| SB-09 | **Adopted.** One integer per key, prefix-exact reset, no `clear()`. |
| SB-10 | **Adopted.** A note in `architecture.md` and a changelog line. |
| SB-11 | **Adopted.** Mapped to §5. The static check is a PHPUnit unit test rather than a CI grep, so it also runs locally. |

## 7. Risks, compatibility, extension

- **Risks.** (1) Core changes to the header markup: the tag processor only keys on `th` + `id`, and the WP matrix integration tests catch drift. (2) Layout jump on the first drag: avoided by the freeze. (3) Filler-column tradeoff (§3). (4) There are no Screen Options toggles today, so AC6 is only checked by simulation. (5) The JS is new in a patch release, which needs the full test and audit cycle.
- **Multisite.** No server state. Subdirectory networks share one origin, so widths are shared across sites in the browser. That is acceptable for a UI preference. Subdomain sites keep their own.
- **Backward compatibility and uninstall.** Without JS the page is identical to 1.2.0 except for the data attributes and a hidden button. No hooks, options or tables change. `uninstall.php`, the privacy exporter and eraser, and the policy text need nothing, because the data is browser-only and is never sent.
- **Extension.** No public hooks are added on purpose, and `wpBouncerCols` is not an API. Themes can restyle via `.wpb-col-handle`, `.wpb-cols-on` and `.wpb-cols-fixed`.
