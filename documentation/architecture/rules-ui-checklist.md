# WPB-2 Rules tab: accessibility and JavaScript checklist

Manual checklist for the behaviour that the automated suites cannot see: what JavaScript adds, and
what assistive technology and keyboard users get. Design: [rules-ui.md](rules-ui.md) (§3.4, §9,
§10.3). Decision: [ADR 001](../adr/001-rules-tab-categories.md) (owner decision 6: manual checklist
for 1.2.0, Playwright job later).

Run it before tagging 1.2.0, on a test site (never production), as an administrator. Use the Rules
tab with the default settings, then again after `?wpb_rule=waf`.

Part A records what was already checked while implementing, and how. Part B is the checklist for a
person with the browsers and screen readers.

---

## A. Checked during implementation

### A.1 No JavaScript (curl, DOM checks): automated in `tests/e2e/run.sh`, section "Rules tab"

curl runs no JavaScript, so these are the no-JS behaviours. All pass.

| Check | How |
|---|---|
| Every rule row and category exists once (`#rule-<id>`, `#wpb-cat-<slug>`) | `grep -o 'id="…"'` count is 1 |
| Titles, switches, state text and warnings are in the page, outside `<details>` | markup tests in `RulesTabTest` |
| Settings sit in 10 native `<details class="wpb-rule-settings">`, all closed by default | e2e `open_panels` is empty |
| `?wpb_rule=uploads_php` renders that panel `open`, with no JavaScript; an unknown or hostile value opens nothing and is not echoed unescaped | e2e |
| Expand/collapse buttons are rendered `hidden`, so they never show without JavaScript | e2e (`class="wpb-expand" hidden`) |
| Posting the form as a browser would (closed panels included) changes no setting, with defaults and with every rule non-default | e2e and `RulesTabTest` (single site and multisite) |
| A rule missing from the POST is switched off (the guard can fail) | e2e and `RulesTabTest` |
| Country rule is a status card: no input named `wp_bouncer[rules][country]…`, a link to the Countries tab | e2e |
| Dashboard: the four categories, one Turn on/off button per rule, a toggle works and reverts | e2e |

### A.2 JavaScript behaviour, run against a fake DOM (JavaScriptCore, `jsc`)

`assets/admin.js` was executed with a hand-made DOM for these, all as intended. This is not a
browser: it proves the logic, not the rendering. Part B repeats them in real browsers.

| Behaviour | Result |
|---|---|
| Load with `#rule-uploads_php`: that row's `<details>` opens, the row is scrolled to and focused | pass |
| `hashchange` to `#wpb-cat-block-lists`: the section is focused (nothing to open) | pass |
| Click on a same-page link whose hash is already the current hash (no `hashchange` fires) re-opens and focuses | pass |
| Unknown, empty and malformed hashes (`#nope`, `#%E0%A4%A`, `#wp-bouncer" onfocus="x`) are ignored with no error | pass |
| Changing a switch sets the state text to "Off (not saved)", changing it back restores "On"; "You have unsaved changes." is announced once | pass |
| An `invalid` event from a field inside a closed panel opens the panel | pass |
| Submit stores the ids of open panels in `sessionStorage['wpbRulesOpen']`; on load they reopen, unknown or non-string ids are ignored, and the key is cleared | pass |
| Expand all / Collapse all unhide, get their labels from the page's i18n strings, and set `open` on every panel | pass |

### A.3 Keyboard, reasoned from the markup and the CSS (not tested with a person)

- Tab order follows reading order: jump list links, Expand all, Collapse all (only when
  JavaScript unhid them), then for each rule: switch, the fix link if there is one, the "Settings"
  summary, the panel's inputs (only when open: the content of a closed `<details>` is not in the tab
  order), and finally the save bar.
- The switch is a real `<input type="checkbox" role="switch">`: Space toggles it. Its name is the
  rule title (the `screen-reader-text` span inside the label), not the old ambiguous "Enabled".
- `<summary>` is natively focusable; Enter and Space toggle the panel, and the open state is
  announced by the browser. It holds only text (no heading, no link), so its role is not flattened.
- Rule rows and category sections have `tabindex="-1"`: reachable by script and by a link, not part
  of the tab order. `:focus-visible` draws an outline on them, and `.wpb-switch input:focus-visible`
  keeps the existing ring on the slider.
- There is no keyboard trap and no `beforeunload` prompt.

---

## B. Checklist for the tester

Tick each line per browser. Browsers: Chrome, Firefox, Safari (current), plus one of Edge. Note the
version.

### B.1 Without JavaScript

Disable JavaScript in the browser (Chrome: DevTools, Command menu, "Disable JavaScript"; Firefox:
`javascript.enabled` in `about:config`), reload the Rules tab.

- [ ] Four category sections show, each with a name, a one-line description and "N of M rules on".
- [ ] Every rule shows its title, switch, "On" or "Off", and any warning.
- [ ] "Expand all" and "Collapse all" are not visible.
- [ ] Click "Settings" on a rule: the panel opens. Click again: it closes. Enter and Space do the same.
- [ ] Open one panel, change a number, press Save: "Settings saved." appears and the value is kept.
- [ ] Do not open any panel, press Save: no rule changed (compare the Dashboard before and after).
- [ ] Follow a notice link for the uploads rule (`…&wpb_rule=uploads_php#rule-uploads_php`): the page scrolls to the rule and its panel is open.
- [ ] Follow the jump list links: each scrolls to its category (the heading is not hidden under the admin bar).

### B.2 With JavaScript

- [ ] Load `…&tab=rules#rule-waf`: the WAF panel is open, scrolled into view, and the row has a visible focus outline.
- [ ] From another place on the page click a link to `#rule-waf` again: it re-opens, scrolls and focuses.
- [ ] Press the browser's Back and Forward buttons across two hashes: the target follows.
- [ ] Change a switch: the state reads "Off (not saved)" (or "On (not saved)"); change it back: the marker goes. "You have unsaved changes." appears next to Save, once.
- [ ] Open two panels, Save: after the redirect the same two panels are open (and a panel opened by the hash is open too).
- [ ] Expand all opens all 10 panels; Collapse all closes them.
- [ ] Type 0 in a number field with `min="1"` inside a panel, close the panel, press Save: the panel opens and the browser's message points at the field.
- [ ] With the browser's storage blocked (private mode with cookies blocked), the page still works; panels simply start closed after a save.
- [ ] Open the Countries and Tools tabs: the country picker, "Add my IP" and the geo import progress still work (the script is shared).

### B.3 Keyboard only (no mouse)

- [ ] Tab from the page title: tabs, jump list, Expand all, Collapse all, then the first rule's switch.
- [ ] Space on a switch toggles it. The focus ring is visible on the slider.
- [ ] Tab to "Settings", press Enter: the panel opens and the next Tab goes to its first input.
- [ ] Tab through a whole category: the order matches the visual order. Nothing is skipped and nothing traps focus.
- [ ] Shift+Tab goes back through the same order.
- [ ] The Save button is reachable without passing through every panel when all are closed, and Enter in a number field submits the form.
- [ ] When the page is scrolled, the sticky save bar does not cover the focused control (scroll-margin and the bar's height).

### B.4 Screen reader

NVDA with Firefox or Chrome on Windows, and VoiceOver with Safari on macOS.

- [ ] A switch is announced as "<Rule title>, switch, on/off" (for example "IP blocklist, switch, on"), never just "Enabled".
- [ ] A rule row is announced as a group named after its title; the heading list (H key) shows the page h1, four h2 categories and an h3 per rule, in that order.
- [ ] "Settings: <Rule title>" is announced as a button with "collapsed" or "expanded".
- [ ] A warning is read as text starting "Needs attention:" or "Before switching on:". Nothing depends on colour or the icon (the icon is `aria-hidden`).
- [ ] After changing a switch, "You have unsaved changes." is announced once.
- [ ] After Save, "Settings saved." is announced (the notice has `role="status"`; an error has `role="alert"`).
- [ ] On the Countries tab the switch reads "Country blocking, switch"; on the Traffic tab "Record traffic, switch".
- [ ] The country card reads as text (state, summary, geo line) and a "Configure on the Countries tab" link; there is no unlabelled control.

### B.5 Zoom, small screens, RTL, high contrast

- [ ] 200% browser zoom: nothing is clipped or overlaps; the rule head wraps; the switch stays at the start.
- [ ] Window at 782 px and at 360 px: the save bar is no longer sticky at 782 px or less; the jump list wraps; panels use the full width.
- [ ] RTL (set the site language to Arabic or Hebrew, or use the RTL Tester plugin): the layout mirrors, the switch thumb moves toward the correct side, the warning stripe is on the right, the "Settings" arrow points the right way.
- [ ] Forced colours (Windows high contrast, or DevTools, Rendering, "Emulate CSS media feature forced-colors: active"): the switch has an outline, the "on" state is distinguishable, warning lines have a border, "Settings" is visibly a button.
- [ ] Reduced motion is respected (the switch transition is the only animation, and the page scroll is instant).

### B.6 Third-party rules and multisite (if the site allows)

- [ ] Add a plugin that uses the `wp_bouncer_rules` filter. With no `wp_bouncer_rule_info`, it shows under "Other" with its id, and "Managed by the plugin that added it." With `wp_bouncer_rule_info`, it shows in its category with its title.
- [ ] Multisite, as a sub-site administrator: the "No PHP in uploads" switch and the `.htaccess` checkbox are disabled and say "Managed by your network administrator."; saving the Rules tab leaves both unchanged. As a network administrator they are live.

---

## C. Results

Fill in per release.

| Date | Version | Tester | Browsers / screen readers | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |
