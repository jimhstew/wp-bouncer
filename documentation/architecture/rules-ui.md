# WPB-2: Rules UI in categories (design)

Status: implemented in 1.2.0. Author: architect, 2026-10-23. This is the design record. Where it differs from the code, the code is right, and the differences are listed under "As built" below.
Spec: `documentation/backlog.md` → WPB-2 and "Owner decisions" 3 and 6.
Target release: 1.2.0, or 1.3.0 if it slips (owner decision 5).

This document is the design only. It changes no settings keys, no option structure, no
database schema and no existing hook. The data-engineer is not needed: nothing new is stored.

---

## As built (1.2.0)

Where the implementation differs from the sections below. The code is the reference.

- **Location.** `Admin\RuleCatalog` and `Admin\RuleStatus` live in `src/Admin/`, not in a separate core folder. Both make no WordPress calls and are unit-tested. `Admin\RuleOverview` is the WordPress-facing assembler (§7.2), and `Admin\RuleLabels` holds the text (§6.3).
- **`rule_switch()`.** The signature is `rule_switch( string $id, bool $checked, bool $disabled = false, string $title = '' )`. `$title` is the **fourth** parameter, after `$disabled`. §3.4 and §8.2 say "third"; that was wrong.
- **`back()`.** The signature is `back( string $tab, string $code, array $args = array(), bool $error = false, string $fragment = '' )`. When the fragment is `rule-<id>` for a built-in id, `back()` also adds `wpb_rule=<id>` to the redirect, so the row's settings are open where the admin lands (§4.2).
- **Multisite exception to "never disabled".** On multisite, a user without `wpb_manage_firewall` sees the uploads rule's switch and its `.htaccess` checkbox disabled, with the note "Managed by your network administrator." `Settings::preserve_privileged()` keeps the stored `enabled` and `htaccess` values on save, so the disabled controls change nothing. This is the only disabled input the Rules tab renders (see the contract in `partials/rule-row.php`). Regex User-Agent patterns that a sub-site admin adds are dropped by the same function, and the field stays editable.
- **Notice reasons.** `RuleLabels::notice()` has screen-wide text for four reasons: `NO_GEO_DB`, `GEO_HEADER_UNTRUSTED`, `UPLOADS_BROKEN` and `UPLOADS_WRITE_FAILED`. §6.2 lists three. The country-paused notice (`GEO_HEADER_UNTRUSTED`, see RT-06) is screen-wide too.

---

## 0. Summary of decisions

| Question | Decision |
|---|---|
| Layout | **One page, one form.** Four category sections (plus "Other" when needed), each always expanded, with a heading, description and "N of M rules on". Inside a section each rule is a **row** that always shows its title, on/off switch, state text and any warning. The rule's settings sit in a native **`<details>`** disclosure below the row. A small jump list at the top links to the categories. No sub-tabs, no separate detail pages. |
| Saving | **Submit every input every time.** The page keeps one `<form>` with `tab=rules`. Every rule input is always rendered, never `disabled`, never lazy-loaded. A closed `<details>` hides its inputs but the browser still submits them. `Settings::TAB_FIELDS` and `Settings::apply_form()` **do not change**. A round-trip test proves "render, submit as a browser would, save" leaves the settings exactly as they were. |
| Category declaration | **Built-in rules:** one constant map, `Admin\RuleCatalog::CATEGORIES` (pure PHP). A unit test fails if a rule in `Settings::defaults()` has no entry there. **Third-party rules:** a new filter, `wp_bouncer_rule_info`, which returns `id => [ 'category' => slug, 'title' => string ]`. A missing or unknown category goes to "Other". The rule's title defaults to its id. `RuleInterface` does not change. |
| Deep links | `#rule-<id>` stays on every rule row, including `#rule-country` (a status card). `#wpb-cat-<slug>` is added for categories. The target row is visible without JavaScript. With JavaScript, the hash also opens the row's settings, scrolls to it and moves focus there, on load and on every hash change. Notices link to the specific rule: `?tab=rules&wpb_rule=<id>#rule-<id>`, and `wpb_rule` makes the server render that panel open. `#wpb-alerts` (General tab) is not touched. |
| Status | Pure `Admin\RuleStatus` computes each rule's state, plus "attention" (a warning) or "setup" (a neutral hint). It uses the same conditions as today's notices, and `notices()` is rewritten to use it, so there is one source of truth. |
| Dashboard tab | The flat rules table is replaced by the **same grouped overview partial**, with the same categories, titles and states, and the existing **Turn on/off** buttons kept. Labels, categories and status all come from one place. |
| Country rule | A **status card** in "Block lists": the state as text, a summary (mode, number of countries, scope), any geo-database warning, and a "Configure on the Countries tab" link. It has **no input**, because `rules.country` belongs to the Countries tab. |

---

## 1. Current state (what this changes)

- `views/rules.php`: one form (`tab=rules`), ten `<section id="rule-<id>">` panels in an arbitrary order, and a text line pointing to the Countries tab. The switch's accessible name is "Enabled" on every rule (ambiguous). The Traffic tab has the same problem.
- `AdminController::rule_labels()`: a hard-coded `id => [title, description]` map, used by the Dashboard table, the log filter and `rule_title()`.
- `AdminController::notices()`: works out the country-without-geo-DB and uploads-broken/write-failed conditions inline, and says "See Rules → No PHP in uploads" as plain text.
- `views/dashboard.php`: its own flat rules table with Turn on/off buttons (`handle_toggle_rule`).
- `Plugin::build_rules()` builds 10 firewall rules and applies `wp_bouncer_rules`. `uploads_php` is not a firewall rule (it is `UploadsGuard`), so the list of "rules the admin manages" is `Settings::defaults()['rules']` (11 ids), not `build_rules()`.
- `Settings::TAB_FIELDS['rules']` owns the 10 rules other than `country`. `apply_form()` **replaces** each owned key with what was posted, or with an empty array if nothing was posted, and `sanitize()` turns that into all-false. So **any rule whose inputs are missing from the POST is switched off.** The integration test `test_saving_the_rules_tab_treats_missing_checkboxes_as_off` relies on this (line 313: "a rule absent from the form is switched off"), and it stays valid.

---

## 2. Layers

| Layer | What it means here |
|---|---|
| Bootstrap | Unchanged. No new constants, version checks, activation or uninstall work. |
| Hooks | One new filter, `wp_bouncer_rule_info` (§5). `Plugin::run_firewall()` keeps the rule list it already builds, so the admin can read it without running `wp_bouncer_rules` a second time (§5.3). |
| Presentation | `views/rules.php` rebuilt from partials. Shared `partials/rule-overview.php` used by the Dashboard. CSS/JS additions in `assets/admin.css` and `assets/admin.js`. |
| API | No new admin-post, AJAX, REST, cron or CLI handlers. `handle_save`, `handle_toggle_rule`, `handle_uploads_probe` and `handle_uploads_sync` keep their contract. The last two add a fragment and the `wpb_rule` arg to their redirect. |
| Domain (pure PHP) | `Admin\RuleCatalog`: categories and membership. `Admin\RuleStatus`: state, flags and category totals. No WordPress calls, unit-tested. |
| Data access | Unchanged. It reads what the screen already reads: `wp_bouncer_settings`, `wp_bouncer_geo_meta`, `wp_bouncer_uploads_htaccess`, `wp_bouncer_uploads_probe`. |
| Infrastructure | i18n for the new strings. Multisite: per-site as today. Uninstall: nothing new to clean up. |

---

## 3. Layout

### 3.1 Options considered

| Option | Verdict |
|---|---|
| **A. Sections on one page, rule settings in `<details>`** | **Chosen.** One form, so saving can't drop a panel. Without JS everything is present and operable (native disclosure). Anchors work natively. It scales: a 12th rule is one more row. |
| B. Sub-tabs (one per category) | Rejected. Either each sub-tab is its own form (the `apply_form` trap: saving "Login" would switch off every other rule), or it is one form whose other panels JS hides. That needs JS to be usable, a no-JS fallback that is just option A, and deep links that need JS to pick the tab. More code, same result. |
| C. Overview cards plus one detail screen per rule | Rejected. Per-rule screens would each need their own form, so `TAB_FIELDS` would have to be split per rule. It means more clicks to change two rules, and every notice link becomes a navigation. The overview is still useful, so it is reused as the Dashboard partial (§7). |
| Custom accordion (`button[aria-expanded]` + `hidden`) | Rejected in favour of native `<details>`. Native gives keyboard handling, expanded/collapsed announcement and a no-JS fallback for free. WP 5.8 dropped IE11, so every supported browser has `<details>`. |

### 3.2 Page structure (Rules tab)

```
h1 WP Bouncer
nav  (tabs)
[notices]
nav.wpb-cat-nav  aria-label="Rule categories"          ← jump list, outside the form
  ul > li > a[href="#wpb-cat-block-lists"] "Block lists" + "2 of 3 rules on" [+ "1 needs attention"]
  … one li per non-empty category
  [Expand all] [Collapse all]                          ← rendered hidden, unhidden by JS
form.wpb-rules-form  (method=post, action=admin-post.php, nonce wp_bouncer_save, tab=rules)
  section.wpb-card.wpb-category#wpb-cat-<slug>  tabindex=-1  aria-labelledby=wpb-cat-<slug>-title
    h2#wpb-cat-<slug>-title  Category name
    p.description            One-line description
    p.wpb-cat-summary        "2 of 3 rules on" [· "1 needs attention"]
    div.wpb-rule#rule-<id>   tabindex=-1  role=group  aria-labelledby=rule-<id>-title   (one per rule)
      div.wpb-rule-head
        label.wpb-switch > input[type=checkbox][role=switch][name=wp_bouncer[rules][<id>][enabled]]
                           + span.wpb-slider[aria-hidden] + span.screen-reader-text "<Rule title>"
        div.wpb-rule-text
          h3#rule-<id>-title  Rule title
          span.wpb-state      "On" | "Off"   (text; JS adds " (not saved)" after a change)
          p.description       One-line description
          p.wpb-rule-flag     (only when flagged) "Needs attention: … <a>fix link</a>"  or  "Before switching on: …"
      details.wpb-rule-settings [open when flagged-attention or targeted by wpb_rule]
        summary  "Settings" + span.screen-reader-text ": <Rule title>"
        …the rule's existing inputs (partial views/rules/<id>.php, moved verbatim)
  div.wpb-savebar  (sticky at the bottom of the form)  submit_button() + span[aria-live=polite].wpb-unsaved
form#wpb-uploads-probe-form, form#wpb-uploads-sync-form   (unchanged, after the main form)
```

Rule row variants:

- **Country** (`#rule-country`): same head, but **no switch input**. It shows the state as text in the switch's place, then a summary ("Blocking 3 countries on the whole site", "Admitting only 2 countries on login pages", "No countries chosen"), the geo-database line, any flag, and a `button`-styled link "Configure on the Countries tab". It has no `<details>`. **It must not render any `wp_bouncer[rules][country][…]` input**, because the Rules tab doesn't own `rules.country`, so such an input would be silently ignored.
- **Third-party rule**: the same head, with no switch and no details. It shows the title (escaped), its id in `<code>`, "On" or "Off" from `is_enabled()`, and the line "Managed by the plugin that added it."

Order: categories in `RuleCatalog` order, with "Other" last and only if it isn't empty. Within a category, built-in rules follow the catalog order, then third-party rules in `wp_bouncer_rules` order.

| Category (slug) | Rules, in order | Description (one line) |
|---|---|---|
| Block lists (`block-lists`) | `ip_blocklist`, `country`, `user_agent` | Which visitors never get in. |
| Login and accounts (`login-accounts`) | `login_lockout`, `xmlrpc`, `user_enumeration` | Protecting sign-in and usernames. |
| Scanners and floods (`scanners-floods`) | `sensitive_files`, `not_found`, `rate_limit` | Temporary bans for probing and too many requests. |
| Attack payloads and hardening (`payloads-hardening`) | `waf`, `uploads_php` | Malicious request content and script uploads. |
| Other (`other`) | third-party rules with no known category | Rules added by other plugins. |

Slugs are **public and stable**: they appear in anchors and in the `wp_bouncer_rule_info` filter. Never rename them; change only the translated display names.

### 3.3 Default open/closed

Server-rendered (no JS needed, and no flash of content collapsing after load):

- Category sections are never collapsible.
- A rule's `<details>` is **closed** by default. It is rendered `open` when the rule has an **attention** flag, or when `wpb_rule=<id>` names it. `wpb_rule` is `sanitize_key()`'d and must be a built-in catalog id; otherwise it is ignored.
- With JS: the hash target is opened (§4), and panels the admin had open before saving are reopened from `sessionStorage` (§9.2).

**No-JS reading of acceptance criterion 6.** Every category and rule is visible: title, switch, state and warnings are always shown. Every setting can be reached and changed: `<details>` opens natively with a click or Enter/Space. Everything is saved, because closed panels still submit. The owner should confirm this reading (§12, question 3). The alternative, "everything open without JS", can't be done without a flash, because the server can't tell whether JS is running.

### 3.4 Keyboard and screen readers

- **Switch name (fix).** `AdminController::rule_switch( string $id, bool $checked, string $title = '' )`. The new optional fourth parameter (`$title`, after `$disabled`) keeps existing calls valid. The screen-reader text becomes the rule title (fallback: `__( 'Enabled' )` if `$title` is empty). The input gets `role="switch"`, so screen readers announce "IP blocklist, switch, on". The Countries tab passes "Country blocking". Fix the Traffic tab the same way ("Record traffic"); it is the same bug.
- Tab order per row: switch → (fix link, if any) → "Settings" summary → panel inputs when open. Reading order and visual order are the same.
- Headings: `h1` page → `h2` category → `h3` rule, and `h4` for any sub-heading inside a panel (none today). The Dashboard partial uses `h2` for its card and `h3` per category.
- The summary text is "Settings" plus hidden ": <title>", so a list of controls reads "Settings: IP blocklist". There are no interactive elements inside `<summary>`, and no heading inside it, because summary has an implicit button role that would flatten the heading.
- Status never relies on colour. State is text ("On"/"Off"). Flags start with a text prefix ("Needs attention:" or "Before switching on:") and a `dashicons-warning` / `dashicons-info` icon with `aria-hidden`.
- Focus: rule rows and category sections have `tabindex="-1"` so a deep link can move focus there. `:focus-visible` gets a visible outline. The switch keeps its existing focus ring.
- Announcements: expand and collapse are announced natively. "Unsaved changes" goes to a polite live region in the save bar. "Settings saved" is the existing admin notice after the redirect. Give `notice()` output `role="status"` for success and `role="alert"` for errors. That is a small, safe improvement.
- `invalid` events: number inputs have `min`/`max`. If an invalid value sits in a closed `<details>`, the browser can't focus it and the submit seems to do nothing. The JS opens the ancestor `<details>` on `invalid` (capture phase). Without JS, the admin had to open the panel to type the value in the first place, and the server clamps out-of-range values anyway.
- 200% zoom and narrow screens: the row head wraps (`flex-wrap`), the switch stays at the start, and the panel goes full width. The jump list wraps. At ≤782 px the sticky save bar becomes static (WordPress's mobile toolbar is tall).
- RTL: new CSS uses logical properties (`margin-inline-start`, `padding-inline`, `inset-inline-start`). The switch thumb's `translateX` is mirrored with `[dir=rtl]`. Change the existing `.wpb-indent` and `.wpb-inline` `margin-left`/`margin-right` to logical properties while there.
- Forced colours (Windows high contrast): `@media (forced-colors: active)` gives `.wpb-slider` a `1px solid CanvasText` border, the checked state `background: Highlight`, and badges a border. Otherwise the opacity-0 checkbox and background-only badges disappear.

---

## 4. Deep links

### 4.1 Anchors (kept and added)

| Anchor | Where | Behaviour |
|---|---|---|
| `#rule-<id>`, for every built-in id including `country` | Rules tab rule row | The row (title, switch, state) is outside `<details>`, so it is visible and the browser scrolls to it with or without JS. With JS: also opens its `<details>`, scrolls, focuses the row. |
| `#rule-<sanitised third-party id>` | Rules tab | Only if `sanitize_html_class( $id )` is non-empty and doesn't clash with another id. Otherwise the row has no anchor. |
| `#wpb-cat-<slug>` | Rules tab category section | Scroll and focus. Nothing to open. |
| `#wpb-alerts` | General tab (unchanged) | Still used by `AlertNotifier` `settings_url`. The generic JS hash handler also focuses it. Harmless. |

The JS hash handler (§9.1) is generic. It runs on page load and on `hashchange`, and also on clicks of same-page `a[href^="#"]` inside `.wp-bouncer`, because clicking the current hash fires no `hashchange`. It:

1. takes `decodeURIComponent( location.hash.slice( 1 ) )` and finds the element with `document.getElementById()` (never `querySelector( location.hash )`), and acts only if the element is inside `.wp-bouncer`
2. opens every ancestor `<details>`, and the row's own `.wpb-rule-settings` if the target is a `.wpb-rule`
3. calls `scrollIntoView( { block: 'start' } )`, accounting for the admin bar with CSS `scroll-margin-top: 46px` on `.wpb-rule, .wpb-category`, which also fixes the no-JS jump
4. calls `focus( { preventScroll: true } )`.

### 4.2 Links into the Rules tab

Add `AdminController::rule_url( string $id ): string`:

- built-in ids other than `country`: `self::url( 'rules', [ 'wpb_rule' => $id ] ) . '#rule-' . $id`
- `country`: `self::url( 'countries' )` (the settings live there). The Rules-tab card is reached as `self::url( 'rules' ) . '#rule-country'`.

Used by:

| Caller | Change |
|---|---|
| `notices()` uploads broken / write failed | The text "See Rules → No PHP in uploads." becomes a link "Go to No PHP in uploads" → `rule_url( 'uploads_php' )`. Keep the sentence before it **unchanged**: e2e greps "answered uploaded files (images too) with an error". |
| `notices()` country without geo DB | Keep the text. Add a link "Import one under Tools" → `url( 'tools' )`. The rule card on the Rules tab shows the same flag. |
| `notices()` proxy warning (optional, same pattern) | Link "General → Trusted proxies" → `url( 'general' ) . '#wpb-proxies'`. |
| `handle_uploads_probe`, `handle_uploads_sync` | Redirect to `rule_url( 'uploads_php' )` plus `wpb_msg`. `back()` takes an optional `array $args` and `string $fragment` (as built, see "As built"). A `rule-<id>` fragment for a built-in id also adds `wpb_rule=<id>`, so the row's settings open. The existing integration assertion `tab=rules` still passes. |
| Dashboard overview titles | `rule_url( $id )`. |

`notice()` becomes `notice( string $type, string $message, string $link_url = '', string $link_text = '' )`. It prints `esc_html( $message )`, then, if given, ` <a href="esc_url">esc_html</a>`. `wpb_msg` notices never get a link, so there's no new content-spoofing surface.

---

## 5. How a rule declares its category

### 5.1 Built-in rules: `Admin\RuleCatalog` (pure PHP)

```php
namespace WPBouncer\Admin;

final class RuleCatalog {
    public const OTHER = 'other';

    /** Display order of categories and of the built-in rules in each. The one place a built-in rule declares its category. */
    public const CATEGORIES = array(
        'block-lists'        => array( 'ip_blocklist', 'country', 'user_agent' ),
        'login-accounts'     => array( 'login_lockout', 'xmlrpc', 'user_enumeration' ),
        'scanners-floods'    => array( 'sensitive_files', 'not_found', 'rate_limit' ),
        'payloads-hardening' => array( 'waf', 'uploads_php' ),
    );

    /** Rules whose settings live on another tab (status card, no inputs on the Rules tab). */
    public const EXTERNAL = array( 'country' => 'countries' );

    /** @return string[] Category slugs in display order, OTHER last. */
    public static function slugs(): array;

    /** @return string[] Every built-in rule id in display order. */
    public static function builtin_ids(): array;

    /** Slug for a built-in id, or null. */
    public static function category_of( string $id ): ?string;

    /**
     * Clean third-party declarations: drop built-in ids (built-in metadata wins), drop ids not in
     * $registered (only rules that are actually in the chain are shown), coerce category to a known
     * slug or OTHER, strip tags from title, trim, cap at 80 chars, fall back to the id.
     *
     * @param mixed    $raw        Return value of the wp_bouncer_rule_info filter.
     * @param string[] $registered Ids returned by the rule chain that are not built-in.
     * @return array<string, array{category: string, title: string}>
     */
    public static function third_party( $raw, array $registered ): array;

    /**
     * @param array<string, array{category: string, title: string}> $third_party From third_party().
     * @return array<string, string[]> slug => rule ids, display order; empty categories removed except the four built-in ones.
     */
    public static function group( array $third_party ): array;
}
```

Use `strip_tags()` in pure PHP, then `esc_html()` at output.

Why it lives under `Admin\`: it is display metadata, not firewall behaviour. Keep it out of `Rules\` so nobody is tempted to use it in the hot path. Add it, and `RuleStatus`, to the "Decision core (pure)" row of the layers table in `documentation/architecture.md`.

Adding a built-in rule: add its id to `CATEGORIES` (the one place), its strings to `RuleLabels`, and its partial `views/rules/<id>.php`. Tests fail if any of these is missing (§10).

### 5.2 Third-party rules: `wp_bouncer_rule_info` filter

```php
/**
 * Describe rules added through wp_bouncer_rules so they appear in the admin overview.
 *
 * @param array<string, array{category?: string, title?: string}> $info Rule id => details. Empty by default.
 * @param string[]                                              $ids  Ids of non-built-in rules currently in the chain.
 */
$info = apply_filters( 'wp_bouncer_rule_info', array(), $ids );
```

Example for `adding-a-rule.md` (Option B):

```php
add_filter( 'wp_bouncer_rule_info', function ( array $info ) {
    $info['no_wp_json_for_bots'] = array(
        'category' => 'scanners-floods',          // block-lists | login-accounts | scanners-floods | payloads-hardening | other
        'title'    => __( 'Bots on the REST API', 'my-plugin' ),
    );
    return $info;
} );
```

Rules:
- The filter runs only when the admin overview is built (Rules and Dashboard tabs, and the notices on our screen). It never runs in the firewall path.
- A rule in the chain with no entry appears under "Other" with its id as title. This meets acceptance criterion 11's minimum: id and enabled state are visible.
- An entry for an id that isn't in the chain is ignored, so the screen shows nothing that doesn't run.
- An entry for a built-in id is ignored, so the built-in metadata can't be relabelled.
- Unknown keys are ignored. The array shape leaves room to add `description` or `settings_url` later without a breaking change.
- Third-party rules get **no switch and no stored settings** (owner deferral). `handle_toggle_rule` keeps rejecting ids that aren't in `Settings`.

### 5.3 Where the admin gets the third-party ids

`Plugin` gains `private ?array $rules = null` and:

```php
/** The rule chain for this request (built once). Used by the admin overview. @return RuleInterface[] */
public function registered_rules(): array { return $this->rules ??= $this->build_rules(); }   // ??= is PHP 7.4
```

`run_firewall()` changes `new Firewall( $this->build_rules(), …` to `new Firewall( $this->registered_rules(), …`, so on an admin request `wp_bouncer_rules` runs **once**, as today. `reload_settings()` resets `$this->rules = null`. When the firewall didn't run (`WP_BOUNCER_DISABLE`, WP-CLI), the admin builds the chain lazily. The cost in the hot path is one property assignment.

Third-party ids are the `id()` values of `registered_rules()` that aren't built-in (`RuleCatalog::builtin_ids()`), with duplicates dropped. Their on/off is `is_enabled()`. If `id()` or `is_enabled()` throws, catch `\Throwable` and show the rule under Other as "Unknown". A broken add-on must not white-screen our settings page.

### 5.4 Alternatives declined

| Alternative | Why not |
|---|---|
| Add `category()` / `title()` to `RuleInterface` | Breaks every existing third-party rule (fatal on load). Ruled out by the spec. |
| Optional interface (`DescribedRuleInterface`) | Ergonomic, but titles need `__()`, which rules must not call (they are pure and unit-tested without WordPress). It also needs an instance, and `uploads_php` has no rule instance. It could be **added later** without breaking anything; the filter stays the base mechanism. Not in v1, to keep one mechanism. |
| Category on the rule's settings array | Third-party rules have no settings in our option, and it would mix display data into stored data. |
| Let the filter add new categories | Not requested. It complicates anchors and ordering. Unknown slugs go to Other. Revisit with "per-category actions" if ever wanted. |

---

## 6. Status

### 6.1 `Admin\RuleStatus` (pure PHP)

```php
namespace WPBouncer\Admin;

final class RuleStatus {
    public const FLAG_ATTENTION = 'attention';   // on, but not (fully) working: warning style, opens the panel, counted
    public const FLAG_SETUP     = 'setup';       // off, and needs set-up before it is useful: neutral hint, not counted

    // Reason codes (stable; tests and the Dashboard widget may use them).
    public const NO_GEO_DB            = 'no_geo_db';            // existing notice condition
    public const UPLOADS_BROKEN       = 'uploads_broken';       // existing notice condition
    public const UPLOADS_WRITE_FAILED = 'uploads_write_failed'; // existing notice condition
    public const NO_COUNTRIES         = 'no_countries';         // new (in-page only): block mode, empty list: does nothing
    public const ALLOW_LIST_EMPTY     = 'allow_list_empty';     // new (in-page only): allow mode, empty list: CountryRule treats itself as off
    public const UPLOADS_UNPROTECTED  = 'uploads_unprotected';  // new (in-page only): last "Test now" said unprotected
    public const SETUP_COUNTRY        = 'setup_country';        // off, and no geo source yet
    public const SETUP_RATE_LIMIT     = 'setup_rate_limit';     // off (factory default): check the object-cache note before switching on

    /**
     * @param array{
     *   rules: array<string, array<string, mixed>>,   // Settings::to_array()['rules']
     *   geo_rows: int,                                  // wp_bouncer_geo_meta['rows'] ?? 0
     *   geo_source: string,                             // settings geo_source
     *   disabled: bool,                                 // Plugin::is_disabled()
     *   uploads_state: array<string, mixed>|null,       // get_option( UploadsGuard::STATE_OPTION ) if array
     *   uploads_probe: string|null                      // get_option( UploadsGuard::PROBE_OPTION )['result'] if set
     * } $facts
     * @return array<string, array{on: bool, flag: string|null, reasons: string[]}>  for every built-in id
     */
    public static function builtin( array $facts ): array;

    /**
     * @param array<string, string[]>                          $groups   RuleCatalog::group()
     * @param array<string, array{on: bool, flag: string|null}> $statuses Built-in plus third-party (third-party: flag null)
     * @return array<string, array{on: int, total: int, attention: int}>
     */
    public static function summarise( array $groups, array $statuses ): array;

    /** @return array{on: int, total: int, attention: int} Whole-plugin totals (for the WPB-4 widget's status line). */
    public static function totals( array $groups, array $statuses ): array;
}
```

Conditions. These copy today's `notices()` logic exactly. The new ones are marked.

| Rule | Condition | Result |
|---|---|---|
| `country` | enabled and `geo_rows === 0` and `geo_source !== 'header'` | attention, `NO_GEO_DB` (fix: Tools) |
| `country` | enabled, `countries` empty, mode `block` | attention, `NO_COUNTRIES` (fix: Countries) **new** |
| `country` | enabled, `countries` empty, mode `allow` | attention, `ALLOW_LIST_EMPTY` (fix: Countries) **new** |
| `country` | off and no geo source (same test as `NO_GEO_DB`) | setup, `SETUP_COUNTRY` (link: Tools) |
| `uploads_php` | `wants = ! disabled && enabled && htaccess`; `wants && is_broken` (`uploads_state['broken']`) | attention, `UPLOADS_BROKEN` |
| `uploads_php` | else `wants && is_array(uploads_state) && empty(uploads_state['ok'])` | attention, `UPLOADS_WRITE_FAILED` |
| `uploads_php` | `enabled && uploads_probe === 'unprotected'` | attention, `UPLOADS_UNPROTECTED` **new** |
| `rate_limit` | off | setup, `SETUP_RATE_LIMIT` (link: its own panel) |
| any | otherwise | `on` = `! empty( enabled )`, no flag |

`on` is the **saved** `enabled` flag, the same value the Dashboard toggle flips. "N of M rules on" counts `on` over all rules in the category, including the country card and third-party rules (their `is_enabled()`). A flag with any attention reason is `attention`, so the category gets "1 needs attention".

### 6.2 One source of truth for notices

`notices()` gets the statuses from the shared assembler (§7.2). It emits the three **existing** notices from `NO_GEO_DB`, `UPLOADS_BROKEN` and `UPLOADS_WRITE_FAILED`, with the same text and type as today, plus the links from §4.2. The three **new** reasons show only in the page (Rules card, Dashboard overview), not as screen-wide notices. Showing them everywhere would add noise. Owner question 2.

### 6.3 Text

`Admin\RuleLabels` (WordPress-facing, i18n) owns every string:

- `rules(): array<id, array{0: title, 1: description}>`: moved from `AdminController::rule_labels()`. That method stays as a one-line delegate for backward compatibility, since it is `public static` and the log uses it.
- `categories(): array<slug, array{0: name, 1: description}>`, including `other`.
- `reason( string $code ): array{0: text, 1: link_text, 2: link_url}`.
- `summary( int $on, int $total, int $attention ): string`:
  ```php
  /* translators: 1: rules switched on, 2: rules in this category. */
  _n( '%1$s of %2$s rule on', '%1$s of %2$s rules on', $total, 'wp-bouncer' )
  /* translators: %s: number of rules that need attention. */
  _n( '%s needs attention', '%s need attention', $attention, 'wp-bouncer' )
  ```
  Numbers go through `number_format_i18n()`.
- `country_summary( array $rule ): string`, with `_n()` on the count and separate full sentences for block/allow × site/login (no string concatenation).

The sentences with inline number inputs (login lockout, sensitive files, 404 flood, rate limit) are **moved verbatim** into the partials. The msgids don't change, so existing translations keep working.

---

## 7. Dashboard tab and the shared overview

### 7.1 Decision

Replace the Dashboard's flat "Rules" table with `partials/rule-overview.php`. It is a card titled "Rules". Each category gets an `h3` with its summary line, then a table of its rules: title (linked via `rule_url()`), state badge ("On"/"Off", text), flag text if any, and the **existing Turn on/off form** (`wp_bouncer_toggle_rule`, unchanged handler, nonce, POST). Third-party rows get no button. The country row keeps its button, as today.

Why keep the buttons: acceptance criterion 6 requires the Dashboard toggles to keep working, they are POST-only and nonce-protected, and the handler changes one key only. Why not "reduce to a link": the Dashboard is the at-a-glance screen and the WPB-4 widget will want the same totals. Both screens and the widget read **one** structure (§7.2), so they can't disagree.

### 7.2 `Admin\RuleOverview` (WordPress-facing assembler)

```php
final class RuleOverview {
    public function __construct( Plugin $plugin );
    /** Memoised per request: notices() and the view share it. */
    public function categories(): array; // list of array{slug, title, description, on, total, attention, rules: list<array{
                                         //   id, title, description, builtin: bool, external_tab: ?string,
                                         //   on: bool, flag: ?string, reasons: list<array{text, link_text, link_url}>,
                                         //   url: string, anchor: ?string }>}
    public function statuses(): array;   // id => RuleStatus row (for notices())
}
```

It gathers the facts (one `get_option` each for geo meta, uploads state and probe; all already read on this screen today), asks `registered_rules()` for the third-party ids, applies `wp_bouncer_rule_info`, then calls `RuleCatalog` and `RuleStatus`. `AdminController` holds one instance. `render()` passes `$overview` to the `rules` and `dashboard` views. There is no extra cost on other tabs, except `notices()`, which needs only `statuses()`. That needs no third-party discovery, so `statuses()` skips `registered_rules()`.

---

## 8. Files

### 8.1 Add

| File | Kind | Purpose |
|---|---|---|
| `src/Admin/RuleCatalog.php` | pure | Categories, membership, third-party normalisation, grouping |
| `src/Admin/RuleStatus.php` | pure | State, flags, reason codes, summaries, totals |
| `src/Admin/RuleLabels.php` | WordPress (i18n) | All titles, descriptions, category names, reason and summary text |
| `src/Admin/RuleOverview.php` | WordPress (assembler) | Facts → catalog → status → view model; runs `wp_bouncer_rule_info` |
| `src/Admin/views/partials/rule-category.php` | view | One category section |
| `src/Admin/views/partials/rule-row.php` | view | Row head (switch, title, state, flags) and `<details>` that includes the rule partial |
| `src/Admin/views/partials/rule-flags.php` | view | Flag lines with fix links (used by the row and the overview) |
| `src/Admin/views/partials/rule-overview.php` | view | Dashboard grouped table |
| `src/Admin/views/rules/<id>.php`, one each for `ip_blocklist`, `user_agent`, `xmlrpc`, `login_lockout`, `rate_limit`, `waf`, `user_enumeration`, `sensitive_files`, `not_found`, `uploads_php` | view | The panel contents, **moved verbatim** from today's `rules.php` (without the `$heading()` call) |
| `src/Admin/views/rules/country.php` | view | Country status card body (no inputs) |
| `tests/Unit/Admin/RuleCatalogTest.php`, `tests/Unit/Admin/RuleStatusTest.php` | tests | §10 |
| `tests/Support/FormFields.php` | test helper (pure, `DOMDocument`) | "What a browser would submit" from HTML: successful controls of a form, by HTML rules (checked checkboxes and radios only, textareas, selects, inputs, `form=` attribute honoured, `disabled` excluded). Used by integration tests and the e2e suite |
| `tests/Integration/Admin/RulesTabTest.php` | tests | §10 |

Partial includes: `rule-row.php` includes `__DIR__ . '/../rules/' . $id . '.php'` **only** for ids in `RuleCatalog::builtin_ids()`. A third-party id never reaches a file path.

### 8.2 Change

| File | Change |
|---|---|
| `src/Admin/views/rules.php` | Rebuilt: jump list, one form, loop over `$overview` categories, sticky save bar, uploads probe/sync forms unchanged after the form. The trailing "configured on the Countries tab" line is removed (replaced by the card). |
| `src/Admin/views/dashboard.php` | Rules card replaced by `partials/rule-overview.php`. Stats and the other cards are unchanged. |
| `src/Admin/views/countries.php` | `rule_switch( 'country', …, __( 'Country blocking' ) )`. Optional back link "See all rules" → `url('rules') . '#rule-country'`. |
| `src/Admin/views/traffic.php` | Switch screen-reader text "Record traffic", plus `role="switch"`. |
| `src/Admin/AdminController.php` | `rule_labels()` delegates to `RuleLabels::rules()`. `rule_switch()` gets the optional fourth parameter `$title` and `role="switch"`. New `rule_url()`. `notice()` gets an optional link and a role. `notices()` uses `RuleOverview::statuses()`. `back()` gets optional args and fragment. Probe/sync redirects go to `rule_url( 'uploads_php' )`. `render()` passes `$overview`. `enqueue_assets()` adds i18n strings (`notSaved`, `unsaved`, `expandAll`, `collapseAll`). |
| `src/Plugin.php` | `registered_rules()` memo; `run_firewall()` uses it; `reload_settings()` resets it. |
| `assets/admin.css` | §9.3 |
| `assets/admin.js` | §9.1, 9.2 |
| `src/Settings.php` | **No change.** |
| Docs (docs-writer) | `documentation/adding-a-rule.md` (Option A step 4: catalog + labels + partial; Option B: `wp_bouncer_rule_info`), `rules.md` (categories), `architecture.md` (layers table, Extending), `README.md`, `readme.txt`, `CHANGELOG.md`, screenshots |

---

## 9. JavaScript and CSS (no build step, no dependencies)

### 9.1 JS: the generic part (every Bouncer tab)

ES5 style, inside the existing IIFE, like the current file.

- `reveal( id )` as in §4.1. It runs on load, on `hashchange`, and on clicks of same-page hash links inside `.wp-bouncer`.
- `invalid` listener (capture) on `document` limited to `.wp-bouncer form`: opens ancestor `<details>`.

### 9.2 JS: the Rules tab (`form.wpb-rules-form` present)

- **Live state text:** on `change` of a `.wpb-switch input`, set the row's `.wpb-state` to "On"/"Off" plus " (not saved)" if it differs from its `data-saved` value. Then set the save bar's live region to "You have unsaved changes." once. Use `textContent` only.
- **Expand/Collapse all:** unhide the two buttons in the jump list and toggle `open` on every `.wpb-rule-settings`.
- **Keep open panels across a save:** on `submit`, store the ids of open `.wpb-rule-settings` rows in `sessionStorage['wpbRulesOpen']`. On load, reopen them (each looked up with `getElementById`, ignored if missing) and clear the key. Wrap it in `try` (storage can be disabled). No server change.
- No `beforeunload` prompt (intrusive). No client-side filtering in v1. If one is added later, it must hide with the `hidden` attribute, **never `disabled`**.

### 9.3 CSS

- `.wpb-cat-nav` (wrapping inline list), `.wpb-category` (the existing `.wpb-card`), `.wpb-rule` rows separated by `border-block-start`, `.wpb-rule-head` (existing, add `flex-wrap: wrap`), `.wpb-state`, `.wpb-rule-flag` plus `.is-attention` (warning left border and icon) and `.is-setup` (neutral), `.wpb-rule-settings > summary` (button-like, `cursor: pointer`, visible focus), `.wpb-savebar { position: sticky; bottom: 0; }` with a top border and white background.
- `scroll-margin-top: 46px` on `.wpb-rule, .wpb-category, #wpb-alerts`. `:focus-visible` outline on `[tabindex="-1"]` targets.
- RTL logical properties, the `forced-colors` block and the ≤782 px rules from §3.4.
- Expected size: about 80 lines of CSS and about 90 lines of JS. Both stay enqueued only on our screen (unchanged).

---

## 10. Tests

### 10.1 Unit (pure, < 1 s; `tests/Unit/Admin/`)

`RuleCatalogTest`
- Every id in `Settings::defaults()['rules']` is in `CATEGORIES` exactly once, and `CATEGORIES` has no id that isn't in the defaults (acceptance criterion 12).
- The four slugs are in owner order, `OTHER` comes last, and the slugs match `/^[a-z-]+$/`.
- `third_party()`: unknown or missing category → `other`; title stripped, trimmed, capped at 80 characters, falls back to the id; built-in ids dropped; ids not in `$registered` dropped; non-array input → `[]`; `<script>` in a title doesn't survive.
- `group()`: a 12th rule (a fixture third-party rule declared in `login-accounts`) appears after the built-ins with no other change (acceptance criterion 9); undeclared rules go to `other`; `other` is omitted when empty.

`RuleStatusTest`: one case per row of the §6.1 table, and the negatives (country on with a header source → no `NO_GEO_DB`; `disabled` → no uploads reasons; probe `protected` → no flag). Also `summarise()`/`totals()` counts, and "setup flags are not counted as attention".

`SettingsTest` (add one test): the rule ids in `TAB_FIELDS['rules']` ∪ `TAB_FIELDS['countries']` equal the defaults' rule ids, and each id is owned by exactly one tab. This pins the save contract this design relies on.

### 10.2 Integration (`tests/Integration/Admin/RulesTabTest.php`, `WP_UnitTestCase`)

1. **Round-trip, defaults:** render the Rules tab, take `FormFields::of( $html, 'form.wpb-rules-form' )`, set it as `$_POST`, `handle_save` → the stored settings `===` the settings before the save.
2. **Round-trip, non-defaults:** set a fixture that flips every boolean and fills every list for all 11 rules, then do the same as test 1. This catches a partial that forgets to render an input, or renders it with the wrong name.
3. **One change only:** as test 2, but change `rules[waf][xss]` before posting. Only that key differs (array diff of the whole option).
4. **Completeness:** every rule id in `TAB_FIELDS['rules']` has an `enabled` input in the form; no form control has `disabled`; there is no `wp_bouncer[rules][country]` input on the Rules tab.
5. **Markup:** `id="rule-<id>"` exists for all 11 built-ins, and `id="wpb-cat-<slug>"` for the 4 categories; each switch's accessible name is the rule title (the screen-reader text in its `label`, plus `role="switch"`); headings go h2 → h3.
6. **Default open:** no panel is `open` by default; with `wpb_rule=waf` only the waf panel is `open`; `wpb_rule=../x` or an unknown id → none.
7. **Flags:** country on with no geo DB → the card shows "Needs attention" with a Tools link, the panel is open, and the category summary says 1 needs attention. Uploads broken → same, for `uploads_php`.
8. **Third-party:** with a `wp_bouncer_rules` fixture rule and a `wp_bouncer_rule_info` entry `{category: 'login-accounts', title: '<b>X</b>'}`: it appears in that category, the title is escaped (no `<b>`), there is no switch input for it, and the round-trip (test 1) still passes. Without an info entry it appears under Other with its id. A rule whose `is_enabled()` throws renders as "Unknown" and the page renders.
9. **Dashboard:** the overview groups by the same categories; the toggle forms still post `wp_bouncer_toggle_rule`; the existing `test_toggle_rule_*` tests pass unchanged; the On/Off states match the Rules tab for the same settings.
10. **Notices:** the uploads notices contain `href=…tab=rules…wpb_rule=uploads_php…#rule-uploads_php`; the country notice keeps "no geo database is loaded" (the existing test is unchanged).
11. **Redirects:** probe/sync redirect `Location` contains `tab=rules` (existing assertion) and `#rule-uploads_php`.
12. **Filter called once:** on a request where `run_firewall()` ran, rendering the Rules tab doesn't call `wp_bouncer_rules` again (count with a test filter).
13. Existing tests stay as they are: `AdminScreensTest::test_every_tab_renders_for_an_administrator`, `AdminControllerTest` save/lockout/toggle/probe/sync/labels tests (including `rule_title( 'custom_rule' ) === 'custom_rule'`).

### 10.3 e2e (`tests/e2e/run.sh`)

**Existing checks that touch the Rules tab.** They must keep passing; markup constraints follow from them.

| Line(s) | Check | Constraint on the new markup |
|---|---|---|
| 364–369 | every tab, including `rules` and `dashboard`, loads 200 with no PHP warnings | none |
| 474–477 (`probe()`) and 511, 515 | `nonce_for wp_bouncer_uploads_probe rules` / `…_sync rules`: a regex finds `name="_wpnonce" value="…"` followed, with no other `_wpnonce` in between, by `name="action" value="wp_bouncer_uploads_probe"` | Keep the probe and sync forms as separate forms whose `wp_nonce_field()` comes right before the `action` hidden input (as today). Don't move them into a partial that reorders those fields. |
| 478, 490, 512, 517 | probe results via those forms | handler unchanged |
| 482–484 | Rules tab: `count_in 'in place.'` = **1** and `'Protected: the server refused'` = **1** (counts *lines*) | The overview, flags and the Dashboard partial must **not** repeat the `.htaccess` status phrase "in place." or the probe message on the Rules tab. Only the uploads panel prints them. |
| 508–509 | Rules tab shows the notice "answered uploaded files (images too) with an error" (count 1) | Keep that notice sentence exactly; the `UPLOADS_BROKEN` flag text on the card must use different wording. |
| 518 | after the fix, that phrase count = 0 | same |
| 611–612 | Dashboard loads 200 | none |

**New checks** (in a "Rules tab" block after "Admin screens"):
- Round-trip: save the option JSON, fetch the Rules tab, build the POST with `php tests/Support/FormFields.php <html> form.wpb-rules-form` (the helper has a small CLI entry point), POST to `admin-post.php`, compare the option JSON → equal. This doubles as the no-JS check: curl runs no JavaScript and posts closed panels.
- One change: set `waf.xss` off in the scraped fields → only that key differs.
- Anchors: `id="rule-<id>"` count 1 for each of the 11 ids; `id="wpb-cat-…"` for the 4 categories.
- `?tab=rules&wpb_rule=uploads_php` → that panel's `<details` has `open`.
- Uploads-broken notice includes `#rule-uploads_php`.
- Dashboard contains the 4 category names and still toggles a rule (POST `wp_bouncer_toggle_rule` for `xmlrpc`, check the option, then toggle it back).

**Not covered automatically:** the JS behaviours (hash opening and focus, `invalid` opening, sessionStorage reopen, unsaved text). There is no browser in the suite and adding one breaks the no-dependency rule. Manual checklist for the tester: Chrome, Firefox, Safari; keyboard only; NVDA or VoiceOver pass; 200% zoom; 782 px; RTL (switch the site language to Arabic or Hebrew, or use the RTL Tester plugin); Windows high contrast or `forced-colors` emulation in DevTools. Recommend a Playwright job later as a dev-only CI step (owner question 6).

### 10.4 Static analysis

PHPStan array shapes on `RuleStatus::builtin()` facts and the `RuleOverview` view model (level 6, per WPB-1). phpcs: the views keep the `WordPress.Security.EscapeOutput` discipline; the inline-input sentences keep their existing justified ignores.

---

## 11. Security

`documentation/security/` doesn't exist yet (WPB-3 is planned), so there is no security-blue guidance to adopt or decline. The considerations below are mine. Add this design to the WPB-3 delta-audit scope (backlog WPB-3 criterion 8), and ask security-blue to review §5 and §11 before development if the threat model exists by then.

| Topic | Design |
|---|---|
| Capability and nonces | No new handlers. `handle_save` and `handle_toggle_rule` keep `guard()` (`manage_options` + `check_admin_referer`). Views render only after `render()`'s capability check. The overview is built only on our screen for users with `manage_options`. |
| Saving | No change to `apply_form()`/`sanitize()`; the allow-list stays the only path into the option. Third-party rules can't write settings (no inputs; `sanitize()` drops unknown keys anyway). The self-lockout guard is unchanged. |
| Third-party titles and ids | Treated as untrusted text: tags stripped and length capped in `RuleCatalog::third_party()`, `esc_html()` at output, ids printed with `esc_html()` in `<code>`, anchors from `sanitize_html_class()` with clash checks. Ids **never** reach an include path; partials are chosen only from the built-in catalog. |
| `wpb_rule` query arg | `sanitize_key()`, then must be a built-in catalog id. Its only effect is adding `open` to one `<details>`. |
| Notice links | URLs built by `AdminController::url()`/`rule_url()`, output with `esc_url()`. `wpb_msg` notices stay plain escaped text with no link. |
| JS | Hash looked up with `getElementById()` (not used as a selector), limited to `.wp-bouncer`. DOM updates via `textContent` only. `sessionStorage` holds element ids only and is validated on read. No new AJAX. |
| Broken add-ons | `id()`/`is_enabled()` calls in the overview are wrapped in `try/catch (\Throwable)`, so a faulty third-party rule can't make the settings screen unusable (availability of the admin's way to fix things). |
| Filter running in admin | `wp_bouncer_rule_info` runs only on our screen. `wp_bouncer_rules` doesn't run an extra time (§5.3). |

---

## 12. Risks, compatibility and open questions

### 12.1 Risks

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| A partial forgets an input, or renames it, so saving switches a rule off or resets a value | Medium / **high** (silent loss of protection) | Partials are moved verbatim. Round-trip tests with defaults and with a full non-default fixture (integration and e2e). Completeness test of `enabled` inputs. Unit test of `TAB_FIELDS` ownership. |
| Someone later "optimises" by not rendering closed panels, or by disabling hidden inputs | Low / high | A comment in `rules.php` and `rule-row.php` explaining the contract; the completeness test (no `disabled`, all names present). |
| Someone puts a country input on the Rules tab (it would be ignored) | Low / medium (confusing) | The test asserts there is no `wp_bouncer[rules][country]` input on the Rules tab. |
| An invalid number in a closed panel blocks submit with no visible reason | Low / medium | The `invalid` handler opens the panel. The server clamps anyway. |
| e2e line counts break because a status phrase is repeated | Medium / low | §10.3 constraints listed for the developer. |
| Third-party filter callbacks with side effects or slow code on our screen | Low / low | Runs once per page view on our screen only. Documented as "keep it cheap and side-effect free". |
| Browsers that auto-open `<details>` on find-in-page differ | Low / none | Progressive behaviour only. |
| WPB-4 (widget) ships first and invents its own "rules on" count | Medium / medium (two definitions) | Build `RuleCatalog` + `RuleStatus` as **slice 1** and let WPB-4 use `RuleStatus::totals()`. These two classes can ship in 1.2.0 even if the UI slips to 1.3.0. |

### 12.2 Compatibility

- **Minimums (WPB-5):** PHP 8.3 and WordPress 7.0. The earlier PHP 7.4 / WP 5.8 limits (no enums, `match`, `readonly`, named arguments or `str_contains`) no longer apply. `<details>`, `role="switch"`, `scroll-margin`, `:focus-visible`, `forced-colors` and logical properties are all supported by the browsers WordPress 7.0 supports. In older browsers the extra CSS degrades gracefully.
- **Settings:** the structure of `wp_bouncer_settings` is unchanged; no migration and no `DB_VERSION` bump. Upgrade shows the same values. **Downgrade to 1.1.x:** nothing new is stored. `sessionStorage` is client-side and short-lived. The `wpb_rule` arg in old links is ignored by 1.1.x.
- **Public PHP API:** `AdminController::rule_labels()` keeps its shape. `rule_switch()` and `notice()` only gain optional parameters. `RuleInterface`, `AbstractRule` and `wp_bouncer_rules` are unchanged. New: `wp_bouncer_rule_info` filter, `Plugin::registered_rules()`, `AdminController::rule_url()`.
- **Anchors and links:** every `#rule-<id>` that existed still exists, `#rule-country` is new, and `#wpb-alerts` is unchanged.
- **Multisite:** per-site settings and screens as today. Network activation adds no network screen. **Uninstall:** nothing new to remove.
- **Performance:** the Rules tab makes no queries beyond today's option reads (all autoloaded except geo meta, which this screen already reads). It makes no log-table queries and no remote calls. Status is O(rules). Firewall hot path: one property assignment.

### 12.3 Delivery slices (for the developer)

1. `RuleCatalog`, `RuleStatus`, `RuleLabels` (+ `rule_labels()` delegate), `RuleOverview`, `Plugin::registered_rules()`. Unit tests. `notices()` moved onto statuses, with links. No visible change apart from the links.
2. Partials (verbatim move), new `rules.php`, switch names (Rules, Countries, Traffic), CSS. Integration round-trip and markup tests. e2e additions.
3. JS (§9.1, 9.2) and the manual accessibility checklist.
4. Dashboard overview partial and its tests.
5. `wp_bouncer_rule_info`, third-party rows and tests, docs (docs-writer).

### 12.4 Owner decisions

All seven recommendations below were accepted by the owner on 2026-10-23; see [ADR 001](../adr/001-rules-tab-categories.md).

1. **Rate limiting "off" status.** The spec lists "rate limiting off by default" among rules needing set-up. I show it as a neutral **"Before switching on"** hint (not a warning, not counted in "needs attention"). Off is a valid, recommended choice on sites without an object cache, and a permanent warning would train admins to ignore warnings. Agree?
2. **Three new attention conditions** (country on with an empty list in block mode or allow mode, and uploads "Test now" last said unprotected): shown on the Rules card and Dashboard overview only, **not** as screen-wide notices. Agree, or should they also be notices?
3. **No-JS reading:** rule titles, switches, states and warnings are always visible. Settings are behind a native `<details>` that works without JS (§3.3). Acceptable, or must every panel be expanded without JS (which means everything is expanded for JS users too, with no collapsing on load)?
4. **Dashboard:** replace the flat table with the grouped overview and **keep** the Turn on/off buttons (recommended). The alternative is to reduce it to a link to the Rules tab.
5. **Category slugs** (`block-lists`, `login-accounts`, `scanners-floods`, `payloads-hardening`, `other`) become a public, permanent API (anchors, filter values). OK as named?
6. **Browser tests:** accept a manual checklist for the JS and accessibility behaviours in 1.2.0, with a dev-only Playwright job as a later chore?
7. (Small, optional) Should the Activity Log show a third-party rule's declared title instead of its id? It's a cheap follow-up, not in v1.

---

## 13. ADR draft (for `documentation/adr/`)

**ADR: Rules tab grouped into categories on one form.** *Context:* 11 rules on one long page, and the `apply_form()` contract that a rule missing from the POST is switched off. *Decision:* one page, one form, always-expanded category sections, per-rule native `<details>` for settings, all inputs always submitted, `TAB_FIELDS` unchanged; categories declared in `Admin\RuleCatalog` for built-ins and through the `wp_bouncer_rule_info` filter for third parties, with "Other" as the fallback; status computed once in `Admin\RuleStatus` and shared by notices, the Rules tab, the Dashboard and the WPB-4 widget. *Consequences:* no settings migration and downgrade-safe; a round-trip test is the guard against accidental switch-offs; sub-tabs and per-rule screens are ruled out unless `TAB_FIELDS` is split per rule in a future ADR.
