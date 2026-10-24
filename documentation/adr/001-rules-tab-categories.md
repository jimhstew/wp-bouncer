# ADR 001: Rules tab grouped into categories on one form

- Status: Accepted (2026-10-23)
- Backlog: WPB-2. Design: [architecture/rules-ui.md](../architecture/rules-ui.md)

## Context

The Rules tab lists 11 rules on one long page, which is hard to scan and won't scale as rules are added. `Settings::apply_form()` replaces every key the tab owns, so a rule whose inputs are missing from the POST is switched off. Any layout that hides rules from the form (sub-tabs, per-rule screens, unrendered panels) would silently switch rules off when another part is saved.

## Decision

- One page, one form. Four always-expanded category sections (Block lists; Login and accounts; Scanners and floods; Attack payloads and hardening), plus "Other" when a third-party rule needs it. Each rule keeps its own switch; there are no category-level switches.
- Rule settings sit in a native `<details>` under each rule row. All inputs are always rendered and submitted; nothing is `disabled`. `TAB_FIELDS` and `apply_form()` are unchanged.
- Built-in categories are declared in `Admin\RuleCatalog`; third-party rules declare category and title through the `wp_bouncer_rule_info` filter, falling back to "Other". `RuleInterface` is unchanged.
- Status is computed once in `Admin\RuleStatus` and shared by the admin notices, the Rules tab, the Dashboard tab overview and the WPB-4 Dashboard widget.

## Owner decisions

1. Rate limiting being off shows as a neutral "Before switching on" hint, not a warning, and is not counted as needing attention.
2. The three new attention states (country blocking on with no countries chosen in block or allow mode; the last uploads test said "not protected") appear on the Rules tab and Dashboard overview only, not as screen-wide notices.
3. Without JavaScript, settings sit in panels that open with one click (native `<details>`); titles, switches, states and warnings are always visible.
4. The Dashboard tab's flat rules table is replaced by the shared grouped overview, keeping its Turn on/off buttons.
5. Category slugs `block-lists`, `login-accounts`, `scanners-floods`, `payloads-hardening` and `other` are a permanent public API (anchors and filter values).
6. JavaScript and accessibility behaviour is checked with a manual checklist for 1.2.0; an automated browser-test job (Playwright, development only) is a later chore.
7. Showing a third-party rule's declared title in the Activity Log is a later follow-up, not part of this change.

## Consequences

- No settings migration; downgrade to 1.1.x is safe.
- A render-save round-trip test (integration and e2e) guards against accidental switch-offs.
- Sub-tabs and per-rule screens are ruled out unless a future ADR splits `TAB_FIELDS` per rule.
- The design is included in the WPB-3 delta security audit before 1.2.0.
