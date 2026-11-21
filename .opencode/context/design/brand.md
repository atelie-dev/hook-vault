# hook-vault — brand & design context

Status: **approved by the user, 2026-11-21** (direction, theme mechanism, scope, token set).
Any change to the values below goes through a new approved decision recorded here.

## Source material (facts, verified 2026-11-21)

- No logo, no brand guide, no font files: the de facto brand was the `:root` block of
  `internal/webui/static/app.css`. Identity = the `hook-vault` wordmark + accent blue
  `#6ea8fe` on a cool dark gray.
- Baseline screenshots (dev panel 127.0.0.1:8081, seeded endpoints): `/tmp/opencode/baseline/`
  — `login-1280.png`, `endpoints-1280.png`, `create-1280.png`, `endpoints-375.png`, `create-375.png`.
- Typography: system stacks only. **Non-negotiable: zero font bytes in the binary.**
- Verified baseline defects (fixed in the 2026-11-21 revamp unless noted):
  - `.row > * { flex: 1 1 200px }` inflated the "New endpoint" button into a full-width bar.
  - Keygen radio pair rendered broken (radios inherited `input { width: 100% }`).
  - Endpoints table overflowed the 375px viewport; no horizontal-scroll wrapper.
  - Policy cell rendered `90dno cap` (template `if` glue).
  - Status badges near-invisible (no tint, muted-on-muted).
  - Login card left-aligned; logout form posted to a `GET`-only route (405 — broken logout).

## Approved decisions (2026-11-21)

1. **Direction — "refined technical console"** (GitHub/Linear-like): sans for reading,
   mono for data (slugs, kids, counts, bytes), tinted status badges, tabular numerals,
   visible focus states. Keeps system fonts.
2. **Theme** — light is the CSS default; dark applies via `prefers-color-scheme` or a
   manual `data-theme="dark|light"` on `<html>` (header toggle, `localStorage["hv-theme"]`,
   applied pre-paint by a small head script). `color-scheme` follows the active theme.
   The manual choice wins over the system. The two dark blocks in `app.css` are
   deliberately duplicated (no build step) and MUST be kept identical.
3. **Scope** — revamp of the 3 existing screens, no new panel routes. A per-endpoint
   detail page (the API already exposes GET/PATCH/keys/stats) is an **open decision,
   deferred**.
4. **Endpoint list = cards, not a table** (user choice, 2026-11-21, on side-by-side
   mockups): few endpoints, many attributes each; the ingest URL is the primary copy
   target and gets a dedicated row; 375px must not scroll sideways. Stats stay
   scannable via a fixed label/value grid inside each card (tabular numerals).
5. **Token set** — see `app.css`; rationale per token:

| Token | Dark | Light | Rationale |
|---|---|---|---|
| `--bg` | `#0b0e14` | `#f6f8fa` | darker base lifts panels in dark; cool gray in light |
| `--panel` | `#12161f` | `#ffffff` | card/table surface |
| `--panel-2` | `#1a2130` | `#eef1f6` | inputs, chips, secondary surfaces |
| `--input-bg` | `#0b0e14` | `#ffffff` | editable surfaces — recessed well no escuro, campo nítido sobre cartão branco (critic 2026-11-21); chips/`.ingest` seguem em `--panel-2` |
| `--line` | `#242d3d` | `#d7dde6` | borders in the same cool hue |
| `--text` | `#e7ecf5` | `#17202e` | body text, AA with margin in both themes |
| `--muted` | `#98a2b3` | `#5b6675` | secondary text: 7.1:1 on dark panel, 5.8:1 on white |
| `--accent` | `#6ea8fe` | `#0969da` | dark keeps the existing brand hue; light needs AA on white (5.2:1) |
| `--on-accent` | `#0b1020` | `#ffffff` | replaces the only color literal outside `:root` (primary button) |
| `--ok` | `#7bd88f` | `#1a7f37` | AA green in light |
| `--warn` | `#f0b357` | `#9a6700` | AA amber in light |
| `--err` | `#ef6b6b` | `#cf222e` | AA red in light |
| `--radius`/`--radius-sm` | `8px`/`6px` | same | single radius scale |
| `--focus-ring` | `color-mix(accent 30%)` | same | keyboard focus visible in both themes |

   Contrast pairs computed 2026-11-21 (WCAG AA 4.5:1): all body/secondary pairs above
   pass; accent-on-white and white-on-accent are 5.2:1.

## Verification notes (how to screenshot this panel)

- The dev server serves embedded assets — any change to `internal/webui/static/` or
  `templates/` requires a **rebuild + restart** to show up.
- Desktop captures: 1280×900. To pin a theme, set `data-theme` on `<html>` (dark and
  light blocks are identical, so both are representative); the OS preference of the
  dev machine is **light**, so a capture with no override shows the light theme.
- True 375px mobile captures: `resize_page` clamps at ~500px window width and the CDP
  viewport override applies unreliably across navigations in this environment. What
  worked (2026-11-21): inject a real `<iframe style="width:375px;height:812px">` into
  a loaded page, point it at the panel URL, and screenshot the iframe element — an
  iframe has its own layout viewport. Watch for the grid/flex `min-width: 0` trap:
  without it the ingest URL (long, unbreakable) blows the 375px viewport open.

6. **Max stored size input** — number + unit picker (bytes/KiB/MiB/GiB, default
   1 GiB) in the create form; the unit multiplies into `max_bytes` on the wire, so
   API and DB keep storing bytes. The list humanizes with the `bytes` template func,
   independent of the unit the user picked (2026-11-21).

## Non-negotiables (from AGENTS.md / technical-domain.md, verified current)

- Hand-rolled CSS, **no framework, no build step** (`app.css` header contract; embedded
  via `go:embed`). New static assets must be `git add`-ed before `nix build`.
- Panel never receives key material (invariant 8); no user accounts (7); DTOs carry no
  secrets (2).
- `text/template` resolves funcs at parse time — `panel_parse_test.go` must stay green.
- In `create.html`, declare DOM refs at the top of the module (TDZ gotcha that already
  killed the submit listener once).
