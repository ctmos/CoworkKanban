# LifeOS Design System

## 1. Visual Theme & Atmosphere

LifeOS is a personal productivity dashboard — warm, focused, and quietly capable. Built on a parchment-toned canvas (`#f5f0ea`) inspired by Claude's aesthetic language, the interface feels like a well-organized leather notebook rather than a sterile SaaS dashboard. Every surface communicates warmth through exclusively warm-toned neutrals — no cool grays exist in this system.

The accent color is Amber (`#c47a2a`) — earthier and more subdued than typical tech oranges. It appears only for primary CTAs, active states, and the highest-signal interactive moments. The rest of the palette relies on layered warm neutrals that create depth through subtle surface differentiation rather than heavy shadows or borders.

**Key Characteristics:**
- Warm parchment canvas (`#f5f0ea`) — the emotional foundation
- Exclusively warm-toned neutrals — every gray has a yellow-brown undertone
- Amber accent (`#c47a2a`) — earthy, grounded, used sparingly
- Ring-based shadow system for interactive states
- Whisper-soft elevation shadows (`rgba(26,24,21,0.06)`)
- Inter font family at 14px base — clean, readable, modern
- 8px spacing grid with generous whitespace
- Glassmorphism-lite: white cards on warm canvas with subtle borders

## 2. Color Palette & Roles

### Light Theme (Default)

| Token | Value | Role |
|-------|-------|------|
| `--bg` | `#f5f0ea` | Page canvas — warm parchment, never pure white |
| `--surface` | `#ffffff` | Cards, sections, elevated containers |
| `--surface2` | `#f0ebe4` | Subtle surface tinting — toolbar backgrounds, input fills, secondary surfaces |
| `--border` | `#e8e3dc` | Standard warm border — cream-tinted, gentle containment |
| `--text` | `#1a1815` | Primary text — warm near-black, not pure `#000` |
| `--text-muted` | `#6b6560` | Secondary text — warm medium gray for metadata, timestamps, labels |
| `--accent` | `#c47a2a` | Primary CTA, active states, brand moments — the only chromatic color |
| `--accent-dark` | `#a86520` | Hover state for accent — slightly deeper |
| `--accent-light` | `rgba(196,122,42,0.08)` | Focus rings, selected backgrounds — barely visible amber tint |

### Dark Theme

| Token | Value | Role |
|-------|-------|------|
| `--bg` | `#1a1714` | Dark canvas — warm charcoal with olive undertone |
| `--surface` | `#252019` | Dark cards — elevated warm dark |
| `--surface2` | `#2e2820` | Secondary dark surface |
| `--border` | `#3d352a` | Dark border — warm, never cool gray |
| `--text` | `#e8e0d4` | Light text on dark — warm cream, not pure white |
| `--text-muted` | `#9a8e7d` | Muted text on dark — warm stone |

### Semantic Colors
- **Error:** `#c0392b` (warm red, serious without alarming)
- **Success:** `#27ae60` (natural green)
- **Warning:** `--accent` (amber doubles as warning)
- **Info:** `#6b6560` (muted, no blue — stays warm)
- **Focus ring:** `0 0 0 3px var(--accent-light)` — warm amber glow

### Gradient System
LifeOS is **gradient-free**. Depth comes from surface layering (bg → surface2 → surface → white) and warm shadow system. No linear-gradients, no mesh gradients.

## 3. Typography Rules

### Font Family
- **All text:** `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif`
- **Code:** `'SF Mono', 'Fira Code', 'Cascadia Code', monospace`
- No serif fonts in the UI — Inter carries the entire typographic weight

### Hierarchy

| Role | Size | Weight | Line Height | Letter Spacing | Use |
|------|------|--------|-------------|----------------|-----|
| Page Title | 20px | 700 | 1.3 | -0.02em | Tab headings (Projekte, Kanban, etc.) |
| Section Heading | 14px | 600 | 1.4 | 0 | Section titles within cards (Info, Beitraege) |
| Body | 14px | 400 | 1.6 | 0 | Standard content text, entry text |
| Body Small | 13px | 400 | 1.5 | 0 | Secondary body text, descriptions |
| Caption / Meta | 12px | 500 | 1.4 | 0.01em | Timestamps, dates, status labels |
| Label | 12px | 600 | 1.3 | 0.04em | Form labels (uppercase), badges |
| Micro | 11px | 500 | 1.3 | 0.02em | Smallest text — sync status, tiny metadata |
| Button | 13px | 500 | 1.0 | 0 | Button text — all sizes |

### Principles
- **14px base** — large enough for comfortable reading, compact enough for data density
- **Weight range 400–700** — 400 for reading, 500 for emphasis/UI, 600 for section heads, 700 only for page titles
- **Line-height 1.6 for body** — generous for readability, matches the warm/editorial feel
- **Uppercase labels at 12px** with letter-spacing 0.04em — structured, systematic feel
- **No font-size below 11px** — accessibility minimum

## 4. Component Stylings

### Buttons

**Primary (Accent)**
- Background: `var(--accent)` (`#c47a2a`)
- Text: `#ffffff`
- Padding: `9px 16px`
- Radius: `var(--radius-sm)` (8px)
- Hover: `var(--accent-dark)`, `translateY(-1px)`, shadow `0 4px 12px rgba(196,122,42,0.3)`
- Active: `translateY(0)`, no shadow
- The only button with chromatic color

**Secondary**
- Background: `var(--surface)`
- Text: `var(--text)`
- Border: `1px solid var(--border)`
- Padding: `8px 14px`
- Radius: 8px
- Hover: border darkens, subtle lift

**Ghost / Toolbar**
- Background: `transparent`
- Text: `var(--text-muted)`
- Border: `1px solid transparent`
- Padding: `5px 10px`
- Radius: 6px
- Hover: `var(--surface)` bg, `var(--text)` color, border appears

### Cards & Sections (`.proj-section` pattern)
- Background: `var(--surface)` (white)
- Border: `1px solid var(--border)` — warm cream border
- Radius: `var(--radius)` (12px)
- Padding: `20px`
- Margin-bottom: `16px`
- No shadow by default — the border provides gentle containment
- **Section heading:** 14px weight 600, with `border-bottom: 1px solid var(--border)` separator, padding-bottom 8px

### Entry Cards (`.proj-entry-card`)
- Background: `var(--surface)` (white)
- Border: `1px solid var(--border)`
- Radius: `var(--radius)` (12px)
- Padding: `16px 18px`
- Margin-bottom: `12px`
- Hover: `border-color: rgba(196,122,42,0.2)`, `box-shadow: 0 1px 6px rgba(0,0,0,0.03)`
- **Metadata** (date, timestamps): right-aligned, 12px, `var(--text-muted)`
- **Action buttons:** invisible by default, fade in on card hover (opacity 0 → 1)

### Inputs & Forms
- Background: `var(--bg)` or `var(--surface)` depending on context
- Border: `1px solid var(--border)`
- Radius: `var(--radius-sm)` (8px)
- Padding: `10px 12px`
- Font: 14px Inter
- Focus: `border-color: var(--accent)`, `box-shadow: 0 0 0 3px var(--accent-light)`
- Placeholder: `var(--text-muted)`

### Composer Box (Toolbar + Textarea)
- Container: `var(--bg)` background, `1px solid var(--border)`, `var(--radius)` (12px), `overflow: hidden`
- Toolbar: `var(--surface2)` background, `border-bottom: 1px solid var(--border)`, no outer border (inherits from container)
- Textarea: no border (inherits from container), transparent background, `14px`, padding `12px 14px`
- Submit button: inside container, right-aligned, margin `8px 10px 10px 0`
- Focus state: entire container gets `border-color: var(--accent)` + focus ring

### Navigation
- Background: `var(--nav-bg)` (white)
- Border-bottom: `1px solid var(--border)`
- Links: 14px weight 500, `var(--text-muted)`, no decoration
- Active tab: `var(--accent)` underline (2px), text darkens
- Logo: "LifeOS" in 18px weight 700, `var(--text)`

### Status Badges
- Aktiv: green bg, white text
- Pausiert: amber bg, white text
- Abgeschlossen: blue bg, white text
- Archiviert/Geloescht: gray bg, white text
- All badges: 10px font, 600 weight, 4px 10px padding, radius 4px

## 5. Layout Principles

### Spacing System (8px base)
- 4px — micro (gaps between inline elements)
- 6px — tight (button groups, toolbar button gaps)
- 8px — standard (between related elements)
- 10px — comfortable (form element internal spacing)
- 12px — section internal gaps
- 16px — between sections/cards
- 20px — section padding
- 24px — between major sections
- 32px — page-level vertical rhythm

### Grid & Container
- Max content width: `900px` centered (dashboard-appropriate, not full-width)
- No explicit CSS grid — flexbox-based layouts
- Single-column for detail views (Projekte detail, Patienten detail)
- 3-column grid for overview cards (Projekte list, Kanban lanes)
- Full-width sections with internal padding

### Whitespace Philosophy
- **Content-first density:** A productivity dashboard needs data density without feeling cramped
- **Card-based isolation:** Each section is a white card on the parchment canvas — creates natural visual breathing room
- **Consistent internal padding:** Always 20px inside sections — predictable, calm
- **12px between entry cards** — tight enough for scanning, generous enough to distinguish

### Border Radius Scale
| Token | Value | Use |
|-------|-------|-----|
| Sharp | 4px | Badges, tiny tags |
| `--radius-sm` | 8px | Buttons, inputs, small cards |
| `--radius` | 12px | Standard cards, sections, modals |
| `--radius-lg` | 16px | Large containers, dialog boxes |
| Full pill | 9999px | Status dots, toggle switches |

## 6. Depth & Elevation

| Level | Token | Treatment | Use |
|-------|-------|-----------|-----|
| Flat | — | No shadow, no border | Canvas background |
| Contained | — | `1px solid var(--border)` | Standard cards, sections |
| Subtle | `--shadow-sm` | `0 1px 2px rgba(26,24,21,0.04)` | Slight lift on hover |
| Standard | `--shadow` | `0 1px 3px rgba(26,24,21,0.06), 0 1px 2px rgba(26,24,21,0.04)` | Dropdowns, popovers |
| Medium | `--shadow-md` | `0 4px 12px rgba(26,24,21,0.08), 0 1px 3px rgba(26,24,21,0.04)` | Modals, floating panels |
| Large | `--shadow-lg` | `0 8px 24px rgba(26,24,21,0.1), 0 2px 6px rgba(26,24,21,0.04)` | Dialogs, toasts |
| Focus Ring | — | `0 0 0 3px var(--accent-light)` | Input focus, button focus |

**Shadow Philosophy:**
- Shadows use warm transparent blacks (`rgba(26,24,21,x)`) — never cool `rgba(0,0,0,x)`
- Depth is communicated primarily through **border containment**, not shadows
- Shadows appear only on interaction (hover lift, focus) or floating elements (modals, toasts)
- The ring shadow pattern (`0 0 0 3px`) creates a warm glow rather than a drop shadow

## 7. Do's and Don'ts

### Do
- Use `var(--bg)` (`#f5f0ea`) as the page canvas — the warm cream IS the personality
- Keep all neutrals warm-toned — every gray has a yellow-brown undertone
- Use `var(--accent)` (`#c47a2a`) only for primary CTAs and active states
- Use ring-based focus indicators (`0 0 0 3px var(--accent-light)`)
- Maintain the `border + radius` containment pattern for all cards
- Use `var(--text-muted)` for metadata, timestamps, secondary text
- Apply generous body line-height (1.6) for comfortable reading
- Use `var(--surface2)` for subtle background differentiation (toolbars, secondary surfaces)
- Always provide hover feedback on interactive elements (opacity, border-color, or lift)
- Fade action buttons in on card hover — keep cards clean by default

### Don't
- Don't use cool blue-grays — the palette is exclusively warm-toned
- Don't use pure white (`#ffffff`) as a page background — always `var(--bg)` or `var(--surface2)`
- Don't use heavy drop shadows — depth comes from borders and surface layering
- Don't introduce saturated colors beyond the accent — the palette is deliberately muted
- Don't use border-radius below 4px — softness is core to the identity
- Don't add inline styles in HTML — style.css is the single source of truth
- Don't use gradients — depth comes from surface layering
- Don't center-align metadata/dates in card headers — right-align with `margin-left: auto`
- Don't show all interactive controls by default — reveal on hover for a clean resting state
- Don't use font-size below 11px — maintain accessibility
- Don't use `console.log` in production code

## 8. Responsive Behavior

### Breakpoints
| Name | Width | Key Changes |
|------|-------|-------------|
| Mobile | <640px | Single column, stacked sections, compact padding (12px) |
| Tablet | 640–960px | 2-column grids, standard padding |
| Desktop | >960px | Full 3-column grids, generous padding (20px), max-width 900px |

### Touch Targets
- Minimum touch target: 44x44px
- Buttons: minimum padding 8px vertical
- Drag handles: 44px tall hit area
- Card surfaces serve as large touch targets where applicable

### Collapsing Strategy
- Project grid: 3-column → 2-column → 1-column
- Navigation: horizontal tabs → scrollable horizontal strip (no hamburger — all tabs visible)
- Section padding: 20px → 12px on mobile
- Font sizes stay constant — only spacing reduces

## 9. Interaction Patterns

### Hover States
- Cards: border-color shifts to warm accent tint, whisper shadow appears
- Buttons: primary lifts (`translateY(-1px)`), secondary border darkens
- Toolbar buttons: background fills with `var(--surface)`, text darkens
- Action buttons: fade in from `opacity: 0` to `opacity: 1`
- Drag handles: fade from `opacity: 0` to `opacity: 0.5`

### Focus States
- All focusable elements: `border-color: var(--accent)` + `box-shadow: 0 0 0 3px var(--accent-light)`
- Focus ring is warm amber, never blue (except for browser-default outline which we don't override)

### Transitions
- Duration: `0.2s` for most interactions
- Easing: `cubic-bezier(0.4, 0, 0.2, 1)` — quick start, gentle finish
- Properties: always transition specific properties (`opacity`, `transform`, `border-color`, `box-shadow`) — never `all`

### Drag and Drop
- Drag handle: `cursor: grab` → `cursor: grabbing` on active
- Dragging card: `opacity: 0.4`, `scale(0.98)`, `border: 2px dashed var(--accent)`
- Drop target: `border-top: 3px solid var(--accent)` (above) or `border-bottom` (below)
- Handle visibility: hidden by default, fades in on card hover

## 10. Agent Guide

### When Modifying LifeOS CSS
1. Read this DESIGN.md first — understand the token system
2. Use CSS custom properties (`var(--x)`) — never hardcode colors
3. Check both light and dark theme
4. Follow the existing component patterns — don't invent new ones unless needed
5. Match the spacing scale (8px grid)
6. Test with PIN 2611

### Quick Reference
- Page bg: `var(--bg)` — never white
- Card bg: `var(--surface)` — white on warm canvas
- Subtle bg: `var(--surface2)` — for toolbars, inputs
- Text: `var(--text)` — warm near-black
- Muted: `var(--text-muted)` — warm medium gray
- Accent: `var(--accent)` — amber, only for CTAs/active
- Border: `var(--border)` — warm cream
- Radius: 12px standard, 8px small, 16px large
- Shadow on hover: `var(--shadow-sm)`
- Focus ring: `0 0 0 3px var(--accent-light)`
