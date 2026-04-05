# LifeOS Design System v2.1

## Visual Identity
- **Font:** Lexend (Google Fonts) — dyslexia-friendly, wide letterforms, great readability
- **Accent:** Red #e5484d — energisch, aufmerksamkeitsstark
- **Temperature:** Cool blue-gray — technisch, fokussiert
- **Nav:** Pill-style tabs, active = red fill
- **Sections:** Colored left-borders (Rot=Info, Blau=Entries, Gruen=Patienten, Lila=Links)
- **Entries:** Timeline-Darstellung (vertikale Linie + Dots)
- **Theme:** Dark default, Light toggle via Mond/Sonne Icon

## Color Tokens

### Dark Theme (Default)
| Token | Value | Use |
|-------|-------|-----|
| --bg | #16181c | Page canvas |
| --surface | #1a1d22 | Cards, sections |
| --surface2 | #21252b | Elevated surfaces, toolbars |
| --border | #2d3139 | Standard border |
| --border-strong | #3a3f48 | Hover/emphasized border |
| --text | #e0e4ea | Primary text |
| --text-secondary | #8a90a0 | Secondary text |
| --text-muted | #5a6070 | Muted text, metadata |
| --accent | #e5484d | CTAs, active states |
| --accent-dark | #d13438 | Hover state |
| --green | #46a758 | Success, aktiv status |
| --blue | #3b82f6 | Entry section borders |
| --purple | #7c3aed | Link section borders |

### Light Theme
| Token | Value | Use |
|-------|-------|-----|
| --bg | #f5f7fa | Page canvas |
| --surface | #ffffff | Cards, sections |
| --surface2 | #eef1f5 | Toolbars, secondary |
| --border | #dde1e8 | Standard border |
| --text | #1a1d24 | Primary text |
| --text-secondary | #5a6070 | Secondary |
| --text-muted | #8a90a0 | Muted |

## Typography
- Font: Lexend, system-ui fallback
- Body: 14px, weight 400, line-height 1.5
- Headings: 13px uppercase, weight 600, letter-spacing 0.05em
- Page titles: 18px, weight 700
- Buttons: 13px, weight 600

## Components

### Nav (Pills)
- Height: 52px, background: var(--surface)
- Tabs: border-radius 8px, padding 6px 14px
- Active: background var(--accent), color white, weight 600
- Theme toggle: rightmost element, Mond/Sonne icon

### Sections (Colored Left Borders)
- border-left: 3px solid [color]
- .section-info: accent red
- .section-entries: blue #3b82f6
- .section-patients: green #46a758
- .section-links: purple #7c3aed

### Entries (Timeline)
- Vertical line: 2px, var(--border), left side
- Dots: 8px circle, var(--accent), on the line
- Date above entry, 10px uppercase
- Actions fade in on hover

### Radius Scale
- 8px: buttons, inputs (--radius-sm)
- 10px: cards, sections (--radius)
- 14px: large containers (--radius-lg)

## Do's
- Use Lexend everywhere — no font mixing
- Keep accent red for CTAs only
- Use colored left-borders for section identification
- Dark mode as default
- Timeline for chronological entries
- Pill tabs, not underline tabs

## Theme Architecture
- **localStorage Key:** `lifeos-theme` (values: "dark" | "light", default: "dark")
- **CSS Classes:** `dark-theme` OR `light-theme` on `<html>` — NEVER both
- **Assignment Rule:** Always use `document.documentElement.className = theme + '-theme'` — NEVER classList.add/remove (caused dual-class bugs)
- **FOUC Prevention:** Inline script in `<head>` reads localStorage and sets className before CSS renders
- **Toggle Icon:** Sun (☀) in dark mode, Moon (☾) in light mode
- **3 Theme Functions:** `initTheme()` (page load), `toggleTheme()` (nav button), `applyTheme(theme)` (settings buttons)
- **SW Cache Bump:** Required on every deploy — increment `lifeos-vX.Y` in sw.js

## Don'ts
- No warm/brown tones — cool blue-gray only
- No heavy shadows — subtle or none
- No font-size below 10px
- No gradients
- No inline styles in HTML
- No classList.add/remove for theme switching — use className assignment
- No duplicate localStorage keys for theme (only `lifeos-theme`)
