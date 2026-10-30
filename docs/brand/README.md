# ASKA brand (kit 3.0, release 1.2.3)

**Mark:** Perforerad — a perforated plate of round holes in straight staggered rows that shrink toward the upper right. **Name:** ASKA in Archivo Expanded SemiBold capitals, 0.14 em letter spacing, converted to outlines and set below the mark (no font is needed; Archivo is under the SIL Open Font License). **Colour:** black and white with one signal colour, yellow `#F2C230`, which marks the brand and never a state. **No slogan.** Brand 3.0 (30 October 2026) supersedes brand 2.0 (the Fade mark, shipped in 1.2.2) and brand 1.0 (the Glow mark, 1.2.1).

What the repository carries:

- `docs/brand/aska-horizontal-black.png`, `-signal.png` — the horizontal lockup shown at the top of the README (black on light grounds; on dark grounds the yellow mark with the name in white).
- `deploy/gui/icons/hicolor/` — the freedesktop icon theme for the app id `org.aska.Aska` (PNG 16–512, scalable SVG, symbolic SVG); installed by `install.sh`, packaged by `scripts/package-gui.sh`. The tile is signal yellow with the mark in ink; 16–24 px use a simplified small master, 32–48 px a mid master; the symbolic icon is seven holes that GTK recolours.
- `crates/aska-gui/brand/` — the libadwaita colour overrides (`aska.css`, `aska-dark.css`), the stacked lockups the Home screen embeds (`aska-stacked-black.png` for the light style, `aska-stacked-signal.png` for the dark style, and their SVGs), and `aska-tokens.json`, the colour source of truth.

| Role | Light | Dark |
|---|---|---|
| background | `#FFFFFF` | `#0B0B0B` |
| surface | `#F5F5F5` | `#161616` |
| surface-alt | `#EBEBEB` | `#1E1E1E` |
| border | `#DEDEDE` | `#2A2A2A` |
| border-strong | `#808080` | `#666666` |
| text | `#111111` | `#F2F2F2` |
| text-muted | `#666666` | `#9A9A9A` |
| accent (main button) | `#111111` | `#F2C230` |
| on-accent | `#F2C230` | `#111111` |
| signal | `#F2C230` | `#F2C230` |
| info | `#3D6A8F` | `#8DB4D6` |
| success | `#2E7D4F` | `#6FCF97` |
| warning | `#8A4B00` | `#FFB15C` |
| danger | `#B3261E` | `#FF8A80` |

Every text colour passes 4.5:1 against its background; signal yellow is a fill (the app tile, the mark on dark grounds, the main button in the dark style) and is never used for text on a light ground or for a warning. In the client: controls are 2 px rectangles (no pills), cards 4 px; the one main action on a screen is filled with the accent — ink with a yellow label in the light style, yellow with an ink label in the dark style; banners are the state colour on its tinted ground and always start with their word (Refused, Warning, Note); the Tor state in the footer is a dot in the state colour followed by the word. The Home screen shows the stacked logo, the mark 72 px tall with the name below it. The window title and the launcher entry are **ASKA**; the command and the application id stay `aska` and `org.aska.Aska`.

Rules: black files on light grounds, white or signal on dark; clear space of a quarter of the mark's height on every side; minimum width 64 px for the stacked logo, 120 px for the horizontal; do not recolour the logo beyond black, white and signal yellow, retype the name in a font, rotate or mirror the mark (the holes always shrink toward the upper right), or add a slogan, shadow, ring or container. The full kit (Android, iOS, Windows and web icons, all lockups as SVG and PNG, the palette for every platform) and the *ASKA Brand Guidelines 3.0* are the owner's; this directory holds what the Linux client and the repository use.
