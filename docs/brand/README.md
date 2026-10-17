# ASKA brand (kit 2.0, release 1.2.2)

**Mark:** Fade — a 4 × 4 grid of dots shrinking from the lower-left corner to the upper-right. **Name:** ASKA in Jost Medium capitals, 0.22 em letter spacing, converted to outlines (no font is needed; Jost is under the SIL Open Font License). **Colour:** black and white — the Graphite greys — with colour only for states. **No slogan.** Brand 2.0 (17 October 2026) supersedes brand 1.0 (the Glow mark, shipped in 1.2.1).

What the repository carries:

- `docs/brand/aska-horizontal-black.png`, `-white.png` — the lockup shown at the top of the README (black on light grounds, white on dark).
- `deploy/gui/icons/hicolor/` — the freedesktop icon theme for the app id `org.aska.Aska` (PNG 16–512, scalable SVG, symbolic SVG); installed by `install.sh`, packaged by `scripts/package-gui.sh`. The tile is ink with the mark in paper; 16–24 px use a 3 × 3 master, 32–48 px a heavier 4 × 4.
- `crates/aska-gui/brand/` — the libadwaita colour overrides (`aska.css`, `aska-dark.css`), the horizontal lockups the Home screen embeds (`aska-horizontal-black/white.png` and their SVGs), and `aska-tokens.json`, the colour source of truth.

| Role | Light | Dark |
|---|---|---|
| background | `#FFFFFF` | `#0B0B0B` |
| surface | `#F5F5F5` | `#161616` |
| surface-alt | `#EBEBEB` | `#1E1E1E` |
| border | `#DEDEDE` | `#2A2A2A` |
| text | `#111111` | `#F2F2F2` |
| text-muted | `#666666` | `#9A9A9A` |
| accent (ink) | `#111111` | `#F2F2F2` |
| info | `#3D6A8F` | `#8DB4D6` |
| success | `#2E7D4F` | `#6FCF97` |
| warning | `#6E5600` | `#E8C547` |
| danger | `#B3261E` | `#FF8A80` |

Every text colour passes 4.5:1 against its background. In the client: controls are 4 px rectangles (no pills), cards 8 px; the one main action on a screen is filled with the accent; banners are the state colour on its tinted ground and always start with their word (Refused, Warning, Note); the Tor state in the footer is a dot in the state colour followed by the word. The window title and the launcher entry are **ASKA**; the command and the application id stay `aska` and `org.aska.Aska`.

Rules: black files on light grounds, white on dark; clear space of a quarter of the mark's height on every side; do not recolour the logo, retype the name in a font, rotate or mirror the mark, or add a slogan, shadow or container. The full kit (Android, iOS, Windows and web icons, all lockups as SVG and PNG, the palette for every platform) and the *ASKA Brand Guidelines 2.0* are the owner's; this directory holds what the Linux client and the repository use.
