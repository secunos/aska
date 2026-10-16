# Aska brand (kit 1.0, release 1.2.1)

**Mark:** Glow — an ember with a ring of heat. **Wordmark:** Outfit Medium, lowercase `aska`, converted to outlines (no font is needed; Outfit is under the SIL Open Font License). **Slogan:** *Notes that leave no trace.* **Palette:** Nordic calm — ash greys with one ember accent.

What the repository carries:

- `docs/brand/aska-horizontal-on-light.png`, `-on-dark.png` — the lockup shown at the top of the README.
- `deploy/gui/icons/hicolor/` — the freedesktop icon theme for the app id `org.aska.Aska` (PNG 16–512, scalable SVG, symbolic SVG); installed by `install.sh`, packaged by `scripts/package-gui.sh`.
- `crates/aska-gui/brand/` — the libadwaita colour overrides (`aska.css`, `aska-dark.css`), the horizontal lockups with the slogan (`aska-horizontal-on-light.png`, `-on-dark.png` and their SVGs) that the Home screen embeds, and `aska-tokens.json`, the colour source of truth.

| Role | Light | Dark |
|---|---|---|
| background | `#FAFBFC` | `#16191E` |
| surface | `#FFFFFF` | `#20252B` |
| text | `#1B1F24` | `#E6E9ED` |
| text-muted | `#626A74` | `#959DA7` |
| accent (ember) | `#B4501E` | `#F58B4C` |
| success | `#2B7653` | `#6CC49A` |
| warning | `#866500` | `#E6C04A` |
| danger | `#B0323C` | `#F2878C` |

Every text colour meets WCAG AA against its background. Rules: use the on-dark lockup on dark backgrounds and on-light on light ones; keep clear space equal to the height of the `a`; do not recolour the ember, stretch the logo or set the slogan in another typeface — in the client the slogan is therefore part of the lockup image, never a text label. The full kit (Android, iOS, Windows and web icons, all lockups as SVG and PNG) is the owner's; this directory holds what the Linux client and the repository use.
