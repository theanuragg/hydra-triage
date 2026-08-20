# Brand — hydra-triage

**Palette:** dark-terminal + hydra teal (confirmed in session; kept as-is).

The client UI ships a deliberate security-terminal aesthetic: near-black
void, raised panels, cool blue-grey text ramps, teal signal accent. Colors
live as CSS custom properties in `client/src/index.css` under `:root`.

| Token | Value | Use |
|---|---|---|
| `--void` | `#0a0c10` | page background |
| `--panel` | `#12151c` | cards / inputs |
| `--panel-raised` | `#171b24` | hover, table headers |
| `--border` | `#1e232d` | 1px separators |
| `--ink` | `#e7eaf0` | primary text |
| `--ink-dim` | `#8a93a6` | secondary text |
| `--ink-faint` | `#545c6c` | captions, placeholders |
| `--signal` | `#63e6d4` | brand teal — primary actions, active tab, live dot, focus rings |
| `--danger` | `#ff6b6b` | reachable / critical |
| `--warn` | `#f5c36b` | present-unreachable / high+ |
| `--calm` | `#6fe39b` | not-present / clear |

**Typography:** JetBrains Mono for UI chrome and labels, IBM Plex Mono for
data/numbers, IBM Plex Sans for prose. Loaded from Google Fonts in
`client/index.html`.

**Voice:** concise, terminal-style, active voice. Uppercase mono labels
with wide letter-spacing; data displayed in mono. No emoji, no gradients
beyond the loading sweep; status is color + label, never color alone.

**Radius:** `--radius: 6px` everywhere; pills `999px`.
**Motion:** loading sweep 1.1s linear loop, trace edges 0.5s ease
draw-on. Both must respect `prefers-reduced-motion`.
