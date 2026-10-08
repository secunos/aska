# Licences

Aska is free software under two licences, by component:

- **`crates/aska-core`, `crates/aska-proto`, `crates/aska-scan`, `crates/aska` (command-line client) and `crates/aska-gui` (graphical client)** — dual-licensed under the **MIT License** ([LICENSE-MIT](LICENSE-MIT)) **or** the **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE)), at your option. The permissive terms are deliberate: anyone, including people who do not trust this project, must be free to audit, rebuild, fork and embed the client without a licence obstacle.
- **`crates/aska-drop` (the Dead Drop relay)** — **GNU Affero General Public License v3.0 only** ([crates/aska-drop/LICENSE](crates/aska-drop/LICENSE)). Anyone who runs a modified relay as a service must publish the modified source; a relay that quietly logs is what this is meant to make harder.
- The Python reference implementation in `reference/`, the scripts, the deployment files and the documentation follow the client licence (MIT or Apache-2.0).

Each crate's `Cargo.toml` carries its `license` field; `cargo deny check` enforces that every dependency is under a permissive licence from the list in `deny.toml`. The software comes with no warranty of any kind; see the licence texts.
