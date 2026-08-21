# Developer Architecture

`keeper.ui_qml` is the product presentation layer over `KeeperApplication` and `PassBApplication`. `keeper.desktop` retains legacy Tk classes for compatibility tests, but its default entry point delegates to Qt; `--legacy-tk` is explicit.

QML receives only primitive redacted state from `KeeperDesktopController`. It does not import repositories, SQLite records, Executive objects, provider adapters, or KeeperAuthority clients. UI actions call supported application services and cannot synthesize Founder approval, provider qualification, review acceptance, recovery truth, or execution authority.

`keeper.app.storage` owns transactional versioned SQLite records. Lifecycle, verification policy, Git safety, security, notifications, reporting, orchestration, and process-tree provider execution remain separate services. KeeperAuthority remains the authority truth. The desktop health projection uses the existing safe allowlisted health view and does not expose service roots, exchange roots, SIDs, or protected evidence paths.

PySide6 6.10.1 supplies Qt Quick, scaling, accessibility, and Windows integration. Nuitka 4.1.3 builds a standalone per-user artifact. Runtime package contents are hashed and validated by the local lifecycle script before install, repair, upgrade, or rollback.
