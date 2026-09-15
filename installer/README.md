# Recognition — install & distribution

Recognition ships as a **self-contained** Windows app: the published build carries its
own .NET runtime, so end users do **not** need .NET installed. PowerShell 7 (`pwsh`) is
recommended on the target for locked-startup verification and governed packet export.

## 1. Build the distribution (developer machine, needs .NET 8 SDK)

```powershell
pwsh -File scripts\RUN_PACKAGE_DIST_V1.ps1 -RepoRoot .
```

This publishes the self-contained browser and assembles a complete, runnable tree under
`dist\recognition\` — the exe plus the governance files it needs at runtime
(`scripts\`, `policies\`, `config\`, `proofs\trust\`, `schemas\`, `branding\`,
`installer\`). It also:

- wraps the whole distribution in a **governed evidence packet** (verified), and
- produces **`dist\Recognition-win-x64.zip`** — the downloadable.

## 2a. Install from the zip (end user, no admin)

Extract `Recognition-win-x64.zip`, then from the extracted folder:

```powershell
pwsh -File installer\RECOGNITION_INSTALL_V1.ps1
```

Installs per-user to `%LOCALAPPDATA%\Recognition`, creates Start Menu + Desktop
shortcuts (with the app icon), and registers an entry in **Apps & features**.
Reinstalling preserves your `runtime\` data (profile, history, bookmarks). Uninstall:

```powershell
pwsh -File installer\RECOGNITION_UNINSTALL_V1.ps1        # add -KeepData to keep your data
```

## 2b. Build a single Setup.exe (optional, nicer)

With [Inno Setup](https://jrsoftware.org/isdl.php) installed:

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\recognition.iss
```

Produces `installer\Recognition-Setup.exe` — a downloadable, double-clickable installer
with the branded icon.

## 3. Publish a download (GitHub Release)

The self-contained exe (~150 MB) exceeds GitHub's 100 MB file limit for the git tree, so
distribute it as a **Release asset**, not a committed file:

1. Create a tag/release: **GitHub → Releases → Draft a new release** (e.g. `v1.0.0`).
2. Attach `dist\Recognition-win-x64.zip` (and/or `installer\Recognition-Setup.exe`).
3. Publish. The download links live on the Releases page.

CLI alternative (needs the GitHub CLI, `gh auth login` once):

```powershell
gh release create v1.0.0 dist\Recognition-win-x64.zip installer\Recognition-Setup.exe `
  --title "Recognition v1.0.0" --notes "Governed, private browser — self-contained Windows build."
```

## Runtime dependencies on the target

- **WebView2 Runtime** — preinstalled on Windows 11 and current Windows 10; if missing,
  the Evergreen bootstrapper is a free download from Microsoft.
- **PowerShell 7 (`pwsh`)** — for locked-startup verification and packet export. Without
  it the app still launches but startup verification cannot run.
