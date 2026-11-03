# Contributing

Use Python 3.11 or newer and the project virtual environment.

```powershell
.\scripts\setup.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check.ps1
```

For changes to a detection rule, add a positive test, a benign test, and a
documented false-positive boundary. Changes to live capture must not add transmit,
injection, or packet-sending calls. Changes to the dashboard must preserve the
`textContent` rendering boundary and pass `node --check`.

Run the full suite before release:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check_full.ps1
```

Keep generated PCAPs, models, databases, and evaluation artifacts out of Git.
