# EagleGuard Updates

Public update server for **EagleGuard**: every 2 hours GitHub Actions downloads threat data from
[abuse.ch](https://abuse.ch) (MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker) and
[YARA-Forge](https://github.com/YARAHQ/yara-forge), merges it into an accumulating database and
publishes a **signed** package on the `dist` branch.

EagleGuard installations download `dist/manifest.json` and accept a package only if its Ed25519
signature matches the key built into the program and every file matches its SHA-256.
Nothing is uploaded from users' devices.

Secrets (Settings → Secrets and variables → Actions): `ABUSE_CH_AUTH_KEY`, `EAGLEGUARD_SIGNING_KEY`.

Data credits: abuse.ch (see their terms of use), YARA-Forge (rule authors' licenses).
