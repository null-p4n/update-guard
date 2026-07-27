```markdown
# 🛡️ Update Guard

> **"Don't blindly `apt upgrade`."**

Update Guard is a lightweight, opinionated security pipeline for Debian/Ubuntu and Docker hosts.  
It **stages** candidate updates, **verifies** their integrity, **scans** them for malware, checks their **reputation** against public security databases, and **summarizes** the risk — *before* you ever run `apt install` or `docker pull`.

Think of it as a **pre-flight check** for your infrastructure updates.

---

## ✨ What it does (in 30 seconds)

| Stage | What happens |
|-------|-------------|
| 📸 **Snapshot** | Records current APT and Docker state for deterministic diffing |
| 📦 **Stage** | Downloads every candidate `.deb` to a temporary sandbox |
| 🔐 **Verify** | Validates `.deb` structure, computes SHA256s, checks embedded signatures |
| 🦠 **VirusTotal** | Looks up every staged package hash against VT's malware database |
| 🎯 **YARA** | Scans binaries with public YARA rules for known malicious patterns |
| 🌐 **Reputation** | Queries Debian Security Tracker, GHSA, deps.dev, and CISA KEV |
| 🤖 **Chatter** | Uses LLM APIs (Gemini/OpenRouter) to surface public security discourse |
| 📊 **Decide** | Emits a human-readable risk report + machine-friendly exit code |

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐
│  apt-get -s     │────▶│  Stage .debs    │
│  docker ps      │     │  (sandbox)      │
└─────────────────┘     └────────┬────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
   ┌─────────┐            ┌────────────┐           ┌──────────┐
   │ dpkg-deb│            │ VirusTotal │           │  YARA    │
   │ verify  │            │ SHA256     │           │ scan     │
   └────┬────┘            └─────┬──────┘           └────┬─────┘
        │                       │                      │
        └───────────────────────┼──────────────────────┘
                                ▼
                    ┌─────────────────────┐
                    │   Reputation + AI   │
                    │  (GHSA/Tracker/LLM) │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │  Decision Report    │
                    │  Exit 0 = clean     │
                    │  Exit 3 = CRITICAL  │
                    └─────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

| Required | Optional (recommended) |
|----------|------------------------|
| `bash`, `curl`, `jq` | `debsig-verify` — embedded GPG sig checks |
| `apt-get`, `dpkg-deb` | `yara` — static malware pattern scanning |
| `docker`, `skopeo` | `git` — auto-download YARA rule sets |
| `sha256sum` | |

### 1. Install

```bash
sudo mkdir -p /usr/local/bin
sudo curl -fsSL https://raw.githubusercontent.com/YOURNAME/update-guard/main/update-guard.sh \
  -o /usr/local/bin/update-guard
sudo chmod +x /usr/local/bin/update-guard
```

### 2. Configure

```bash
sudo mkdir -p /etc/update-guard
sudo tee /etc/update-guard/config.env > /dev/null <<'EOF'
# --- VirusTotal (free tier: 100 lookups/day, 4/min) ---
VT_API_KEY=your_vt_api_key_here

# --- GitHub Security Advisories ---
GHSA_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# --- AI Chatter (optional, pick one) ---
GEMINI_API_KEY=your_gemini_key_here
# OPENROUTER_API_KEY=your_openrouter_key_here

# --- General ---
UPDATE_GUARD_DEBUG=0
UPDATE_GUARD_KEEP_REPORTS=30
EOF
sudo chmod 600 /etc/update-guard/config.env
```

> 💡 **Tip:** You only need the APIs you plan to use. The script degrades gracefully — if `VT_API_KEY` is missing, it skips VirusTotal; if `yara` isn't installed, it skips YARA.

### 3. Run

```bash
sudo /usr/local/bin/update-guard
```

### 4. Install as a scheduled job

**Systemd (recommended):**
```bash
sudo /usr/local/bin/update-guard --install-systemd
# systemctl status update-guard.timer
```

**Cron:**
```bash
sudo /usr/local/bin/update-guard --install-cron "0 3 * * *"
```

---

## 📋 Example Output

```
[APT] Candidates found:
Inst openssl (3.0.11-1~deb12u2 Debian:12.5/stable [amd64])
Inst curl (7.88.1-10+deb12u5 Debian:12.5/stable [amd64])

[APT] openssl -> 3.0.11-1~deb12u2, eligible for analysis-engine pass
[APT]   -> reputation_check (Debian Security Tracker/KEV/GHSA): /var/lib/update-guard/reports/reputation-openssl-20260727-031500.json
[APT]   -> chatter (unverified): /var/lib/update-guard/reports/chatter-openssl-20260727-031500.json

[DEB VERIFICATION] Staged package integrity & metadata:
VALID: openssl
SIG_NONE_OR_FAIL: openssl (no embedded sig or policy missing)
SHA256: openssl 2d3f...a1b4

[VIRUSTOTAL] Hash reputation (malware/suspicious detections):
[VT] All scanned packages clean (0 malicious, 0 suspicious).

[YARA] Static pattern analysis:
[YARA] No suspicious patterns detected in staged packages.

RISK_EXIT_CODE: 0 (0=clean, 3=critical findings)
Full report: /var/lib/update-guard/reports/decision-20260727-031500.txt
```

---

## 🎛️ Configuration Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `UPDATE_GUARD_STATE_DIR` | `/var/lib/update-guard` | Where snapshots, reports, and staging live |
| `UPDATE_GUARD_KEEP_REPORTS` | `30` | Retention policy: how many run generations to keep |
| `VT_API_KEY` | *(none)* | VirusTotal API v3 key |
| `YARA_RULES_DIR` | `$STATE_DIR/yara-rules` | Path to `.yar` / `.yara` rule files |
| `YARA_BINARY` | auto-detected | Path to `yara` binary |
| `AI_PROVIDER` | `gemini` | `gemini` or `openrouter` |
| `GEMINI_API_KEY` / `OPENROUTER_API_KEY` | *(none)* | LLM provider key |
| `UPDATE_GUARD_DEBUG` | `0` | Set to `1` for verbose debug logging |

---

## 🔌 Exit Codes for Automation

Update Guard returns semantic exit codes so your scheduler, CI/CD, or alerting system can act on results without parsing text:

| Code | Meaning | Action |
|------|---------|--------|
| `0` | ✅ Clean | Safe to proceed with upgrades |
| `1` | Script error | Check stderr / debug log |
| `2` | Lock conflict | Another instance is already running |
| `3` | 🚨 **Critical findings** | Invalid debs, VT detections, or YARA matches — **do not upgrade** |

### CI/CD Integration Example

```yaml
# .github/workflows/update-guard.yml (simplified)
- name: Run Update Guard
  run: |
    sudo ./update-guard.sh
    EXIT=$?
    if [ $EXIT -eq 3 ]; then
      echo "::error::Critical security findings detected. Review report."
      exit 1
    elif [ $EXIT -ne 0 ]; then
      echo "::warning::Update Guard exited with code $EXIT"
    fi
```

---

## 🧠 How the Decision Engine Works

1. **High-impact packages** (`linux-image`, `libc6`, `openssl`, `sudo`, `systemd`) are **never** auto-approved. They are flagged for human review regardless of scan results.
2. **Structural integrity failures** (`dpkg-deb` rejects the file) immediately raise `RISK_EXIT_CODE: 3`.
3. **VirusTotal hits** (`malicious > 0` or `suspicious > 0`) raise `RISK_EXIT_CODE: 3`.
4. **YARA matches** raise `RISK_EXIT_CODE: 3`.
5. Everything else is **informational** — the report gives you signal, not a gate.

---

## 🗂️ Directory Layout

```
/var/lib/update-guard/
├── apt/
│   ├── installed-*.txt
│   └── candidates-*.txt
├── docker/
│   ├── running-*.txt
│   └── remote-check-*.txt
├── staging/
│   └── 20260727-031500/          # staged .deb files
├── yara-rules/
│   └── yara-rules/               # cloned rule repo
└── reports/
    ├── decision-*.txt            # human-readable summary
    ├── deb-verify-*.txt          # integrity + SHA256s
    ├── virustotal-*.json         # VT API responses
    ├── yara-*.txt                # YARA scan results
    ├── reputation-*.json         # GHSA/Tracker/deps.dev
    ├── chatter-*.json            # LLM summaries
    └── debug-*.log               # verbose trace (if DEBUG=1)
```

---

## 🔒 Security Notes

- **API keys** live in `/etc/update-guard/config.env` with `600` permissions. The script never logs them.
- **Staging** happens in a dedicated directory, not `/tmp`, so unprivileged users can't swap files mid-scan.
- **No auto-upgrades.** Update Guard is strictly read-only / advisory. It will never run `apt install` or `docker pull` for you.
- **LLM chatter is tagged** `UNVERIFIED_CHATTER_NOT_AUTHORITATIVE` in every JSON output to prevent over-reliance on AI summaries.

---

## 🛣️ Roadmap

- [ ] SBOM generation for staged packages (`spdx-json`, `cyclonedx-json`)
- [ ] OCI image layer scanning (not just digest comparison)
- [ ] Slack/Discord/Email webhook notifications on `EXIT 3`
- [ ] Configurable YARA rule sources (custom private repos)
- [ ] Integration with [Grype](https://github.com/anchore/grype) or [Trivy](https://github.com/aquasecurity/trivy) for CVE depth-scanning

---

## 🤝 Contributing

Pull requests welcome! Areas we'd love help with:

- Better YARA rule curation (the public repo is huge; a curated subset would be faster)
- Additional reputation sources (Snyk, OSV, NVD API)
- Packaging (`.deb`, `.rpm`, AUR, Homebrew)

---

## 📜 License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <i>Built for people who sleep better knowing their upgrades were checked first.</i>
</p>
```
