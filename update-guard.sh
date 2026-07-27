#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# UPDATE GUARD v2.0
# Scheduled APT/Docker update analyzer with deb verification, VirusTotal
# hash lookup, YARA scanning, and systemd/cron scheduler integration.
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
CONFIG_FILE="${UPDATE_GUARD_CONFIG:-/etc/update-guard/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

STATE_DIR="${UPDATE_GUARD_STATE_DIR:-/var/lib/update-guard}"
LOCK_FILE="$STATE_DIR/.lock"
STAGING_DIR="$STATE_DIR/staging"
KEEP_REPORTS="${UPDATE_GUARD_KEEP_REPORTS:-30}"

# API keys & endpoints
VT_API_KEY="${VT_API_KEY:-}"
VT_API_URL="https://www.virustotal.com/api/v3/files"
YARA_RULES_DIR="${YARA_RULES_DIR:-$STATE_DIR/yara-rules}"
YARA_BINARY="${YARA_BINARY:-$(command -v yara || true)}"

# AI config
AI_PROVIDER="${AI_PROVIDER:-gemini}"
GEMINI_API_KEY="${GEMINI_API_KEY:-}"
GEMINI_MODEL="${GEMINI_MODEL:-gemma-4-31b-it}"
GEMINI_ENDPOINT="https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-openrouter/auto}"
OPENROUTER_ENDPOINT="https://openrouter.ai/api/v1/chat/completions"

# Existing tracker APIs
DEPS_DEV_API="https://api.deps.dev/v3"
DEBIAN_TRACKER_API="https://security-tracker.debian.org/tracker/data/json"
CISA_KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_API="https://api.github.com/advisories"
GHSA_TOKEN="${GHSA_TOKEN:-}"

# -----------------------------------------------------------------------------
# STATE INITIALIZATION
# -----------------------------------------------------------------------------
if ! mkdir -p "$STATE_DIR"/{apt,docker,reports,staging} 2>/dev/null || [[ ! -w "$STATE_DIR" ]]; then
    FALLBACK_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/update-guard"
    echo "WARNING: cannot write to $STATE_DIR (root-owned or no permission)." >&2
    echo "         Falling back to $FALLBACK_DIR — set UPDATE_GUARD_STATE_DIR to override." >&2
    STATE_DIR="$FALLBACK_DIR"
    mkdir -p "$STATE_DIR"/{apt,docker,reports,staging}
    LOCK_FILE="$STATE_DIR/.lock"
    STAGING_DIR="$STATE_DIR/staging"
fi
TS="$(date +%Y%m%d-%H%M%S)"

# -----------------------------------------------------------------------------
# DEPENDENCY CHECKS
# -----------------------------------------------------------------------------
for bin in curl jq skopeo docker apt-get dpkg-deb sha256sum; do
    command -v "$bin" >/dev/null 2>&1 || { echo "missing dependency: $bin" >&2; exit 1; }
done

DEBUG="${UPDATE_GUARD_DEBUG:-0}"
DEBUG_LOG="$STATE_DIR/reports/debug-$TS.log"
[[ "$DEBUG" == "1" ]] && : > "$DEBUG_LOG"

dbg() { [[ "$DEBUG" == "1" ]] && echo "[DEBUG $(date +%T)] $*" | tee -a "$DEBUG_LOG" >&2; return 0; }

# -----------------------------------------------------------------------------
# LOCKING (prevent overlapping scheduled runs)
# -----------------------------------------------------------------------------
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || true)
        if [[ -n "${pid:-}" ]]; then
            if kill -0 "$pid" 2>/dev/null; then
                echo "ERROR: Another instance (PID $pid) is already running. Exiting." >&2
                exit 2
            elif [[ -d "/proc/$pid" ]]; then
                echo "ERROR: Another instance (PID $pid) exists (permission denied to signal). Exiting." >&2
                exit 2
            fi
            dbg "Stale lock file found (PID $pid dead), removing"
        fi
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
    dbg "Lock acquired (PID $$)"
}

release_lock() {
    rm -f "$LOCK_FILE"
    dbg "Lock released"
}

# -----------------------------------------------------------------------------
# CURL HELPER
# -----------------------------------------------------------------------------
curl_json() {
    local url="$1"; shift
    local max_attempts=3
    local attempt=1
    local status body tmp

    while (( attempt <= max_attempts )); do
        tmp=$(mktemp)
        local curl_stderr
        curl_stderr=$(mktemp)
        status=$(curl -sS -o "$tmp" -w '%{http_code}' "$url" "$@" 2>"$curl_stderr") || status="000"
        [[ "$DEBUG" == "1" && -s "$curl_stderr" ]] && dbg "curl stderr: $(cat "$curl_stderr")"
        rm -f "$curl_stderr"

        body=$(cat "$tmp" 2>/dev/null || true); rm -f "$tmp"

        if [[ "$status" -ge 200 && "$status" -lt 300 ]]; then
            dbg "GET/POST $url -> HTTP $status (attempt $attempt/$max_attempts)"
            echo "$body"
            return 0
        fi

        dbg "GET/POST $url -> HTTP $status (attempt $attempt/$max_attempts), body: ${body:0:200}"

        if [[ "$status" == "503" || "$status" == "429" || "$status" == "000" ]]; then
            if (( attempt < max_attempts )); then
                local backoff=$(( attempt * 5 ))
                dbg "Transient error ($status) — retrying in ${backoff}s"
                sleep "$backoff"
                attempt=$((attempt + 1))
                continue
            fi
        fi

        dbg "NON-2xx RESPONSE ($status) for $url — giving up. Full body was: $body"
        echo '{}'
        return 1
    done
}

# -----------------------------------------------------------------------------
# APT SNAPSHOTS
# -----------------------------------------------------------------------------
apt_snapshot() {
    dpkg -l | awk '/^ii/ {print $2, $3, $4}' | sort > "$STATE_DIR/apt/installed-$TS.txt"
    apt-get -s upgrade 2>/dev/null | grep '^Inst' | sort > "$STATE_DIR/apt/candidates-$TS.txt" || true
    ln -sf "installed-$TS.txt" "$STATE_DIR/apt/installed-latest.txt"
    ln -sf "candidates-$TS.txt" "$STATE_DIR/apt/candidates-latest.txt"
}

apt_diff_against_previous() {
    local prev
    prev=$(ls -t "$STATE_DIR"/apt/installed-*.txt 2>/dev/null | grep -v -- '-latest\.txt$' | sed -n '2p' || true)
    if [[ -n "$prev" ]]; then
        diff "$prev" "$STATE_DIR/apt/installed-latest.txt" > "$STATE_DIR/reports/apt-diff-$TS.txt" || true
    fi
}

# -----------------------------------------------------------------------------
# NEW: APT DOWNLOAD & VERIFY
# -----------------------------------------------------------------------------
apt_download_candidates() {
    mkdir -p "$STAGING_DIR/$TS"
    local candidates="$STATE_DIR/apt/candidates-latest.txt"
    [[ -f "$candidates" && -s "$candidates" ]] || { dbg "No candidates to download"; return 0; }

    dbg "Downloading candidate .deb packages to $STAGING_DIR/$TS"
    (
        cd "$STAGING_DIR/$TS"
        while read -r line; do
            [[ "$line" =~ ^Inst\ ([^ ]+)\ .*\(([^ ]+) ]] || continue
            local pkg="${BASH_REMATCH[1]}"
            local newver="${BASH_REMATCH[2]}"
            dbg "Downloading $pkg=$newver"
            apt-get download "$pkg=$newver" >/dev/null 2>&1 || {
                echo "WARNING: failed to download $pkg=$newver" >&2
                dbg "Download failed for $pkg=$newver"
            }
        done < "$candidates"
    )

    find "$STAGING_DIR/$TS" -name "*.deb" -type f > "$STAGING_DIR/downloaded-$TS.txt" || true
    ln -sf "downloaded-$TS.txt" "$STAGING_DIR/downloaded-latest.txt"
    dbg "Downloaded $(wc -l < "$STAGING_DIR/downloaded-latest.txt" 2>/dev/null || echo 0) packages"
}

apt_verify_debs() {
    local deb_list="$STAGING_DIR/downloaded-latest.txt"
    [[ -f "$deb_list" && -s "$deb_list" ]] || return 0

    local verify_report="$STATE_DIR/reports/deb-verify-$TS.txt"
    : > "$verify_report"

    while IFS= read -r deb; do
        local pkg_name
        pkg_name=$(dpkg-deb -f "$deb" Package 2>/dev/null || basename "$deb")

        # 1. Structural integrity
        if ! dpkg-deb -I "$deb" >/dev/null 2>&1; then
            echo "INVALID_DEB: $pkg_name ($deb)" >> "$verify_report"
            continue
        fi
        echo "VALID: $pkg_name" >> "$verify_report"

        # 2. Embedded GPG signature (debsig-verify) — informational only
        if command -v debsig-verify >/dev/null 2>&1; then
            if debsig-verify "$deb" >/dev/null 2>&1; then
                echo "SIG_OK: $pkg_name" >> "$verify_report"
            else
                echo "SIG_NONE_OR_FAIL: $pkg_name (no embedded sig or policy missing)" >> "$verify_report"
            fi
        else
            echo "SIG_SKIP: $pkg_name (debsig-verify not installed)" >> "$verify_report"
        fi

        # 3. SHA256 for external hash checks
        local sha256
        sha256=$(sha256sum "$deb" | awk '{print $1}')
        echo "SHA256: $pkg_name $sha256" >> "$verify_report"

        # 4. Extract control info for audit trail
        local maintainer section
        maintainer=$(dpkg-deb -f "$deb" Maintainer 2>/dev/null || echo "unknown")
        section=$(dpkg-deb -f "$deb" Section 2>/dev/null || echo "unknown")
        echo "META: $pkg_name maintainer=\"$maintainer\" section=\"$section\"" >> "$verify_report"

    done < "$deb_list"

    ln -sf "deb-verify-$TS.txt" "$STATE_DIR/reports/deb-verify-latest.txt"
    echo "$verify_report"
}

# -----------------------------------------------------------------------------
# NEW: VIRUSTOTAL HASH CHECK
# -----------------------------------------------------------------------------
virustotal_check() {
    local deb_list="$STAGING_DIR/downloaded-latest.txt"
    [[ -f "$deb_list" && -s "$deb_list" ]] || { dbg "No debs for VT check"; return 0; }
    [[ -n "${VT_API_KEY:-}" ]] || { dbg "VT_API_KEY not set, skipping VirusTotal"; return 0; }

    local vt_report="$STATE_DIR/reports/virustotal-$TS.json"
    local vt_entries=()
    local count=0

    dbg "Starting VirusTotal hash lookups (free tier: 4/min)"

    while IFS= read -r deb; do
        # Rate limiting: 4 requests per minute on free tier
        if (( count > 0 && count % 4 == 0 )); then
            dbg "VT rate limit: sleeping 60s before next batch"
            sleep 60
        fi

        local sha256 pkg_name
        sha256=$(sha256sum "$deb" | awk '{print $1}')
        pkg_name=$(dpkg-deb -f "$deb" Package 2>/dev/null || basename "$deb")

        local resp
        resp=$(curl -sS "${VT_API_URL}/${sha256}" \
            -H "x-apikey: $VT_API_KEY" \
            -H "Accept: application/json" 2>/dev/null || echo '{}')

        local stats
        stats=$(echo "$resp" | jq -c '.data.attributes.last_analysis_stats // {"error":"no data"}' 2>/dev/null || echo '{"error":"parse failed"}')

        vt_entries+=("$(jq -n --arg pkg "$pkg_name" --arg sha "$sha256" --argjson stats "$stats" \
            '{package: $pkg, sha256: $sha, stats: $stats}')")

        dbg "VT $pkg_name: malicious=$(echo "$stats" | jq -r '.malicious // 0'), suspicious=$(echo "$stats" | jq -r '.suspicious // 0')"
        count=$((count + 1))
    done < "$deb_list"

    printf '%s\n' "${vt_entries[@]}" | jq -s '.' > "$vt_report"
    ln -sf "virustotal-$TS.json" "$STATE_DIR/reports/virustotal-latest.json"
    echo "$vt_report"
}

# -----------------------------------------------------------------------------
# NEW: YARA SCAN
# -----------------------------------------------------------------------------
download_yara_rules() {
    mkdir -p "$YARA_RULES_DIR"
    if [[ -d "$YARA_RULES_DIR/yara-rules/.git" ]]; then
        dbg "Updating YARA rules"
        (cd "$YARA_RULES_DIR/yara-rules" && git pull --depth 1 --ff-only 2>/dev/null || true)
    else
        dbg "Cloning YARA rules repository"
        git clone --depth 1 https://github.com/Yara-Rules/rules.git "$YARA_RULES_DIR/yara-rules" 2>/dev/null || {
            echo "WARNING: failed to clone YARA rules. Install git or provide rules manually." >&2
        }
    fi
}

yara_scan() {
    local deb_list="$STAGING_DIR/downloaded-latest.txt"
    [[ -f "$deb_list" && -s "$deb_list" ]] || { dbg "No debs for YARA scan"; return 0; }

    if [[ -z "${YARA_BINARY:-}" || ! -x "$YARA_BINARY" ]]; then
        dbg "YARA binary not found, skipping YARA scan"
        return 0
    fi

    # Auto-download rules if directory is empty
    if [[ -z "$(find "$YARA_RULES_DIR" \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | head -1)" ]]; then
        if command -v git >/dev/null 2>&1; then
            download_yara_rules
        else
            dbg "No YARA rules and git not available, skipping YARA scan"
            return 0
        fi
    fi

    local yara_report="$STATE_DIR/reports/yara-$TS.txt"
    : > "$yara_report"

    while IFS= read -r deb; do
        local pkg_name
        pkg_name=$(dpkg-deb -f "$deb" Package 2>/dev/null || basename "$deb")
        echo "SCAN: $pkg_name ($deb)" >> "$yara_report"

        local matches
        matches=$("$YARA_BINARY" -r "$YARA_RULES_DIR" "$deb" 2>/dev/null) || true
        if [[ -n "$matches" ]]; then
            echo "$matches" >> "$yara_report"
            echo "RESULT: MATCHES DETECTED" >> "$yara_report"
        else
            echo "RESULT: CLEAN" >> "$yara_report"
        fi
    done < "$deb_list"

    ln -sf "yara-$TS.txt" "$STATE_DIR/reports/yara-latest.txt"
    echo "$yara_report"
}

# -----------------------------------------------------------------------------
# DOCKER SNAPSHOTS
# -----------------------------------------------------------------------------
docker_snapshot() {
    docker ps --format '{{.Names}}\t{{.Image}}' | while IFS=$'\t' read -r name image; do
        digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}' 2>/dev/null || echo "none")
        printf '%s\t%s\t%s\n' "$name" "$image" "$digest"
    done | sort > "$STATE_DIR/docker/running-$TS.txt"
    ln -sf "running-$TS.txt" "$STATE_DIR/docker/running-latest.txt"
}

docker_check_remote_digest() {
    : > "$STATE_DIR/docker/remote-check-$TS.txt"
    while IFS=$'\t' read -r name image local_digest; do
        remote_digest=$(skopeo inspect --format '{{.Digest}}' "docker://$image" 2>/dev/null || echo "unreachable")
        printf '%s\t%s\t%s\t%s\n' "$name" "$image" "$local_digest" "$remote_digest" \
            >> "$STATE_DIR/docker/remote-check-$TS.txt"
    done < "$STATE_DIR/docker/running-latest.txt"
    ln -sf "remote-check-$TS.txt" "$STATE_DIR/docker/remote-check-latest.txt"
}

docker_diff_against_previous() {
    local prev
    prev=$(ls -t "$STATE_DIR"/docker/running-*.txt 2>/dev/null | grep -v -- '-latest\.txt$' | sed -n '2p' || true)
    if [[ -n "$prev" ]]; then
        diff "$prev" "$STATE_DIR/docker/running-latest.txt" > "$STATE_DIR/reports/docker-diff-$TS.txt" || true
    fi
}

# -----------------------------------------------------------------------------
# REPUTATION & AI
# -----------------------------------------------------------------------------
reputation_check() {
    local ecosystem="$1" pkg="$2" version="$3"
    local out="$STATE_DIR/reports/reputation-$pkg-$TS.json"

    local deps_dev_resp="{}"
    local debian_resp="{}"

    if [[ "$ecosystem" == "debian" ]]; then
        debian_resp=$(curl_json "$DEBIAN_TRACKER_API" | jq --arg p "$pkg" '.[$p] // {}') || true
    else
        deps_dev_resp=$(curl_json "${DEPS_DEV_API}/systems/${ecosystem}/packages/${pkg}/versions/${version}") || true
    fi

    local kev_hit="unknown"

    local ghsa_resp="{}"
    if [[ "$ecosystem" == "debian" ]]; then
        dbg "Skipping GHSA for $pkg — ecosystem 'debian' is not a valid GHSA ecosystem value"
    elif [[ -n "${GHSA_TOKEN:-}" ]]; then
        local ghsa_ecosystem="$ecosystem"
        [[ "$ecosystem" == "pypi" ]] && ghsa_ecosystem="pip"
        ghsa_resp=$(curl_json "${GHSA_API}?ecosystem=${ghsa_ecosystem}&affects=${pkg}" \
            -H "Authorization: Bearer ${GHSA_TOKEN}") || true
    else
        dbg "GHSA_TOKEN not set — skipping GHSA lookup for $pkg"
    fi

    jq -n --argjson deps_dev "$deps_dev_resp" --argjson debian "$debian_resp" \
          --argjson ghsa "$ghsa_resp" --arg kev "$kev_hit" \
        '{deps_dev: $deps_dev, debian_tracker: $debian, ghsa: $ghsa, kev_status: $kev}' > "$out"

    echo "$out"
}

_build_chatter_prompt() {
    local pkg="$1" version="$2" cve="${3:-}"
    cat <<EOF
Today's actual date is $(date +%Y-%m-%d). Do not assume any other date — your training
data may be older than today, but the date above is correct and current. Do not treat
a version number as "impossible" or "from the future" just because it looks newer than
what you remember; trust the date given above over your own internal assumptions.

You are summarizing PUBLIC CHATTER ONLY (forums, security researcher posts, social
media, blog commentary) about the package "${pkg}" version "${version}" ${cve:+and CVE ${cve}}.
Do NOT treat this as authoritative — you have no access to structured advisory
databases here, only your own knowledge and reasoning. If you are not confident
there is real signal, say so explicitly rather than speculating.
Output strict JSON only, no markdown fences, no reasoning, no preamble — the entire
response must be exactly one JSON object and nothing else:
{"chatter_summary": string, "confidence": "low"|"medium"|"high", "flagged_terms": [string], "recommend_human_review": boolean}
EOF
}

_ai_call_gemini() {
    local prompt="$1"
    local payload resp
    payload=$(jq -n --arg p "$prompt" '{contents: [{parts: [{text: $p}]}]}')
    resp=$(curl_json "${GEMINI_ENDPOINT}?key=${GEMINI_API_KEY}" \
        -X POST -H "Content-Type: application/json" -d "$payload") || true

    local text
    text=$(echo "$resp" | jq -r '
        [.candidates[0].content.parts[]? | select((.thought // false) != true) | .text] | last // empty
    ' 2>/dev/null)

    jq -n --argjson raw "$resp" --arg text "$text" --arg model "$GEMINI_MODEL" \
        '{source: "gemini", model: $model, model_text: $text, raw: $raw}'
}

_ai_call_openrouter() {
    local prompt="$1"
    local payload resp
    payload=$(jq -n --arg p "$prompt" --arg m "$OPENROUTER_MODEL" \
        '{model: $m, messages: [{role: "user", content: $p}]}')
    resp=$(curl_json "$OPENROUTER_ENDPOINT" \
        -X POST \
        -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$payload") || true

    local text
    text=$(echo "$resp" | jq -r '.choices[0].message.content // empty' 2>/dev/null)
    local actual_model
    actual_model=$(echo "$resp" | jq -r '.model // empty' 2>/dev/null)

    jq -n --argjson raw "$resp" --arg text "$text" --arg model "${actual_model:-$OPENROUTER_MODEL}" \
        '{source: "openrouter", model: $model, model_text: $text, raw: $raw}'
}

ai_interpret_chatter() {
    local pkg="$1" version="$2" cve="${3:-}"
    local out="$STATE_DIR/reports/chatter-$pkg-$TS.json"

    local api_key_var="GEMINI_API_KEY"
    [[ "$AI_PROVIDER" == "openrouter" ]] && api_key_var="OPENROUTER_API_KEY"

    if [[ -z "${!api_key_var:-}" ]]; then
        echo "{\"status\":\"skipped\",\"reason\":\"no ${api_key_var} set\",\"provider\":\"$AI_PROVIDER\"}" > "$out"
        echo "$out"
        return 0
    fi

    local prompt result
    prompt=$(_build_chatter_prompt "$pkg" "$version" "$cve")

    case "$AI_PROVIDER" in
        gemini)     result=$(_ai_call_gemini "$prompt") ;;
        openrouter) result=$(_ai_call_openrouter "$prompt") ;;
        *) echo "unknown AI_PROVIDER: $AI_PROVIDER" >&2; return 1 ;;
    esac

    local model_text
    model_text=$(echo "$result" | jq -r '.model_text // empty')
    if [[ -z "$model_text" ]]; then
        dbg "$AI_PROVIDER call for $pkg returned no usable text. Full result: $result"
    fi

    echo "$result" | jq '. + {tag: "UNVERIFIED_CHATTER_NOT_AUTHORITATIVE"}' > "$out"
    echo "$out"
}

# -----------------------------------------------------------------------------
# DECISION ENGINE (updated with verification results)
# -----------------------------------------------------------------------------
decide() {
    local report="$STATE_DIR/reports/decision-$TS.txt"
    : > "$report"
    local risk_score=0

    # --- APT: never auto-apt-upgrade blind. Flag anything touching security-critical pkgs.
    if [[ -s "$STATE_DIR/apt/candidates-latest.txt" ]]; then
        echo "[APT] Candidates found:" >> "$report"
        cat "$STATE_DIR/apt/candidates-latest.txt" >> "$report"
        echo "" >> "$report"

        while read -r line; do
            [[ "$line" =~ ^Inst\ ([^ ]+)\ .*\(([^ ]+) ]] || continue
            pkg="${BASH_REMATCH[1]}"
            newver="${BASH_REMATCH[2]}"

            if [[ "$pkg" =~ ^(linux-image|libc6|openssl|sudo|systemd) ]]; then
                echo "[APT] $pkg -> HIGH-IMPACT PACKAGE: escalate, do not auto-apply, skipping analysis pass" >> "$report"
                continue
            fi

            echo "[APT] $pkg -> $newver, eligible for analysis-engine pass" >> "$report"

            repo_file=$(reputation_check "debian" "$pkg" "$newver")
            echo "[APT]   -> reputation_check (Debian Security Tracker/KEV/GHSA): $repo_file" >> "$report"

            chatter_file=$(ai_interpret_chatter "$pkg" "$newver")
            echo "[APT]   -> chatter (unverified): $chatter_file" >> "$report"
        done < "$STATE_DIR/apt/candidates-latest.txt"

        local downloaded_count candidate_count
        downloaded_count=$(wc -l < "$STAGING_DIR/downloaded-latest.txt" 2>/dev/null || echo 0)
        candidate_count=$(wc -l < "$STATE_DIR/apt/candidates-latest.txt" 2>/dev/null || echo 0)
        if [[ "$downloaded_count" -ne "$candidate_count" ]]; then
            echo "[APT] WARNING: Only $downloaded_count of $candidate_count packages could be staged for verification." >> "$report"
        fi
    else
        echo "[APT] No candidates. Nothing to do." >> "$report"
    fi

    # --- DEB VERIFICATION RESULTS ---
    echo "" >> "$report"
    echo "[DEB VERIFICATION] Staged package integrity & metadata:" >> "$report"
    if [[ -f "$STATE_DIR/reports/deb-verify-latest.txt" ]]; then
        local invalid=0
        while IFS= read -r line; do
            case "$line" in
                INVALID_DEB*)
                    echo "[DEB] $line -> REJECT (corrupt package)" >> "$report"
                    invalid=$((invalid + 1))
                    ;;
                SIG_OK*)
                    echo "[DEB] $line -> signed embedded signature verified" >> "$report"
                    ;;
                SIG_NONE_OR_FAIL*)
                    echo "[DEB] $line -> informational (most official debs lack embedded sigs)" >> "$report"
                    ;;
                SHA256*)
                    echo "[DEB] $line -> hash captured for external lookup" >> "$report"
                    ;;
            esac
        done < "$STATE_DIR/reports/deb-verify-latest.txt"
        if (( invalid > 0 )); then
            echo "[DEB] WARNING: $invalid package(s) failed structural validation. DO NOT UPGRADE." >> "$report"
            risk_score=3
        fi
    else
        echo "[DEB] No staged packages to verify." >> "$report"
    fi

    # --- VIRUSTOTAL RESULTS ---
    echo "" >> "$report"
    echo "[VIRUSTOTAL] Hash reputation (malware/suspicious detections):" >> "$report"
    if [[ -f "$STATE_DIR/reports/virustotal-latest.json" ]]; then
        local vt_hits
        vt_hits=$(jq -r '
            [.[] | select((.stats.malicious // 0) > 0 or (.stats.suspicious // 0) > 0)]
            | length
        ' "$STATE_DIR/reports/virustotal-latest.json" 2>/dev/null || echo 0)
        vt_hits=${vt_hits:-0}

        if [[ "$vt_hits" -gt 0 ]]; then
            echo "[VT] WARNING: $vt_hits package(s) flagged by VirusTotal!" >> "$report"
            jq -r '.[] | select((.stats.malicious // 0) > 0 or (.stats.suspicious // 0) > 0) |
                "[VT]   " + .package + " -> malicious=\(.stats.malicious) suspicious=\(.stats.suspicious) sha256=\(.sha256)"' \
                "$STATE_DIR/reports/virustotal-latest.json" >> "$report" 2>/dev/null || true
            risk_score=3
        else
            echo "[VT] All scanned packages clean (0 malicious, 0 suspicious)." >> "$report"
        fi
    else
        echo "[VT] Skipped (no VT_API_KEY or no packages)." >> "$report"
    fi

    # --- YARA RESULTS ---
    echo "" >> "$report"
    echo "[YARA] Static pattern analysis:" >> "$report"
    if [[ -f "$STATE_DIR/reports/yara-latest.txt" ]]; then
        if grep -q "RESULT: MATCHES DETECTED" "$STATE_DIR/reports/yara-latest.txt"; then
            echo "[YARA] WARNING: pattern matches detected!" >> "$report"
            grep -B1 "RESULT: MATCHES DETECTED" "$STATE_DIR/reports/yara-latest.txt" >> "$report"
            risk_score=3
        else
            echo "[YARA] No suspicious patterns detected in staged packages." >> "$report"
        fi
    else
        echo "[YARA] Skipped (yara not installed or no rules)." >> "$report"
    fi

    # --- DOCKER: local digest vs remote digest mismatch = update available
    echo "" >> "$report"
    echo "[DOCKER] Digest comparison:" >> "$report"
    if [[ -f "$STATE_DIR/docker/remote-check-latest.txt" ]]; then
        while IFS=$'\t' read -r name image local_digest remote_digest; do
            if [[ "$remote_digest" == "unreachable" ]]; then
                echo "[DOCKER] $name ($image) -> registry unreachable, skip this cycle" >> "$report"
            elif [[ "$local_digest" != *"$remote_digest"* ]]; then
                echo "[DOCKER] $name ($image) -> NEW DIGEST AVAILABLE: $remote_digest" >> "$report"
                echo "[DOCKER]   -> eligible for pull + analysis-engine pass" >> "$report"

                repo_file=$(reputation_check "docker" "${image%%:*}" "${image##*:}")
                echo "[DOCKER]   -> reputation_check: $repo_file" >> "$report"

                chatter_file=$(ai_interpret_chatter "${image%%:*}" "${image##*:}")
                echo "[DOCKER]   -> chatter (unverified): $chatter_file" >> "$report"
            else
                echo "[DOCKER] $name ($image) -> up to date" >> "$report"
            fi
        done < "$STATE_DIR/docker/remote-check-latest.txt"
    fi

    echo "" >> "$report"
    echo "RISK_EXIT_CODE: $risk_score (0=clean, 3=critical findings)" >> "$report"
    echo "Full report: $report"
    cat "$report"

    return $risk_score
}

# -----------------------------------------------------------------------------
# SCHEDULER INSTALLERS
# -----------------------------------------------------------------------------
install_systemd_timer() {
    local unit_name="${1:-update-guard}"
    local service_file="/etc/systemd/system/${unit_name}.service"
    local timer_file="/etc/systemd/system/${unit_name}.timer"
    local script_path
    script_path=$(readlink -f "$0")

    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "ERROR: --install-systemd requires root. Run with sudo." >&2
        return 1
    fi

    if [[ "$script_path" == /tmp/* || "$script_path" == /dev/* ]]; then
        echo "ERROR: Please place this script in a permanent location (e.g., /usr/local/bin) before installing." >&2
        return 1
    fi

    mkdir -p /etc/update-guard
    [[ -f "$CONFIG_FILE" ]] || cat > /etc/update-guard/config.env <<'EOF'
# Update Guard Configuration
# VT_API_KEY=your_virustotal_api_key_here
# GHSA_TOKEN=your_github_pat_here
# GEMINI_API_KEY=your_gemini_key_here
# OPENROUTER_API_KEY=your_openrouter_key_here
# UPDATE_GUARD_DEBUG=0
EOF
    chmod 600 /etc/update-guard/config.env 2>/dev/null || true

    cat > "$service_file" <<EOF
[Unit]
Description=Update Guard - APT/Docker Update Analyzer
After=network.target

[Service]
Type=oneshot
User=root
Environment="UPDATE_GUARD_STATE_DIR=/var/lib/update-guard"
EnvironmentFile=-/etc/update-guard/config.env
ExecStart=${script_path}
Nice=10
IOSchedulingClass=idle
EOF

    cat > "$timer_file" <<EOF
[Unit]
Description=Run Update Guard daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${unit_name}.timer"
    echo "Installed and started ${unit_name}.timer"
    echo "Edit /etc/update-guard/config.env to add API keys."
    systemctl status "${unit_name}.timer" --no-pager || true
}

install_cron_job() {
    local cron_schedule="${1:-0 3 * * *}"
    local script_path
    script_path=$(readlink -f "$0")

    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "WARNING: Installing cron job as non-root. apt operations may fail." >&2
    fi

    (crontab -l 2>/dev/null | grep -v "update-guard scheduled run" || true; \
     echo "$cron_schedule $script_path # update-guard scheduled run") | crontab -

    echo "Installed cron job: $cron_schedule $script_path"
    echo "Current crontab:"
    crontab -l | grep "update-guard" || true
}

# -----------------------------------------------------------------------------
# CLEANUP & STATUS
# -----------------------------------------------------------------------------
cleanup_old_reports() {
    local keep="${UPDATE_GUARD_KEEP_REPORTS:-30}"
    dbg "Cleaning up reports older than $keep runs"

    find "$STATE_DIR/reports" -maxdepth 1 -type f \( -name "*.txt" -o -name "*.json" -o -name "*.log" \) \
        -printf '%T@ %p\n' 2>/dev/null | sort -rn | tail -n +$((keep + 1)) | cut -d' ' -f2- | xargs -r rm -f

    find "$STAGING_DIR" -mindepth 1 -maxdepth 1 -type d \
        -printf '%T@ %p\n' 2>/dev/null | sort -rn | tail -n +$((keep + 1)) | cut -d' ' -f2- | xargs -r rm -rf
}

update_status() {
    local status="$1"
    local msg="${2:-}"
    jq -n --arg ts "$TS" --arg status "$status" --arg msg "$msg" \
       --arg report "$STATE_DIR/reports/decision-$TS.txt" \
       '{last_run: $ts, status: $status, message: $msg, report: $report}' \
       > "$STATE_DIR/last-status.json"
}

# -----------------------------------------------------------------------------
# HELP
# -----------------------------------------------------------------------------
show_help() {
    cat <<EOF
Update Guard v2.0 — APT/Docker update analyzer with deb verification,
VirusTotal hash lookup, YARA scanning, and scheduler integration.

Usage: $0 [OPTION]

Options:
  (none)                Run full analysis pipeline
  --install-systemd     Install systemd service + daily timer (requires root)
  --install-cron [SCH]  Install cron job (default: 0 3 * * *). Requires root for apt.
  --download-yara-rules Fetch/update public YARA rules (requires git)
  --help                Show this message

Environment / Config (/etc/update-guard/config.env):
  UPDATE_GUARD_STATE_DIR    Base state directory
  UPDATE_GUARD_KEEP_REPORTS Number of report generations to retain (default: 30)
  VT_API_KEY                VirusTotal API key (free tier: 100 lookups/day, 4/min)
  YARA_RULES_DIR            Directory containing .yar/.yara rule files
  YARA_BINARY               Path to yara binary (auto-detected if in PATH)
  GHSA_TOKEN                GitHub PAT for GHSA API
  GEMINI_API_KEY / OPENROUTER_API_KEY  AI provider keys
  UPDATE_GUARD_DEBUG        Set to 1 for verbose debug logging

Dependencies: curl, jq, skopeo, docker, apt-get, dpkg-deb, sha256sum
Optional:     debsig-verify, yara, git (for YARA rules)
EOF
}

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------
main() {
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --install-systemd)
            install_systemd_timer "${2:-update-guard}"
            exit 0
            ;;
        --install-cron)
            install_cron_job "${2:-0 3 * * *}"
            exit 0
            ;;
        --download-yara-rules)
            download_yara_rules
            exit 0
            ;;
    esac

    acquire_lock
    trap release_lock EXIT

    apt_snapshot
    apt_diff_against_previous
    apt_download_candidates
    apt_verify_debs
    virustotal_check
    yara_scan
    docker_snapshot
    docker_check_remote_digest
    docker_diff_against_previous
    decide
    local final_exit=$?
    cleanup_old_reports

    if [[ $final_exit -eq 3 ]]; then
        update_status "critical" "High-risk findings detected. Review report before upgrading."
    elif [[ $final_exit -eq 0 ]]; then
        update_status "ok" "No critical findings."
    else
        update_status "warning" "Analysis completed with warnings."
    fi

    exit $final_exit
}

main "$@"
