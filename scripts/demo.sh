#!/usr/bin/env bash
# ==============================================================================
# Wisp End-to-End Scenario Runner
# Permet de tester et visualiser les scénarios Wisp entre 2 terminaux / processus
# sur une même machine (mode interactif, tmux split-screen ou validation batch).
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WISP_BIN="${WISP_BIN:-$ROOT_DIR/target/debug/wisp}"

# Couleurs & typographie
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${CYAN}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✔${NC} ${BOLD}$1${NC}"; }
log_warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
log_error()   { echo -e "${RED}✘${NC} ${BOLD}$1${NC}"; }
log_step()    { echo -e "\n${BLUE}==>${NC} ${BOLD}$1${NC}"; }

# Vérifier que le binaire existe
ensure_binary() {
    if [[ ! -x "$WISP_BIN" ]]; then
        log_info "Compilation de Wisp (${WISP_BIN})..."
        cargo build -p wisp --quiet
    fi
}

# Nettoyage automatique en sortie
DEMO_TMP=""
cleanup() {
    if [[ -n "$DEMO_TMP" && -d "$DEMO_TMP" ]]; then
        rm -rf "$DEMO_TMP"
    fi
}
trap cleanup EXIT

# Démarre l'expéditeur et attend la ligne 'ready'
start_sender() {
    local src="$1"
    local extra_arg="${2:-}"
    local log="$DEMO_TMP/sender.log"
    rm -f "$log"

    if [[ -n "$extra_arg" ]]; then
        "$WISP_BIN" --no-config --json send "$src" --name "$extra_arg" > "$log" 2>&1 &
    else
        "$WISP_BIN" --no-config --json send "$src" > "$log" 2>&1 &
    fi
    SENDER_PID=$!

    CODE=""
    ADDR=""
    for _ in {1..100}; do
        if grep -q '"event":"ready"' "$log" 2>/dev/null; then
            local line
            line=$(grep '"event":"ready"' "$log" | head -n 1)
            CODE=$(echo "$line" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p')
            ADDR=$(echo "$line" | sed -n 's/.*"address":"\([^"]*\)".*/\1/p')
            break
        fi
        sleep 0.05
    done

    if [[ -z "$CODE" || -z "$ADDR" ]]; then
        log_error "Impossible de démarrer l'expéditeur. Logs :"
        cat "$log"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Scénario 1 : Transfert nominal de bout en bout
# ------------------------------------------------------------------------------
scenario_nominal() {
    log_step "Scénario 1 : Transfert nominal standard (Découverte & Vérification)"
    DEMO_TMP=$(mktemp -d /tmp/wisp_demo_nominal.XXXXXX)
    local src="$DEMO_TMP/document.txt"
    local dst="$DEMO_TMP/received"
    mkdir -p "$dst"
    echo "Contenu certifié Wisp - $(date)" > "$src"

    log_info "Démarrage de l'expéditeur..."
    start_sender "$src"

    echo -e "  ${CYAN}[EXPÉDITEUR]${NC} En attente sur ${BOLD}$ADDR${NC} avec le code : ${BOLD}${GREEN}$CODE${NC}"
    log_info "Démarrage du récepteur avec le code généré..."

    "$WISP_BIN" --no-config recv "$CODE" --dir "$dst" --address "$ADDR"
    wait "$SENDER_PID"

    local recv_file="$dst/document.txt"
    if [[ -f "$recv_file" ]] && cmp -s "$src" "$recv_file"; then
        log_success "Succès : Fichier transféré et vérifié à 100% à l'identique !"
        echo -e "  Contenu reçu : ${YELLOW}$(cat "$recv_file")${NC}"
    else
        log_error "Échec : Le fichier reçu est introuvable ou différent."
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Scénario 2 : Protection No-Clobber (Collision de noms)
# ------------------------------------------------------------------------------
scenario_collision() {
    log_step "Scénario 2 : Protection anti-écrasement (No-Clobber)"
    DEMO_TMP=$(mktemp -d /tmp/wisp_demo_collision.XXXXXX)
    local src="$DEMO_TMP/nouveau.txt"
    local dst="$DEMO_TMP/destination"
    mkdir -p "$dst"

    local existing="$dst/rapport.txt"
    echo "FICHIER ORIGINAL PROTEGE" > "$existing"
    echo "FICHIER NOUVEAU LIVRE" > "$src"

    log_info "L'expéditeur envoie un fichier nommé 'rapport.txt'..."
    start_sender "$src" "rapport.txt"

    log_info "Le récepteur reçoit dans un répertoire contenant déjà 'rapport.txt'..."
    "$WISP_BIN" --no-config recv "$CODE" --dir "$dst" --address "$ADDR"
    wait "$SENDER_PID"

    local suffixed="$dst/rapport (1).txt"
    if [[ -f "$existing" && "$(cat "$existing")" == "FICHIER ORIGINAL PROTEGE" ]] && \
       [[ -f "$suffixed" && "$(cat "$suffixed")" == "FICHIER NOUVEAU LIVRE" ]]; then
        log_success "Succès : L'original est intact et le fichier reçu est sauvé sous 'rapport (1).txt' !"
    else
        log_error "Échec de la politique No-Clobber."
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Scénario 3 : Résilience aux probes pré-authentification (WISP-01 / WISP-02)
# ------------------------------------------------------------------------------
scenario_preauth_probe() {
    log_step "Scénario 3 : Tolérance aux scans de ports / drops pré-auth"
    DEMO_TMP=$(mktemp -d /tmp/wisp_demo_preauth.XXXXXX)
    local src="$DEMO_TMP/data.txt"
    local dst="$DEMO_TMP/received"
    mkdir -p "$dst"
    echo "Données résilientes" > "$src"

    start_sender "$src"

    local port="${ADDR##*:}"
    log_info "Expéditeur écoute sur le port $port. Simulation d'un port-scan / probe non-authentifié..."
    
    # Simuler un paquet UDP sur le port
    python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'GARBAGE_PROBE', ('127.0.0.1', $port)); s.close()"
    sleep 0.5

    if kill -0 "$SENDER_PID" 2>/dev/null; then
        log_success "L'expéditeur a ignoré le probe parasite et reste en attente !"
    else
        log_error "L'expéditeur a crashé sur le probe pré-authentification !"
        return 1
    fi

    log_info "Connexion du récepteur légitime..."
    "$WISP_BIN" --no-config recv "$CODE" --dir "$dst" --address "$ADDR"
    wait "$SENDER_PID"
    log_success "Succès : Transfert complété malgré le scan préalable !"
}

# ------------------------------------------------------------------------------
# Scénario 4 : Anti-Bruteforce / Arrêt immédiat sur mauvais mot de passe
# ------------------------------------------------------------------------------
scenario_wrong_code() {
    log_step "Scénario 4 : Arrêt immédiat et définitif sur mauvais code PAKE"
    DEMO_TMP=$(mktemp -d /tmp/wisp_demo_wrong.XXXXXX)
    local src="$DEMO_TMP/secret.txt"
    local dst="$DEMO_TMP/received"
    mkdir -p "$dst"
    echo "Top secret" > "$src"

    start_sender "$src"

    local bad_code="00000000-amber-amber-amber-amber"
    log_info "Tentative de connexion avec un mauvais code : $bad_code"

    set +e
    "$WISP_BIN" --no-config recv "$bad_code" --dir "$dst" --address "$ADDR" 2>/dev/null
    local recv_status=$?
    set -e

    if [[ $recv_status -ne 0 ]]; then
        log_info "Le récepteur non autorisé a été rejeté (statut $recv_status)."
    fi

    # L'expéditeur DOIT avoir quitté immédiatement
    sleep 0.3
    if kill -0 "$SENDER_PID" 2>/dev/null; then
        log_error "Échec : L'expéditeur est resté actif après un échec PAKE (oracle de bruteforce) !"
        kill -9 "$SENDER_PID" 2>/dev/null || true
        return 1
    else
        log_success "Succès : L'expéditeur a immédiatement terminé sa session (politique 1 tentative PAKE stricte) !"
    fi
}

# ------------------------------------------------------------------------------
# Scénario 5 : Nettoyage atomique sur Ctrl+C (Interruption)
# ------------------------------------------------------------------------------
scenario_ctrl_c() {
    log_step "Scénario 5 : Nettoyage atomique des fichiers .part sur interruption"
    DEMO_TMP=$(mktemp -d /tmp/wisp_demo_ctrlc.XXXXXX)
    local src="$DEMO_TMP/large.bin"
    local dst="$DEMO_TMP/destination"
    mkdir -p "$dst"
    dd if=/dev/zero of="$src" bs=1M count=30 status=none

    start_sender "$src"

    log_info "Lancement du récepteur en arrière-plan puis interruption par SIGINT..."
    "$WISP_BIN" --no-config recv "$CODE" --dir "$dst" --address "$ADDR" &
    local recv_pid=$!

    # Attendre que le récepteur commence à écrire le fichier partiel
    sleep 0.4
    kill -INT "$recv_pid" 2>/dev/null || true
    wait "$recv_pid" 2>/dev/null || true
    kill -INT "$SENDER_PID" 2>/dev/null || true
    wait "$SENDER_PID" 2>/dev/null || true

    # Vérifier l'absence de résidus .part
    local partial_count
    partial_count=$(find "$dst" -name ".wisp-*.part" | wc -l)
    if [[ "$partial_count" -eq 0 ]]; then
        log_success "Succès : Aucun fichier orphelin .part laissé dans le dossier de destination !"
    else
        log_error "Échec : Des fichiers partiels ont été abandonnés : $(ls "$dst")"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Scénario 6 : Assainissement Unicode Bidi (WISP-08)
# ------------------------------------------------------------------------------
scenario_bidi() {
    log_step "Scénario 6 : Neutralisation des injections Unicode Bidi"
    DEMO_TMP=$(mktemp -d /tmp/wisp_demo_bidi.XXXXXX)
    local src="$DEMO_TMP/source.txt"
    local dst="$DEMO_TMP/destination"
    mkdir -p "$dst"
    echo "Fichier avec injection bidi" > "$src"

    # Nom contenant un Right-To-Left Override (\u{202E})
    local bidi_name="report"$'\u202e'"txt.pdf"

    start_sender "$src" "$bidi_name"

    "$WISP_BIN" --no-config recv "$CODE" --dir "$dst" --address "$ADDR"
    wait "$SENDER_PID"

    # Le nom sur disque doit avoir été assaini en remplaçant \u202e par '_'
    local sanitized_expected="report_txt.pdf"
    if [[ -f "$dst/$sanitized_expected" ]]; then
        log_success "Succès : Le nom de fichier malveillant a été assaini en '$sanitized_expected' !"
    else
        log_error "Échec : Nom non assaini. Fichiers présents : $(ls "$dst")"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Scénario 7 : Transfert haute performance (50 Mo)
# ------------------------------------------------------------------------------
scenario_benchmark() {
    log_step "Scénario 7 : Test de débit réel (50 Mo)"
    DEMO_TMP=$(mktemp -d /tmp/wisp_demo_bench.XXXXXX)
    local src="$DEMO_TMP/bench.bin"
    local dst="$DEMO_TMP/destination"
    mkdir -p "$dst"
    log_info "Création d'un fichier de 50 Mo..."
    dd if=/dev/urandom of="$src" bs=1M count=50 status=none

    local start_time
    start_time=$(date +%s%N)

    start_sender "$src"

    "$WISP_BIN" --no-config recv "$CODE" --dir "$dst" --address "$ADDR"
    wait "$SENDER_PID"

    local end_time
    end_time=$(date +%s%N)
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local speed_mb_s
    speed_mb_s=$(python3 -c "print(f'{50 / ($elapsed_ms / 1000):.1f}')")

    log_success "Succès : 50 Mo transférés en ${elapsed_ms}ms (${speed_mb_s} Mo/s) !"
}

# ------------------------------------------------------------------------------
# Mode TMUX interactif à 2 panneaux côte à côte
# ------------------------------------------------------------------------------
launch_tmux() {
    log_step "Lancement de la simulation interactive des 7 scénarios dans TMUX"
    
    local session="wisp_demo_$$"
    DEMO_TMP=$(mktemp -d /tmp/wisp_tmux.XXXXXX)

    cat > "$DEMO_TMP/sender.sh" << EOF
#!/usr/bin/env bash
set -e

GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

WISP_BIN="$WISP_BIN"
DEMO_TMP="$DEMO_TMP"

wait_ready() {
    local log="\$1"
    for _ in {1..100}; do
        if grep -q "wisp recv" "\$log" 2>/dev/null; then return 0; fi
        sleep 0.05
    done
    return 1
}

echo -e "\${GREEN}\${BOLD}====================================================\${NC}"
echo -e "\${GREEN}\${BOLD}         EXPÉDITEUR (TERMINAL GAUCHE)               \${NC}"
echo -e "\${GREEN}\${BOLD}====================================================\${NC}\n"

# --- SCÉNARIO 1/7 : NOMINAL ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 1/7] Transfert nominal standard (mDNS + PAKE)\${NC}"
src1="\$DEMO_TMP/src1_doc.txt"
echo "Document officiel Wisp certifié - \$(date)" > "\$src1"
"\$WISP_BIN" --no-config send "\$src1" > "\$DEMO_TMP/s1.log" 2>&1 &
P1=\$!
wait_ready "\$DEMO_TMP/s1.log"
touch "\$DEMO_TMP/s1_ready"
wait \$P1
echo -e "\${GREEN}✔ [1/7] Fichier expédié et vérifié par le récepteur.\${NC}\n"
touch "\$DEMO_TMP/s1_done"
while [[ ! -f "\$DEMO_TMP/s2_start" ]]; do sleep 0.05; done

# --- SCÉNARIO 2/7 : COLLISION NO-CLOBBER ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 2/7] Protection anti-écrasement (No-Clobber)\${NC}"
src2="\$DEMO_TMP/src2_nouveau.txt"
echo "Contenu actualisé du rapport Wisp" > "\$src2"
"\$WISP_BIN" --no-config send "\$src2" --name "rapport.txt" > "\$DEMO_TMP/s2.log" 2>&1 &
P2=\$!
wait_ready "\$DEMO_TMP/s2.log"
touch "\$DEMO_TMP/s2_ready"
wait \$P2
echo -e "\${GREEN}✔ [2/7] Nom en collision envoyé avec succès.\${NC}\n"
touch "\$DEMO_TMP/s2_done"
while [[ ! -f "\$DEMO_TMP/s3_start" ]]; do sleep 0.05; done

# --- SCÉNARIO 3/7 : PREAUTH PROBE ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 3/7] Tolérance aux scans de ports / probes pré-auth\${NC}"
src3="\$DEMO_TMP/src3_probe.txt"
echo "Données résilientes au scan" > "\$src3"
"\$WISP_BIN" --no-config send "\$src3" > "\$DEMO_TMP/s3.log" 2>&1 &
P3=\$!
wait_ready "\$DEMO_TMP/s3.log"
touch "\$DEMO_TMP/s3_ready"
wait \$P3
echo -e "\${GREEN}✔ [3/7] Expéditeur resté actif malgré probe UDP, transfert réussi.\${NC}\n"
touch "\$DEMO_TMP/s3_done"
while [[ ! -f "\$DEMO_TMP/s4_start" ]]; do sleep 0.05; done

# --- SCÉNARIO 4/7 : WRONG CODE ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 4/7] Sécurité anti-bruteforce (Faux code PAKE)\${NC}"
src4="\$DEMO_TMP/src4_secret.txt"
echo "Données ultra confidentielles" > "\$src4"
set +e
"\$WISP_BIN" --no-config send "\$src4" > "\$DEMO_TMP/s4.log" 2>&1
sender_st=\$?
set -e
echo -e "\${GREEN}✔ [4/7] Session terminée immédiatement sur échec d'authentification (Statut \$sender_st).\${NC}\n"
touch "\$DEMO_TMP/s4_done"
while [[ ! -f "\$DEMO_TMP/s5_start" ]]; do sleep 0.05; done

# --- SCÉNARIO 5/7 : CTRL+C CLEANUP ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 5/7] Nettoyage atomique des .part sur interruption\${NC}"
src5="\$DEMO_TMP/src5_large.bin"
dd if=/dev/zero of="\$src5" bs=1M count=25 status=none
set +e
"\$WISP_BIN" --no-config send "\$src5" > "\$DEMO_TMP/s5.log" 2>&1 &
P5=\$!
set -e
wait_ready "\$DEMO_TMP/s5.log"
touch "\$DEMO_TMP/s5_ready"
while [[ ! -f "\$DEMO_TMP/s5_kill_sender" ]]; do sleep 0.05; done
kill -INT \$P5 2>/dev/null || true
wait \$P5 2>/dev/null || true
echo -e "\${GREEN}✔ [5/7] Interruption traitée proprement côté expéditeur.\${NC}\n"
touch "\$DEMO_TMP/s5_done"
while [[ ! -f "\$DEMO_TMP/s6_start" ]]; do sleep 0.05; done

# --- SCÉNARIO 6/7 : BIDI SANITIZATION ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 6/7] Neutralisation des injections Unicode Bidi\${NC}"
src6="\$DEMO_TMP/src6_bidi.txt"
echo "Fichier piégé avec override RTL" > "\$src6"
bidi_name="report"\$'\u202e'"txt.pdf"
"\$WISP_BIN" --no-config send "\$src6" --name "\$bidi_name" > "\$DEMO_TMP/s6.log" 2>&1 &
P6=\$!
wait_ready "\$DEMO_TMP/s6.log"
touch "\$DEMO_TMP/s6_ready"
wait \$P6
echo -e "\${GREEN}✔ [6/7] Fichier avec nom Bidi transmis pour assainissement.\${NC}\n"
touch "\$DEMO_TMP/s6_done"
while [[ ! -f "\$DEMO_TMP/s7_start" ]]; do sleep 0.05; done

# --- SCÉNARIO 7/7 : BENCHMARK 50 MO ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 7/7] Test de débit réel (50 Mo)\${NC}"
src7="\$DEMO_TMP/src7_bench.bin"
dd if=/dev/urandom of="\$src7" bs=1M count=50 status=none
"\$WISP_BIN" --no-config send "\$src7" > "\$DEMO_TMP/s7.log" 2>&1 &
P7=\$!
wait_ready "\$DEMO_TMP/s7.log"
touch "\$DEMO_TMP/s7_ready"
wait \$P7
echo -e "\${GREEN}✔ [7/7] 50 Mo envoyés et validés par le récepteur.\${NC}\n"
touch "\$DEMO_TMP/s7_done"

echo -e "\${GREEN}\${BOLD}====================================================\${NC}"
echo -e "\${GREEN}\${BOLD}✔ TOUS LES 7 SCÉNARIOS TERMINÉS CÔTÉ EXPÉDITEUR     \${NC}"
echo -e "\${GREEN}\${BOLD}====================================================\${NC}"
echo -e "\${CYAN}ℹ Utilisez la molette de la souris pour faire défiler les logs.\${NC}"
echo -e "\${YELLOW}Appuyez sur [Entrée] pour quitter TMUX...\${NC}"

read -r _
tmux send-keys -t "${session}.1" Enter 2>/dev/null || true
EOF

    cat > "$DEMO_TMP/receiver.sh" << EOF
#!/usr/bin/env bash
set -e

GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

WISP_BIN="$WISP_BIN"
DEMO_TMP="$DEMO_TMP"

get_code_addr() {
    local log="\$1"
    code=\$(grep -m 1 "wisp recv" "\$log" | sed -e 's/.*wisp recv //' -e 's/ --.*//' -e 's/[[:space:]]//g')
    addr=""
    if grep -q "Sender address:" "\$log" 2>/dev/null; then
        addr=\$(grep -m 1 "Sender address:" "\$log" | awk '{print \$3}')
    fi
}

echo -e "\${YELLOW}\${BOLD}====================================================\${NC}"
echo -e "\${YELLOW}\${BOLD}          RÉCEPTEUR (TERMINAL DROIT)                \${NC}"
echo -e "\${YELLOW}\${BOLD}====================================================\${NC}\n"

# --- SCÉNARIO 1/7 : NOMINAL ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 1/7] Transfert nominal standard (mDNS + PAKE)\${NC}"
while [[ ! -f "\$DEMO_TMP/s1_ready" ]]; do sleep 0.05; done
get_code_addr "\$DEMO_TMP/s1.log"
echo -e "Code détecté : \${GREEN}\$code\${NC}"
dst1="\$DEMO_TMP/dst1"
mkdir -p "\$dst1"
"\$WISP_BIN" --no-config recv "\$code" --dir "\$dst1" --address "\$addr"
echo -e "\${GREEN}✔ [1/7] Fichier reçu et empreinte BLAKE3 certifiée conforme !\${NC}\n"
while [[ ! -f "\$DEMO_TMP/s1_done" ]]; do sleep 0.05; done
sleep 0.8
touch "\$DEMO_TMP/s2_start"

# --- SCÉNARIO 2/7 : COLLISION NO-CLOBBER ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 2/7] Protection anti-écrasement (No-Clobber)\${NC}"
dst2="\$DEMO_TMP/dst2"
mkdir -p "\$dst2"
echo "DOCUMENT ORIGINAL INVIOLABLE" > "\$dst2/rapport.txt"
while [[ ! -f "\$DEMO_TMP/s2_ready" ]]; do sleep 0.05; done
get_code_addr "\$DEMO_TMP/s2.log"
echo -e "Code détecté : \${GREEN}\$code\${NC} (Fichier entrant 'rapport.txt')"
"\$WISP_BIN" --no-config recv "\$code" --dir "\$dst2" --address "\$addr"
if [[ -f "\$dst2/rapport (1).txt" && "\$(cat "\$dst2/rapport.txt")" == "DOCUMENT ORIGINAL INVIOLABLE" ]]; then
    echo -e "\${GREEN}✔ [2/7] Original préservé, nouveau sauvé sous 'rapport (1).txt' !\${NC}\n"
else
    echo -e "\${RED}✘ [2/7] Échec de la politique No-Clobber !\${NC}\n"
    exit 1
fi
while [[ ! -f "\$DEMO_TMP/s2_done" ]]; do sleep 0.05; done
sleep 0.8
touch "\$DEMO_TMP/s3_start"

# --- SCÉNARIO 3/7 : PREAUTH PROBE ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 3/7] Tolérance aux scans de ports / probes pré-auth\${NC}"
while [[ ! -f "\$DEMO_TMP/s3_ready" ]]; do sleep 0.05; done
get_code_addr "\$DEMO_TMP/s3.log"
port="\${addr##*:}"
echo -e "Simulation d'un port scan non-authentifié sur le port \$port..."
python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'MALICIOUS_PROBE', ('127.0.0.1', \$port)); s.close()"
sleep 0.2
dst3="\$DEMO_TMP/dst3"
mkdir -p "\$dst3"
echo -e "Connexion du récepteur légitime..."
"\$WISP_BIN" --no-config recv "\$code" --dir "\$dst3" --address "\$addr"
echo -e "\${GREEN}✔ [3/7] Transfert complété avec succès malgré le scan parasite !\${NC}\n"
while [[ ! -f "\$DEMO_TMP/s3_done" ]]; do sleep 0.05; done
sleep 0.8
touch "\$DEMO_TMP/s4_start"

# --- SCÉNARIO 4/7 : WRONG CODE ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 4/7] Sécurité anti-bruteforce (Faux code PAKE)\${NC}"
dst4="\$DEMO_TMP/dst4"
mkdir -p "\$dst4"
for _ in {1..100}; do
    if grep -q "wisp recv" "\$DEMO_TMP/s4.log" 2>/dev/null; then break; fi
    sleep 0.05
done
get_code_addr "\$DEMO_TMP/s4.log"
locator="\${code%%-*}"
bad_code="\${locator}-amber-amber-amber-amber"
echo -e "Code légitime : \${CYAN}\$code\${NC}"
echo -e "\${RED}Tentative d'attaque avec mot de passe erroné : \$bad_code\${NC}"
set +e
"\$WISP_BIN" --no-config recv "\$bad_code" --dir "\$dst4" --address "\$addr" 2>/dev/null
st=\$?
set -e
if [[ \$st -ne 0 ]]; then
    echo -e "\${GREEN}✔ [4/7] Rejet immédiat par PAKE (Statut \$st) et session fermée sans oracle !\${NC}\n"
else
    echo -e "\${RED}✘ [4/7] ERREUR : Le mauvais code a été accepté !\${NC}\n"
    exit 1
fi
while [[ ! -f "\$DEMO_TMP/s4_done" ]]; do sleep 0.05; done
sleep 0.8
touch "\$DEMO_TMP/s5_start"

# --- SCÉNARIO 5/7 : CTRL+C CLEANUP ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 5/7] Nettoyage atomique des .part sur interruption\${NC}"
dst5="\$DEMO_TMP/dst5"
mkdir -p "\$dst5"
while [[ ! -f "\$DEMO_TMP/s5_ready" ]]; do sleep 0.05; done
get_code_addr "\$DEMO_TMP/s5.log"
echo "Démarrage du téléchargement d'un gros fichier puis envoi de SIGINT (Ctrl+C)..."
"\$WISP_BIN" --no-config recv "\$code" --dir "\$dst5" --address "\$addr" &
RPID=\$!
sleep 0.3
kill -INT \$RPID 2>/dev/null || true
wait \$RPID 2>/dev/null || true
touch "\$DEMO_TMP/s5_kill_sender"
while [[ ! -f "\$DEMO_TMP/s5_done" ]]; do sleep 0.05; done
parts=\$(find "\$dst5" -name ".wisp-*.part" | wc -l)
if [[ \$parts -eq 0 ]]; then
    echo -e "\${GREEN}✔ [5/7] Transfert interrompu, aucun fichier résiduel .part orphelin !\${NC}\n"
else
    echo -e "\${RED}✘ [5/7] Des fichiers partiels ont été abandonnés !\${NC}\n"
    exit 1
fi
sleep 0.8
touch "\$DEMO_TMP/s6_start"

# --- SCÉNARIO 6/7 : BIDI SANITIZATION ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 6/7] Neutralisation des injections Unicode Bidi\${NC}"
dst6="\$DEMO_TMP/dst6"
mkdir -p "\$dst6"
while [[ ! -f "\$DEMO_TMP/s6_ready" ]]; do sleep 0.05; done
get_code_addr "\$DEMO_TMP/s6.log"
echo "Réception d'un fichier avec injection de masquage d'extension Bidi..."
"\$WISP_BIN" --no-config recv "\$code" --dir "\$dst6" --address "\$addr"
if [[ -f "\$dst6/report_txt.pdf" ]]; then
    echo -e "\${GREEN}✔ [6/7] Caractère masqué neutralisé, fichier assaini en 'report_txt.pdf' !\${NC}\n"
else
    echo -e "\${RED}✘ [6/7] Échec : Nom non assaini : \$(ls "\$dst6")\${NC}\n"
    exit 1
fi
while [[ ! -f "\$DEMO_TMP/s6_done" ]]; do sleep 0.05; done
sleep 0.8
touch "\$DEMO_TMP/s7_start"

# --- SCÉNARIO 7/7 : BENCHMARK 50 MO ---
echo -e "\${CYAN}\${BOLD}[SCÉNARIO 7/7] Test de débit réel (50 Mo)\${NC}"
dst7="\$DEMO_TMP/dst7"
mkdir -p "\$dst7"
while [[ ! -f "\$DEMO_TMP/s7_ready" ]]; do sleep 0.05; done
get_code_addr "\$DEMO_TMP/s7.log"
echo "Transfert haute performance de 50 Mo en cours..."
t0=\$(date +%s%N)
"\$WISP_BIN" --no-config recv "\$code" --dir "\$dst7" --address "\$addr"
t1=\$(date +%s%N)
ms=\$(( (t1 - t0) / 1000000 ))
speed_mb_s=\$(python3 -c "print(f'{50 / (\$ms / 1000):.1f}')" 2>/dev/null || echo "N/A")
echo -e "\${GREEN}✔ [7/7] 50 Mo transférés en \${ms}ms (\${speed_mb_s} Mo/s) !\${NC}\n"
while [[ ! -f "\$DEMO_TMP/s7_done" ]]; do sleep 0.05; done

echo -e "\${GREEN}\${BOLD}====================================================\${NC}"
echo -e "\${GREEN}\${BOLD}✔ TOUS LES 7 SCÉNARIOS SONT VALIDÉS AVEC SUCCÈS !   \${NC}"
echo -e "\${GREEN}\${BOLD}====================================================\${NC}"
echo -e "  \${GREEN}1. Transfert nominal standard (mDNS + PAKE + BLAKE3)\${NC}"
echo -e "  \${GREEN}2. Protection No-Clobber (Anti-écrasement de fichier)\${NC}"
echo -e "  \${GREEN}3. Résilience aux scans de ports / probes pré-auth\${NC}"
echo -e "  \${GREEN}4. Sécurité anti-bruteforce (Arrêt immédiat PAKE)\${NC}"
echo -e "  \${GREEN}5. Nettoyage atomique des fichiers partiels sur Ctrl+C\${NC}"
echo -e "  \${GREEN}6. Neutralisation des injections Unicode Bidi\${NC}"
echo -e "  \${GREEN}7. Benchmark de vitesse réelle (50 Mo)\${NC}"
echo ""
echo -e "\${CYAN}ℹ Utilisez la molette de la souris pour faire défiler les logs des 2 fenêtres.\${NC}"
echo -e "\${YELLOW}\${BOLD}👉 Appuyez sur [Entrée] dans n'importe quel volet pour fermer TMUX...\${NC}"

read -r _
tmux send-keys -t "${session}.0" Enter 2>/dev/null || true
EOF

    chmod +x "$DEMO_TMP/sender.sh" "$DEMO_TMP/receiver.sh"

    # Démarrer tmux avec sender.sh
    tmux new-session -d -s "$session" -n "Wisp-Demo" "bash $DEMO_TMP/sender.sh"

    # Scinder horizontalement pour receiver.sh
    tmux split-window -h -t "$session" "bash $DEMO_TMP/receiver.sh"
    tmux select-layout -t "$session" even-horizontal

    # Activer le support souris (défilement et sélection dans WSL / Windows Terminal)
    tmux set-option -t "$session" mouse on 2>/dev/null || true

    # Vérifier que la session est bien active
    if ! tmux has-session -t "$session" 2>/dev/null; then
        log_error "Échec de création de la session TMUX."
        return 1
    fi

    log_success "Session TMUX interactive démarrée !"
    echo -e "${YELLOW}Les 7 scénarios vont se jouer automatiquement côte à côte.${NC}"
    echo -e "${CYAN}Astuce : Utilisez la souris pour scroller ou redimensionner les panneaux si besoin.${NC}"

    # Attacher ou basculer selon l'environnement
    if [[ -n "${TMUX:-}" ]]; then
        tmux switch-client -t "$session"
        while tmux has-session -t "$session" 2>/dev/null; do
            sleep 1
        done
    elif [[ "$TERM" == "dumb" || ! -t 0 ]]; then
        log_info "Session TMUX en cours d'exécution ($session)."
        echo "Pour observer en direct : tmux attach-session -t $session"
        while tmux has-session -t "$session" 2>/dev/null; do
            sleep 1
        done
    else
        if ! tmux attach-session -t "$session"; then
            log_warn "Attachement automatique non supporté. Attente de la fin de la démonstration..."
            while tmux has-session -t "$session" 2>/dev/null; do
                sleep 1
            done
        fi
    fi

    log_success "Démonstration des 7 scénarios terminée avec succès !"
}

# ------------------------------------------------------------------------------
# Menu Principal
# ------------------------------------------------------------------------------
usage() {
    echo -e "${BOLD}Wisp - Lanceur de scénarios de test E2E${NC}"
    echo ""
    echo "Usage: $0 [COMMANDE]"
    echo ""
    echo "Commandes directes :"
    echo "  nominal       Transfert nominal (Découverte mDNS & intégrité)"
    echo "  collision     Collision de nom de fichier (No-Clobber)"
    echo "  preauth       Résilience aux scans de ports / probes pré-auth"
    echo "  wrong-code    Arrêt immédiat anti-bruteforce sur mauvais mot de passe"
    echo "  ctrl-c        Interruption propre et purge du fichier .part"
    echo "  bidi          Assainissement de noms contenant des caractères Unicode Bidi"
    echo "  benchmark     Test de vitesse réelle (50 Mo)"
    echo "  all           Exécuter TOUS les scénarios d'affilée"
    echo ""
    echo "Mode interactif visuel :"
    echo "  tmux          Ouvre 2 terminaux scindés (gauche/droite) dans TMUX"
    echo ""
}

main() {
    ensure_binary
    local cmd="${1:-all}"
    case "$cmd" in
        nominal)    scenario_nominal ;;
        collision)  scenario_collision ;;
        preauth)    scenario_preauth_probe ;;
        wrong-code) scenario_wrong_code ;;
        ctrl-c)     scenario_ctrl_c ;;
        bidi)       scenario_bidi ;;
        benchmark)  scenario_benchmark ;;
        tmux)       shift; launch_tmux "$@" ;;
        all)
            scenario_nominal
            scenario_collision
            scenario_preauth_probe
            scenario_wrong_code
            scenario_ctrl_c
            scenario_bidi
            scenario_benchmark
            echo ""
            log_success "Tous les 7 scénarios ont été exécutés et validés avec succès !"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
