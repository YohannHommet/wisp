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
    local scenario="${1:-nominal}"
    log_step "Lancement de la simulation interactif dans TMUX (Écran scindé)"
    
    local session="wisp_demo_$$"
    DEMO_TMP=$(mktemp -d /tmp/wisp_tmux.XXXXXX)
    local src="$DEMO_TMP/test_file.txt"
    local dst="$DEMO_TMP/destination"
    mkdir -p "$dst"
    echo "Démonstration Wisp interactive en direct - $(date)" > "$src"

    # Script d'orchestration pour le panneau récepteur
    local sync_pipe="$DEMO_TMP/sync.pipe"
    mkfifo "$sync_pipe"

    # Démarrer tmux en arrière-plan
    tmux new-session -d -s "$session" -n "Wisp-Demo" \
        "echo -e '${GREEN}${BOLD}=== EXPÉDITEUR (TERMINAL 1) ===${NC}\n'; '$WISP_BIN' --no-config send '$src' | tee '$sync_pipe'; read -p 'Appuyez sur Entrée pour quitter...'"

    # Scinder l'écran horizontalement (panneau droit pour le récepteur)
    tmux split-window -h -t "$session" \
        "echo -e '${YELLOW}${BOLD}=== RÉCEPTEUR (TERMINAL 2) ===${NC}\n'; \
         echo 'Attente du code d expéditeur...'; \
         code=\$(grep -m 1 'wisp recv' '$sync_pipe' | sed 's/.*wisp recv //;s/ --.*//;s/ //g'); \
         echo -e 'Code détecté : ${GREEN}'\$code'${NC}\n'; \
         '$WISP_BIN' --no-config recv \"\$code\" --dir '$dst'; \
         echo -e '\nFichier vérifié dans $dst :'; ls -lh '$dst'; \
         read -p 'Appuyez sur Entrée pour quitter...'"

    log_success "Session TMUX créée ! Attachement à la session..."
    echo -e "${YELLOW}Astuce : Vous verrez l'expéditeur à gauche et le récepteur à droite.${NC}"
    sleep 1
    tmux attach-session -t "$session"
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
        tmux)       launch_tmux ;;
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
