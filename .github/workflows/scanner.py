import os
import sys
import socket
import ipaddress
import time

from pathlib import Path
from concurrent.futures import (
    ThreadPoolExecutor,
    wait,
    FIRST_COMPLETED
)

from colorama import init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn
)
from rich.align import Align
from rich import box


# ============================================================
# WINDOWS / UTF-8
# ============================================================

if os.name == "nt":

    try:
        os.system("chcp 65001 > nul")
    except Exception:
        pass

    try:
        sys.stdout.reconfigure(
            encoding="utf-8"
        )

        sys.stderr.reconfigure(
            encoding="utf-8"
        )

    except Exception:
        pass


# ============================================================
# INITIALISATION
# ============================================================

init(
    autoreset=True
)

console = Console(
    force_terminal=True
)

# Nombre maximum de futures en attente.
#
# Exemple :
# 15000 threads -> environ 15000 tâches maximum
# simultanément dans la file.
#
# Cela évite de créer des millions de futures.
PENDING_FACTOR = 2


# ============================================================
# OUTILS
# ============================================================

def clear_screen():

    os.system("cls")


def format_number(value):

    return f"{value:,}".replace(",", " ")


def format_time(seconds):

    seconds = max(
        0,
        int(seconds)
    )

    hours, remainder = divmod(
        seconds,
        3600
    )

    minutes, seconds = divmod(
        remainder,
        60
    )

    if hours > 0:

        return (
            f"{hours:02d}:"
            f"{minutes:02d}:"
            f"{seconds:02d}"
        )

    return (
        f"{minutes:02d}:"
        f"{seconds:02d}"
    )


# ============================================================
# BANNIERE
# ============================================================

def banner():

    art = r"""
██╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║
██║██║         ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

    console.print(
        Panel(
            Align.center(
                f"[bold cyan]{art}[/bold cyan]\n"
                "[bold white]"
                "T C P   N E T W O R K   S C A N N E R"
                "[/bold white]\n"
                "[bold green]"
                "L A B O R A T O R Y   E D I T I O N"
                "[/bold green]\n"
                "[dim]"
                "Windows CLI | Authorized Testing"
                "[/dim]"
            ),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2)
        )
    )

    console.print()


# ============================================================
# SAISIE
# ============================================================

def ask(
    question,
    default=None
):

    if default is not None:

        value = console.input(
            f"\n"
            f"[bold cyan]>> {question}[/bold cyan] "
            f"[dim][{default}][/dim] : "
        ).strip()

        if not value:
            value = default

    else:

        value = console.input(
            f"\n"
            f"[bold cyan]>> {question}[/bold cyan] : "
        ).strip()

    console.print(
        f"   [bold yellow]INPUT : {value}[/bold yellow]"
    )

    return value


# ============================================================
# PARSING DES PORTS
# ============================================================

def parse_ports(value):

    ports = set()

    for part in value.split(","):

        part = part.strip()

        if not part:
            continue

        # ----------------------------------------------------
        # PLAGE
        # ----------------------------------------------------

        if "-" in part:

            pieces = part.split("-")

            if len(pieces) != 2:

                raise ValueError(
                    f"Plage invalide : {part}"
                )

            try:

                start = int(
                    pieces[0].strip()
                )

                end = int(
                    pieces[1].strip()
                )

            except ValueError:

                raise ValueError(
                    f"Plage invalide : {part}"
                )

            if not 1 <= start <= 65535:

                raise ValueError(
                    f"Port invalide : {start}"
                )

            if not 1 <= end <= 65535:

                raise ValueError(
                    f"Port invalide : {end}"
                )

            if start > end:

                raise ValueError(
                    f"Plage incorrecte : {part}"
                )

            ports.update(
                range(
                    start,
                    end + 1
                )
            )

        # ----------------------------------------------------
        # PORT UNIQUE
        # ----------------------------------------------------

        else:

            try:

                port = int(part)

            except ValueError:

                raise ValueError(
                    f"Port invalide : {part}"
                )

            if not 1 <= port <= 65535:

                raise ValueError(
                    f"Le port doit etre compris "
                    f"entre 1 et 65535 : {port}"
                )

            ports.add(port)

    if not ports:

        raise ValueError(
            "Aucun port valide."
        )

    return sorted(ports)


# ============================================================
# COMPTER LES IP
#
# Première passe du fichier.
#
# IMPORTANT :
# On ne stocke aucune IP.
#
# Le programme compte simplement combien
# d'adresses seront analysées.
# ============================================================

def count_targets(filename):

    total = 0

    with open(
        filename,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            try:

                # ------------------------------------------------
                # CIDR
                # ------------------------------------------------

                if "/" in line:

                    network = ipaddress.ip_network(
                        line,
                        strict=False
                    )

                    if network.version != 4:
                        continue

                    # hosts() évite les adresses réseau/broadcast
                    total += network.num_addresses

                    if network.prefixlen <= 30:
                        total -= 2

                # ------------------------------------------------
                # IP SIMPLE
                # ------------------------------------------------

                else:

                    ip = ipaddress.ip_address(
                        line
                    )

                    if ip.version == 4:

                        total += 1

            except ValueError:

                # Ligne invalide :
                # on l'ignore.
                continue

    return total


# ============================================================
# GENERATEUR D'IP
#
# Deuxième passe du fichier.
#
# Les IP sont produites UNE PAR UNE.
#
# Elles ne sont jamais toutes stockées en mémoire.
# ============================================================

def iter_targets(filename):

    with open(
        filename,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            try:

                # ------------------------------------------------
                # CIDR
                # ------------------------------------------------

                if "/" in line:

                    network = ipaddress.ip_network(
                        line,
                        strict=False
                    )

                    if network.version != 4:
                        continue

                    for ip in network.hosts():

                        yield str(ip)

                # ------------------------------------------------
                # IP SIMPLE
                # ------------------------------------------------

                else:

                    ip = ipaddress.ip_address(
                        line
                    )

                    if ip.version != 4:
                        continue

                    yield str(ip)

            except ValueError:

                continue


# ============================================================
# TEST TCP
# ============================================================

def test_port(
    ip,
    port,
    timeout
):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:

        result = sock.connect_ex(
            (
                ip,
                port
            )
        )

        return result == 0

    except Exception:

        return False

    finally:

        sock.close()


# ============================================================
# SCAN D'UNE IP
#
# Une tâche = une IP.
#
# Le worker teste tous les ports sélectionnés.
# ============================================================

def scan_ip(
    ip,
    ports,
    timeout
):

    opened = []

    tests = 0

    for port in ports:

        tests += 1

        if test_port(
            ip,
            port,
            timeout
        ):

            opened.append(
                port
            )

    return (
        ip,
        opened,
        tests
    )


# ============================================================
# SAUVEGARDE
# ============================================================

def save_results(
    output_file,
    ip,
    opened_ports
):

    if not opened_ports:
        return 0

    with open(
        output_file,
        "a",
        encoding="utf-8"
    ) as file:

        for port in opened_ports:

            file.write(
                f"{ip}:{port}\n"
            )

        # Force l'écriture immédiatement.
        file.flush()

    return len(
        opened_ports
    )


# ============================================================
# CONFIGURATION
# ============================================================

def configuration():

    clear_screen()

    banner()

    console.print(
        Panel(
            "[bold white]"
            "CONFIGURATION DU SCAN"
            "[/bold white]\n\n"
            "[dim]"
            "Configure ton scan de laboratoire."
            "[/dim]",
            border_style="blue"
        )
    )

    # ========================================================
    # FICHIER IP
    # ========================================================

    while True:

        target_file = ask(
            "Fichier TXT contenant les IP/reseaux"
        )

        if Path(target_file).is_file():

            console.print(
                "[bold green]"
                "   [OK] Fichier trouve"
                "[/bold green]"
            )

            break

        console.print(
            "[bold red]"
            "   [ERREUR] Fichier introuvable"
            "[/bold red]"
        )

    # ========================================================
    # PORTS
    # ========================================================

    while True:

        ports_input = ask(
            "Port(s) a scanner"
        )

        try:

            ports = parse_ports(
                ports_input
            )

            console.print(
                "[bold green]"
                f"   [OK] {format_number(len(ports))} "
                "port(s) selectionne(s)"
                "[/bold green]"
            )

            break

        except ValueError as error:

            console.print(
                f"[bold red]"
                f"   [ERREUR] {error}"
                f"[/bold red]"
            )

    # ========================================================
    # THREADS
    # ========================================================

    while True:

        value = ask(
            "Nombre de threads",
            "15000"
        )

        try:

            threads = int(value)

            if threads < 1:
                raise ValueError

            if threads > 15000:

                console.print(
                    "[yellow]"
                    "   [WARN] Maximum : 15000 threads"
                    "[/yellow]"
                )

                threads = 15000

            console.print(
                "[bold green]"
                f"   [OK] {threads} "
                "threads selectionnes"
                "[/bold green]"
            )

            break

        except ValueError:

            console.print(
                "[bold red]"
                "   [ERREUR] Nombre de threads invalide"
                "[/bold red]"
            )

    # ========================================================
    # TIMEOUT
    # ========================================================

    while True:

        value = ask(
            "Timeout en secondes",
            "1.0"
        )

        try:

            timeout = float(value)

            if timeout <= 0:
                raise ValueError

            console.print(
                "[bold green]"
                f"   [OK] Timeout : {timeout:g} seconde(s)"
                "[/bold green]"
            )

            break

        except ValueError:

            console.print(
                "[bold red]"
                "   [ERREUR] Timeout invalide"
                "[/bold red]"
            )

    # ========================================================
    # SORTIE
    # ========================================================

    output_file = ask(
        "Fichier TXT des resultats",
        "scan.txt"
    )

    console.print(
        "[bold green]"
        f"   [OK] Resultats : {output_file}"
        "[/bold green]"
    )

    return (
        target_file,
        ports,
        threads,
        timeout,
        output_file
    )


# ============================================================
# RECAPITULATIF
# ============================================================

def show_summary(
    target_file,
    ports,
    threads,
    timeout,
    output_file,
    total_ips
):

    clear_screen()

    banner()

    table = Table(
        title="RECAPITULATIF DU SCAN",
        border_style="cyan",
        box=box.ROUNDED
    )

    table.add_column(
        "PARAMETRE",
        style="bold cyan"
    )

    table.add_column(
        "VALEUR",
        style="bold white"
    )

    table.add_row(
        "Fichier cibles",
        target_file
    )

    table.add_row(
        "IP a scanner",
        format_number(total_ips)
    )

    table.add_row(
        "Ports",
        format_number(len(ports))
    )

    if len(ports) <= 20:

        port_display = ", ".join(
            str(p)
            for p in ports
        )

    else:

        port_display = (
            f"{ports[0]} -> {ports[-1]} "
            f"({format_number(len(ports))} ports)"
        )

    table.add_row(
        "Selection",
        port_display
    )

    table.add_row(
        "Threads",
        str(threads)
    )

    table.add_row(
        "Timeout",
        f"{timeout:g}s"
    )

    table.add_row(
        "Sortie",
        output_file
    )

    console.print(table)

    total_tests = (
        total_ips *
        len(ports)
    )

    console.print()

    console.print(
        Panel(
            f"[bold yellow]"
            f"IP a scanner : {format_number(total_ips)}"
            f"[/bold yellow]\n"
            f"[bold yellow]"
            f"Tests IP:PORT : {format_number(total_tests)}"
            f"[/bold yellow]",
            border_style="yellow"
        )
    )

    console.print()

    answer = ask(
        "Demarrer le scan ? [O/n]",
        "O"
    )

    return answer.lower() in {
        "o",
        "oui",
        "y",
        "yes"
    }


# ============================================================
# SCAN PRINCIPAL
#
# IMPORTANT :
#
# On ne crée PAS une future pour chaque IP.
#
# On maintient seulement :
#
# threads * PENDING_FACTOR
#
# tâches en attente.
#
# Cela permet de traiter de très gros fichiers.
# ============================================================

def start_scan(
    target_file,
    total_ips,
    ports,
    threads,
    timeout,
    output_file
):

    total_tests = (
        total_ips *
        len(ports)
    )

    # --------------------------------------------------------
    # Réinitialiser le fichier de sortie
    # --------------------------------------------------------

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ):
        pass

    # --------------------------------------------------------
    # Statistiques
    # --------------------------------------------------------

    completed_ips = 0
    completed_tests = 0
    opened = 0

    start_time = time.perf_counter()

    # --------------------------------------------------------
    # Générateur d'IP
    # --------------------------------------------------------

    targets = iter_targets(
        target_file
    )

    # --------------------------------------------------------
    # Nombre maximum de futures
    # --------------------------------------------------------

    max_pending = max(
        threads,
        threads * PENDING_FACTOR
    )

    # ========================================================
    # BARRE DE PROGRESSION
    # ========================================================

    progress = Progress(
        SpinnerColumn(),
        TextColumn(
            "[bold cyan]{task.description}"
        ),
        BarColumn(),
        TextColumn(
            "[bold white]"
            "{task.percentage:>3.0f}%"
        ),
        TextColumn(
            "[bold cyan]"
            "IP : {task.completed}/{task.total}"
        ),
        TextColumn(
            "[bold green]"
            "OPEN : {task.fields[opened]}"
        ),
        TextColumn(
            "[bold yellow]"
            "IP/s : {task.fields[ips_sec]:.1f}"
        ),
        TextColumn(
            "[bold magenta]"
            "Tests/s : {task.fields[tests_sec]:.0f}"
        ),
        TimeElapsedColumn(),
        TextColumn(
            "[dim]"
            "ETA : {task.fields[eta]}"
        ),
        console=console
    )

    task = progress.add_task(
        "SCAN TCP",
        total=total_ips,
        opened=0,
        ips_sec=0.0,
        tests_sec=0.0,
        eta="--"
    )

    # ========================================================
    # EXECUTOR
    # ========================================================

    with progress:

        with ThreadPoolExecutor(
            max_workers=threads
        ) as executor:

            pending = set()

            # =================================================
            # FONCTION POUR REMPLIR LE POOL
            # =================================================

            def fill_pool():

                while len(pending) < max_pending:

                    try:

                        ip = next(targets)

                    except StopIteration:

                        break

                    future = executor.submit(
                        scan_ip,
                        ip,
                        ports,
                        timeout
                    )

                    pending.add(
                        future
                    )

            # Premier remplissage.
            fill_pool()

            # =================================================
            # BOUCLE PRINCIPALE
            # =================================================

            while pending:

                done, pending = wait(
                    pending,
                    return_when=FIRST_COMPLETED
                )

                # ---------------------------------------------
                # Traiter les tâches terminées
                # ---------------------------------------------

                for future in done:

                    try:

                        (
                            ip,
                            opened_ports,
                            tests
                        ) = future.result()

                    except Exception:

                        opened_ports = []
                        tests = len(ports)

                    # -----------------------------------------
                    # Sauvegarde instantanée
                    # -----------------------------------------

                    opened += save_results(
                        output_file,
                        ip,
                        opened_ports
                    )

                    # -----------------------------------------
                    # Compteurs
                    # -----------------------------------------

                    completed_ips += 1

                    completed_tests += tests

                    elapsed = (
                        time.perf_counter()
                        - start_time
                    )

                    # -----------------------------------------
                    # IP/s
                    #
                    # IP COMPLETEMENT TERMINEES / temps
                    # -----------------------------------------

                    ips_per_second = (
                        completed_ips / elapsed
                        if elapsed > 0
                        else 0
                    )

                    # -----------------------------------------
                    # Tests/s
                    #
                    # Nombre réel de tests TCP terminés
                    # par seconde.
                    # -----------------------------------------

                    tests_per_second = (
                        completed_tests / elapsed
                        if elapsed > 0
                        else 0
                    )

                    # -----------------------------------------
                    # ETA
                    # -----------------------------------------

                    remaining = (
                        total_ips -
                        completed_ips
                    )

                    if ips_per_second > 0:

                        eta_seconds = (
                            remaining /
                            ips_per_second
                        )

                        eta = format_time(
                            eta_seconds
                        )

                    else:

                        eta = "--"

                    # -----------------------------------------
                    # Barre
                    # -----------------------------------------

                    progress.update(
                        task,
                        advance=1,
                        opened=opened,
                        ips_sec=ips_per_second,
                        tests_sec=tests_per_second,
                        eta=eta
                    )

                # ---------------------------------------------
                # Remplir à nouveau le pool
                # ---------------------------------------------

                fill_pool()

    # ========================================================
    # STATISTIQUES FINALES
    # ========================================================

    elapsed = (
        time.perf_counter()
        - start_time
    )

    final_ips_sec = (
        completed_ips / elapsed
        if elapsed > 0
        else 0
    )

    final_tests_sec = (
        completed_tests / elapsed
        if elapsed > 0
        else 0
    )

    # ========================================================
    # RESULTATS
    # ========================================================

    console.print()

    table = Table(
        title="SCAN TERMINE",
        border_style="green",
        box=box.DOUBLE
    )

    table.add_column(
        "STATISTIQUE",
        style="bold cyan"
    )

    table.add_column(
        "VALEUR",
        justify="right",
        style="bold white"
    )

    table.add_row(
        "IP scannees",
        format_number(completed_ips)
    )

    table.add_row(
        "Ports selectionnes",
        format_number(len(ports))
    )

    table.add_row(
        "Tests IP:PORT",
        format_number(completed_tests)
    )

    table.add_row(
        "Ports ouverts",
        f"[bold green]"
        f"{format_number(opened)}"
        f"[/bold green]"
    )

    table.add_row(
        "Temps ecoule",
        format_time(elapsed)
    )

    table.add_row(
        "IP/s",
        f"[bold yellow]"
        f"{final_ips_sec:.2f}"
        f"[/bold yellow]"
    )

    table.add_row(
        "Tests/s",
        f"[bold magenta]"
        f"{final_tests_sec:.2f}"
        f"[/bold magenta]"
    )

    console.print(table)

    console.print()

    console.print(
        Panel(
            "[bold green]"
            "SCAN TERMINE AVEC SUCCES"
            "[/bold green]\n\n"
            f"Resultats : "
            f"[bold cyan]{output_file}[/bold cyan]\n\n"
            "[dim]"
            "Format : IP:PORT"
            "[/dim]",
            border_style="green",
            padding=(1, 3)
        )
    )


# ============================================================
# MAIN
# ============================================================

def main():

    try:

        # ----------------------------------------------------
        # Configuration
        # ----------------------------------------------------

        (
            target_file,
            ports,
            threads,
            timeout,
            output_file
        ) = configuration()

        console.print()

        # ----------------------------------------------------
        # Comptage des IP
        #
        # IMPORTANT :
        # aucune IP n'est chargée en mémoire ici.
        # ----------------------------------------------------

        console.print(
            "[bold cyan]"
            ">> Analyse du fichier cible..."
            "[/bold cyan]"
        )

        total_ips = count_targets(
            target_file
        )

        if total_ips == 0:

            console.print(
                "[bold red]"
                "[ERREUR] Aucune IPv4 valide trouvee."
                "[/bold red]"
            )

            input(
                "\nAppuyez sur Entree pour quitter..."
            )

            return

        console.print(
            "[bold green]"
            f"[OK] {format_number(total_ips)} "
            "IP detectees."
            "[/bold green]"
        )

        # ----------------------------------------------------
        # Confirmation
        # ----------------------------------------------------

        confirmed = show_summary(
            target_file,
            ports,
            threads,
            timeout,
            output_file,
            total_ips
        )

        if not confirmed:

            console.print(
                "\n[yellow]"
                "Scan annule."
                "[/yellow]"
            )

            input(
                "\nAppuyez sur Entree pour quitter..."
            )

            return

        # ----------------------------------------------------
        # Scan
        # ----------------------------------------------------

        clear_screen()

        banner()

        console.print(
            Panel(
                "[bold green]"
                "SCAN TCP EN COURS"
                "[/bold green]\n\n"
                "[dim]"
                "IP/s    = IP entierement traitees / seconde"
                "[/dim]\n"
                "[dim]"
                "Tests/s = tests IP:PORT / seconde"
                "[/dim]\n"
                "[dim]"
                "OPEN    = ports TCP ouverts detectes"
                "[/dim]\n"
                "[dim]"
                "Les resultats sont sauvegardes immediatement."
                "[/dim]",
                border_style="green"
            )
        )

        console.print()

        start_scan(
            target_file,
            total_ips,
            ports,
            threads,
            timeout,
            output_file
        )

        console.print()

        input(
            "Appuyez sur Entree pour quitter..."
        )

    except KeyboardInterrupt:

        console.print(
            "\n\n[bold red]"
            "SCAN INTERROMPU."
            "[/bold red]"
        )

        input(
            "\nAppuyez sur Entree pour quitter..."
        )

    except Exception as error:

        console.print(
            "\n[bold red]"
            f"[ERREUR] {error}"
            "[/bold red]"
        )

        input(
            "\nAppuyez sur Entree pour quitter..."
        )


# ============================================================
# LANCEMENT
# ============================================================

if __name__ == "__main__":

    main()