#!/usr/bin/env python3
import os
import subprocess
import shutil
from datetime import datetime
from colorama import Fore, Style, init as colorama_init
from pyfiglet import figlet_format
from termcolor import colored

# ===== init color =====
colorama_init(autoreset=True)

# ===== base paths =====
HOME = os.path.expanduser("~")

BBP_BASE = os.path.join(HOME, "bug-hunting", "bbp")  # temp / recon workspace
FULLPOWER_BASE = os.path.join(HOME, "bug-hunting", "fullpower")  # final reports fullpower
ATTACK_BASE = os.path.join(HOME, "bug-hunting")  # we'll create bugtype dirs here
WL_BASE = os.path.join(HOME, "Bug-Hunting", "wordlist")  # wordlists from setup.sh

os.makedirs(BBP_BASE, exist_ok=True)
os.makedirs(FULLPOWER_BASE, exist_ok=True)

# ===== helpers =====
def banner():
    title = figlet_format("HUNT", font="slant")
    print(colored(title, "cyan"))
    print(Fore.MAGENTA + "    Bug Bounty Recon Console")
    print(Fore.MAGENTA + "    use with permission only 🚨\n")
    print(Fore.YELLOW + "Temp dir     : ~/bug-hunting/bbp/<target>/")
    print(Fore.YELLOW + "FullPower dir: ~/bug-hunting/fullpower/<target>/fullpower.json")
    print(Fore.YELLOW + "Attack dir   : ~/bug-hunting/<bugtype>/<target>/result.json\n")

def menu():
    print(Fore.CYAN + "[0] FULL POWER (subfinder -> httpx -> nuclei)")
    print(Fore.CYAN + "[1] subfinder")
    print(Fore.CYAN + "[2] httpx")
    print(Fore.CYAN + "[3] gau")
    print(Fore.CYAN + "[4] nuclei")
    print(Fore.CYAN + "[5] hakrawler")
    print(Fore.CYAN + "[6] ffuf")
    print(Fore.CYAN + "[7] gf")
    print(Fore.CYAN + "[8] dalfox")
    print(Fore.CYAN + "[9] exit")
    print(Fore.CYAN + "[10] ATTACK FOCUS (xss / sqli / lfi chain)\n")

def ask(prompt, default=None):
    if default is not None:
        val = input(Fore.GREEN + f"{prompt} [{default}]: ").strip()
        if val == "":
            return default
        return val
    else:
        return input(Fore.GREEN + f"{prompt}: ").strip()

def sanitize_target_for_dir(s):
    s = s.strip()
    s = s.replace("http://", "")
    s = s.replace("https://", "")
    s = s.replace("/", "_")
    return s

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def run_cmd(cmd, cwd=None, shell=False):
    """Run command and stream output."""
    if shell:
        preview = cmd
    else:
        preview = " ".join(cmd)

    print(Fore.YELLOW + "\n[CMD] " + preview)
    print(Fore.YELLOW + "--------------------------------------------------\n")
    try:
        if shell:
            subprocess.run(cmd, shell=True, check=False)
        else:
            subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Aborted by user.\n")
    except Exception as e:
        print(Fore.RED + f"[!] Error running command: {e}\n")

# ===== basic tool runners =====

def run_subfinder():
    target = ask("Target domain (e.g. example.com)")
    threads = ask("Threads for subfinder (-t)", default="200")

    tclean = sanitize_target_for_dir(target)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, "subs.txt")

    cmd = [
        "subfinder",
        "-d", target,
        "-t", threads,
        "-silent",
        "-o", out_file,
    ]

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(cmd)

def run_httpx():
    target = ask("Target name (folder under bbp/, e.g. example.com)")
    tclean = sanitize_target_for_dir(target)
    temp_dir = os.path.join(BBP_BASE, tclean)
    subs_path = os.path.join(temp_dir, "subs.txt")

    if not os.path.isfile(subs_path):
        print(Fore.RED + f"[!] subs.txt not found at {subs_path}")
        subs_path = ask("Custom path to list for httpx -l")

    threads = ask("Threads for httpx (-t)", default="100")
    mc = ask("Match status code (-mc)", default="200")

    out_file = os.path.join(temp_dir, "httpx.txt")

    cmd = [
        "httpx",
        "-l", subs_path,
        "-mc", mc,
        "-t", threads,
        "-silent",
        "-o", out_file,
    ]

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(cmd)

def run_gau():
    target = ask("Target domain for gau (e.g. example.com)")
    tclean = sanitize_target_for_dir(target)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, "gau.txt")

    shell_cmd = f"gau --subs {target} | tee {out_file}"
    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(shell_cmd, shell=True)

def run_nuclei():
    mode = ask("Scan single URL or list? (single/list)", default="list").lower()
    sev = ask("Severity filter (critical,high,medium,low,info) OR blank for ALL", default="")
    conc = ask("Concurrency (-c)", default="50")

    if mode == "single":
        single_url = ask("Single URL (https://target.com)")
        tclean = sanitize_target_for_dir(single_url)
        temp_dir = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file = os.path.join(temp_dir, "nuclei.txt")

        base_cmd = [
            "nuclei",
            "-u", single_url,
            "-c", conc,
            "-o", out_file
        ]
    else:
        base = ask("Target name (folder under bbp/, e.g. example.com)")
        tclean = sanitize_target_for_dir(base)
        temp_dir = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        live_list = os.path.join(temp_dir, "httpx.txt")
        if not os.path.isfile(live_list):
            print(Fore.RED + f"[!] {live_list} not found, give custom list path")
            live_list = ask("Custom path for nuclei -l")

        out_file = os.path.join(temp_dir, "nuclei.txt")

        base_cmd = [
            "nuclei",
            "-l", live_list,
            "-c", conc,
            "-o", out_file
        ]

    if sev != "":
        base_cmd += ["-severity", sev]

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd)

def run_hakrawler():
    start_url = ask("Start URL (https://target.com)")
    include_subs = ask("Include subdomains? (y/n)", default="y").lower()
    depth = ask("Max depth (-d)", default="2")

    tclean = sanitize_target_for_dir(start_url)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, "hakrawler.txt")

    base_cmd = f"hakrawler -url {start_url} -d {depth}"
    if include_subs.startswith("y"):
        base_cmd += " -subs"
    base_cmd += f" | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd, shell=True)

def run_ffuf():
    target_url = ask("Target fuzz URL (use FUZZ, ex: https://site.com/FUZZ or ...?q=FUZZ)")
    tclean = sanitize_target_for_dir(target_url)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    print(Fore.YELLOW + "\nWordlist mode:")
    print(Fore.YELLOW + " 1) raft-large-directories.txt")
    print(Fore.YELLOW + " 2) web-extensions.txt")
    print(Fore.YELLOW + " 3) api-endpoints.txt")
    print(Fore.YELLOW + " 4) lfi.txt")
    print(Fore.YELLOW + " 5) sqli.txt")
    print(Fore.YELLOW + " 6) xss-payloadbox.txt")
    print(Fore.YELLOW + " 7) custom path")

    wl_choice = ask("Choose wordlist", default="1")

    wl_map = {
        "1": os.path.join(WL_BASE, "raft-large-directories.txt"),
        "2": os.path.join(WL_BASE, "web-extensions.txt"),
        "3": os.path.join(WL_BASE, "api-endpoints.txt"),
        "4": os.path.join(WL_BASE, "lfi.txt"),
        "5": os.path.join(WL_BASE, "sqli.txt"),
        "6": os.path.join(WL_BASE, "xss-payloadbox.txt"),
    }

    if wl_choice == "7":
        wl_path = ask("Custom wordlist path (absolute)")
    else:
        wl_path = wl_map.get(wl_choice, wl_map["1"])

    threads = ask("Threads (-t)", default="50")
    mc = ask("Match status code (-mc)", default="200")

    out_file = os.path.join(temp_dir, "ffuf.txt")

    cmd = [
        "ffuf",
        "-u", target_url,
        "-w", wl_path,
        "-t", threads,
        "-mc", mc,
        "-c",
        "-v",
        "-r",
        "-o", out_file
    ]

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(cmd)

def run_gf():
    list_path = ask("Path to list of URLs/params (e.g. ~/bug-hunting/bbp/target/gau.txt)")
    pattern = ask("gf pattern (xss,sqli,lfi,redirect,ssti,...)", default="xss")

    tclean = sanitize_target_for_dir(os.path.basename(os.path.dirname(list_path)))
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, f"gf-{pattern}.txt")
    shell_cmd = f"cat {list_path} | gf {pattern} | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(shell_cmd, shell=True)

def run_dalfox():
    mode = ask("Scan single URL or file list? (single/list)", default="list").lower()
    skip_mining = ask("Skip mining? (--skip-mining-all) y/n", default="y").lower()
    conc = ask("Concurrency (--worker)", default="30")

    payload_file = os.path.join(WL_BASE, "xss-payloadbox.txt")
    if not os.path.isfile(payload_file):
        payload_file = ask("Custom payload file for dalfox --custom-payload", default=payload_file)

    if mode == "single":
        target_url = ask("Target URL for dalfox (ex: https://site.com/vuln.php?x=FUZZ)")
        tclean = sanitize_target_for_dir(target_url)
        temp_dir = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file = os.path.join(temp_dir, "dalfox.txt")

        base_cmd = f"dalfox url {target_url} --custom-payload {payload_file} --worker {conc}"
    else:
        list_path = ask("Path to list of URLs (for dalfox file mode)")
        tclean = sanitize_target_for_dir(os.path.basename(os.path.dirname(list_path)))
        temp_dir = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file = os.path.join(temp_dir, "dalfox.txt")

        base_cmd = f"dalfox file {list_path} --custom-payload {payload_file} --worker {conc}"

    if skip_mining.startswith("y"):
        base_cmd += " --skip-mining-all"

    base_cmd += f" | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd, shell=True)

# ===== FULL POWER MODE =====
def run_fullpower():
    # ask target + threads
    target = ask("Target root (example.com, NOT https://)")
    speed = ask("Threads (-t/-c all tools)", default="50")

    tclean = sanitize_target_for_dir(target)

    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    final_dir = os.path.join(FULLPOWER_BASE, tclean)
    ensure_dir(final_dir)

    subs_file = os.path.join(temp_dir, "subs.txt")
    httpx_file = os.path.join(temp_dir, "httpx.txt")
    nuclei_out = os.path.join(final_dir, "fullpower.json")

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(Fore.MAGENTA + f"\n[ FULL POWER @ {timestamp} ]")
    print(Fore.MAGENTA + f"Target   : {target}")
    print(Fore.MAGENTA + f"Temp dir : {temp_dir}")
    print(Fore.MAGENTA + f"Final    : {nuclei_out}")
    print(Fore.YELLOW  + "\nSubfinder -> httpx -> nuclei. Setelah selesai, file temp dihapus.\n")

    # 1. subfinder
    cmd_subfinder = [
        "subfinder",
        "-d", target,
        "-t", speed,
        "-silent",
        "-o", subs_file
    ]
    print(Fore.CYAN + "\n[1] subfinder -> subs.txt")
    run_cmd(cmd_subfinder)

    # 2. httpx
    cmd_httpx = [
        "httpx",
        "-l", subs_file,
        "-mc", "200",
        "-t", speed,
        "-silent",
        "-o", httpx_file
    ]
    print(Fore.CYAN + "\n[2] httpx -> httpx.txt")
    run_cmd(cmd_httpx)

    # 3. nuclei
    cmd_nuclei = [
        "nuclei",
        "-l", httpx_file,
        "-c", speed,
        "-o", nuclei_out
    ]
    print(Fore.CYAN + "\n[3] nuclei -> fullpower.json")
    run_cmd(cmd_nuclei)

    # cleanup temp
    for f in [subs_file, httpx_file]:
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(Fore.YELLOW + f"[cleanup] removed {f}")
            except:
                print(Fore.RED + f"[!] failed to remove {f}")

    print(Fore.GREEN + "\n[✓] Full power finished.")
    print(Fore.GREEN + f"    Report -> {nuclei_out}\n")

# ===== ATTACK FOCUS MODE =====
def run_attack_focus():
    # 1) ask basic info
    target = ask("Target root (example.com)")
    bug_type = ask("Bug type? (xss / sqli / lfi)", default="xss").lower()
    speed = ask("Speed / threads (default 50)", default="50")

    tclean = sanitize_target_for_dir(target)

    # temp dir for work (bbp/<target>)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    # final dir for this bugtype (~/bug-hunting/<bugtype>/<target>/)
    final_dir = os.path.join(ATTACK_BASE, bug_type, tclean)
    ensure_dir(final_dir)

    gau_raw        = os.path.join(temp_dir, "gau_raw.txt")         # full crawl
    focus_raw      = os.path.join(temp_dir, "focus_raw.txt")       # filtered by gf
    focus_alive    = os.path.join(temp_dir, "focus_alive.txt")     # only live 200
    result_file    = os.path.join(final_dir, "result.json")        # final report

    print(Fore.MAGENTA + "\n[ ATTACK FOCUS MODE ]")
    print(Fore.MAGENTA + f"Target   : {target}")
    print(Fore.MAGENTA + f"Bug type : {bug_type}")
    print(Fore.MAGENTA + f"Temp dir : {temp_dir}")
    print(Fore.MAGENTA + f"Final    : {result_file}")
    print(Fore.YELLOW  + "\nChain: gau -> gf(filter by vuln type) -> httpx (live only) -> exploit tool\n")

    # STEP 1: GAU (collect archive URLs / params)
    shell_gau = f"gau --subs {target} | tee {gau_raw}"
    print(Fore.CYAN + "\n[1] gau -> gau_raw.txt")
    run_cmd(shell_gau, shell=True)

    # STEP 2: GF FILTER (pick only interesting URLs for chosen vuln type)
    # we'll map bug_type (xss/sqli/lfi) directly to gf pattern with same name
    gf_pattern = bug_type  # expects gf xss / gf sqli / gf lfi to exist in ~/.gf
    shell_gf = f"cat {gau_raw} | gf {gf_pattern} | tee {focus_raw}"
    print(Fore.CYAN + "\n[2] gf -> focus_raw.txt")
    run_cmd(shell_gf, shell=True)

    # STEP 3: HTTPX (only test filtered URLs, check which are actually alive 200)
    cmd_httpx = [
        "httpx",
        "-l", focus_raw,
        "-mc", "200",
        "-t", speed,
        "-silent",
        "-o", focus_alive
    ]
    print(Fore.CYAN + "\n[3] httpx (200 only) -> focus_alive.txt")
    run_cmd(cmd_httpx)

    # STEP 4: EXPLOIT TOOL
    print(Fore.CYAN + "\n[4] exploitation -> result.json")

    if bug_type == "xss":
        # dalfox against list
        payload_file = os.path.join(WL_BASE, "xss-payloadbox.txt")
        if not os.path.isfile(payload_file):
            # fallback: still pass this path, user can adjust later
            payload_file = payload_file

        # default: skip mining biar gak barbar
        shell_dalfox = (
            f"dalfox file {focus_alive} "
            f"--custom-payload {payload_file} "
            f"--worker {speed} "
            f"--skip-mining-all "
            f"| tee {result_file}"
        )
        run_cmd(shell_dalfox, shell=True)

    elif bug_type == "sqli":
        # loop sqlmap safe mode for each URL in focus_alive
        # we keep batch / risk=1 / level=1 / smart to stay 'legal-ish'
        shell_sqlmap = (
            "while read -r url; do "
            "echo '[*] Testing SQLi:' \"$url\"; "
            "sqlmap -u \"$url\" --batch --level=1 --risk=1 --random-agent --smart --flush-session; "
            "done < " + focus_alive + " | tee " + result_file
        )
        run_cmd(shell_sqlmap, shell=True)

    elif bug_type == "lfi":
        # nuclei scan potential LFI-style URLs only
        shell_nuclei = (
            f"nuclei -l {focus_alive} -c {speed} -o {result_file}"
        )
        run_cmd(shell_nuclei, shell=True)

    else:
        print(Fore.RED + f"[!] Unknown bug_type '{bug_type}'. Supported: xss / sqli / lfi")
        print(Fore.RED + "    Skipping exploit step.")

    # STEP 5: CLEANUP TEMP FILES
    for f in [gau_raw, focus_raw, focus_alive]:
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(Fore.YELLOW + f"[cleanup] removed {f}")
            except:
                print(Fore.RED + f"[!] failed to remove {f}")

    print(Fore.GREEN + "\n[✓] Attack focus finished.")
    print(Fore.GREEN + f"    Final report -> {result_file}\n")
    
# ===== main loop =====
def main():
    while True:
        os.system("clear")
        banner()
        menu()
        choice = ask("pilih menu", default="9")

        if choice == "0":
            run_fullpower()
        elif choice == "1":
            run_subfinder()
        elif choice == "2":
            run_httpx()
        elif choice == "3":
            run_gau()
        elif choice == "4":
            run_nuclei()
        elif choice == "5":
            run_hakrawler()
        elif choice == "6":
            run_ffuf()
        elif choice == "7":
            run_gf()
        elif choice == "8":
            run_dalfox()
        elif choice == "9":
            print(Fore.YELLOW + "bye hacker. stay legal. ✌")
            break
        elif choice == "10":
            run_attack_focus()
        else:
            print(Fore.RED + "invalid choice.")

        input(Fore.CYAN + "\n[press ENTER to continue]")

if __name__ == "__main__":
    main()
