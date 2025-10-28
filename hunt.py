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

BBP_BASE        = os.path.join(HOME, "bug-hunting", "bbp")          # workspace temp per-target
FULLPOWER_BASE  = os.path.join(HOME, "bug-hunting", "fullpower")    # fullpower final
ATTACK_BASE     = os.path.join(HOME, "bug-hunting")                 # attack-focus final dir under bugtype
CUSTOM_BASE     = os.path.join(HOME, "bug-hunting", "custom")       # custom chain final
XRAY_BASE       = os.path.join(HOME, "bug-hunting", "xray")         # xray scan final
WL_BASE         = os.path.join(HOME, "Bug-Hunting", "wordlist")     # wordlists from setup.sh

for p in [BBP_BASE, FULLPOWER_BASE, CUSTOM_BASE, XRAY_BASE]:
    os.makedirs(p, exist_ok=True)

# ===== helpers =====
def big_banner():
    title = figlet_format("BUG-HUNTING", font="slant")
    print(colored(title, "cyan"))
    print(Fore.MAGENTA + "          recon  •  fuzz  •  vuln scan")
    print(Fore.RED +    "      USE ONLY WITH PERMISSION. SERIUS. 🚨\n")
    print(Fore.YELLOW + " Temp      : ~/bug-hunting/bbp/<target>/")
    print(Fore.YELLOW + " FullPower : ~/bug-hunting/fullpower/<target>/fullpower.json")
    print(Fore.YELLOW + " Attack    : ~/bug-hunting/<bugtype>/<target>/result.json")
    print(Fore.YELLOW + " Custom    : ~/bug-hunting/custom/<target>/custom.json")
    print(Fore.YELLOW + " Xray      : ~/bug-hunting/xray/<target>/xray.json\n")

def recon_banner():
    title = figlet_format("RECON", font="slant")
    print(colored(title, "green"))
    print(Fore.CYAN + "Subdomain enum, live hosts, crawling, fuzz, etc.\n")

def xray_banner():
    title = figlet_format("XRAY", font="slant")
    print(colored(title, "red"))
    print(Fore.CYAN + "High-signal vuln scanner (chaitin/xray)\n")

def attack_banner():
    title = figlet_format("ATTACK", font="slant")
    print(colored(title, "yellow"))
    print(Fore.CYAN + "Chain: gau -> gf -> httpx -> exploit-tool\n")

def fullpower_banner():
    title = figlet_format("FULL POWER", font="slant")
    print(colored(title, "magenta"))
    print(Fore.CYAN + "subfinder -> httpx -> nuclei (auto). Temp cleaned.\n")

def custom_banner():
    title = figlet_format("CUSTOM", font="slant")
    print(colored(title, "blue"))
    print(Fore.CYAN + "You pick the combo. I execute in that order.\n")

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

def run_cmd(cmd, shell=False):
    """
    Run a command and stream output live.
    cmd: list (if shell=False) OR string (if shell=True)
    """
    preview = cmd if shell else " ".join(cmd)
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

# =====================================================================
# LOW-LEVEL RUNNERS (single tools, interactive)
# =====================================================================

def run_subfinder_interactive():
    target = ask("Target domain (example.com)")
    threads = ask("Threads for subfinder (-t)", default="200")

    tclean   = sanitize_target_for_dir(target)
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

def run_httpx_interactive():
    target_name = ask("Target name (folder under bbp/, e.g. example.com)")
    tclean   = sanitize_target_for_dir(target_name)
    temp_dir = os.path.join(BBP_BASE, tclean)
    subs_txt = os.path.join(temp_dir, "subs.txt")

    if not os.path.isfile(subs_txt):
        print(Fore.RED + f"[!] subs.txt not found at {subs_txt}")
        subs_txt = ask("Custom path for httpx -l")

    threads = ask("Threads for httpx (-t)", default="100")
    mc      = ask("Match status code (-mc)", default="200")

    out_file = os.path.join(temp_dir, "httpx.txt")

    cmd = [
        "httpx",
        "-l", subs_txt,
        "-mc", mc,
        "-t", threads,
        "-silent",
        "-o", out_file,
    ]

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(cmd)

def run_gau_interactive():
    target = ask("Target domain for gau (example.com)")
    tclean   = sanitize_target_for_dir(target)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, "gau.txt")

    shell_cmd = f"gau --subs {target} | tee {out_file}"
    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(shell_cmd, shell=True)

def run_nuclei_interactive():
    mode  = ask("Scan single URL or list? (single/list)", default="list").lower()
    sev   = ask("Severity filter (critical,high,medium,low,info) OR blank for ALL", default="")
    conc  = ask("Concurrency (-c)", default="50")

    if mode == "single":
        single_url = ask("Single URL (https://target.com)")
        tclean     = sanitize_target_for_dir(single_url)
        temp_dir   = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file   = os.path.join(temp_dir, "nuclei.txt")

        base_cmd = [
            "nuclei",
            "-u", single_url,
            "-c", conc,
            "-o", out_file
        ]
    else:
        base        = ask("Target name (folder under bbp/, e.g. example.com)")
        tclean      = sanitize_target_for_dir(base)
        temp_dir    = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        httpx_list  = os.path.join(temp_dir, "httpx.txt")
        if not os.path.isfile(httpx_list):
            print(Fore.RED + f"[!] {httpx_list} not found, provide custom list path")
            httpx_list = ask("Custom path for nuclei -l")

        out_file = os.path.join(temp_dir, "nuclei.txt")

        base_cmd = [
            "nuclei",
            "-l", httpx_list,
            "-c", conc,
            "-o", out_file
        ]

    if sev != "":
        base_cmd += ["-severity", sev]

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd)

def run_hakrawler_interactive():
    start_url     = ask("Start URL (https://target.com)")
    include_subs  = ask("Include subdomains? (y/n)", default="y").lower()
    depth         = ask("Max depth (-d)", default="2")

    tclean   = sanitize_target_for_dir(start_url)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, "hakrawler.txt")

    base_cmd = f"hakrawler -url {start_url} -d {depth}"
    if include_subs.startswith("y"):
        base_cmd += " -subs"
    base_cmd += f" | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd, shell=True)

def run_ffuf_interactive():
    target_url = ask("Target fuzz URL (must contain FUZZ, ex: https://site.com/FUZZ or ...?q=FUZZ)")
    tclean   = sanitize_target_for_dir(target_url)
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
    mc      = ask("Match status code (-mc)", default="200")

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

def run_gf_interactive():
    list_path = ask("Path to list of URLs/params (ex: ~/bug-hunting/bbp/target/gau.txt)")
    pattern   = ask("gf pattern (xss,sqli,lfi,redirect,ssti,...)", default="xss")

    # try to infer target dir name
    tguess   = os.path.basename(os.path.dirname(list_path))
    tclean   = sanitize_target_for_dir(tguess)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, f"gf-{pattern}.txt")
    shell_cmd = f"cat {list_path} | gf {pattern} | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(shell_cmd, shell=True)

def run_dalfox_interactive():
    mode         = ask("Scan single URL or file list? (single/list)", default="list").lower()
    skip_mining  = ask("Skip mining? (--skip-mining-all) y/n", default="y").lower()
    conc         = ask("Concurrency (--worker)", default="30")

    payload_file = os.path.join(WL_BASE, "xss-payloadbox.txt")
    if not os.path.isfile(payload_file):
        payload_file = ask("Custom payload file for dalfox --custom-payload", default=payload_file)

    if mode == "single":
        target_url = ask("Target URL for dalfox (ex: https://site.com/vuln.php?x=FUZZ)")
        tclean     = sanitize_target_for_dir(target_url)
        temp_dir   = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file   = os.path.join(temp_dir, "dalfox.txt")

        base_cmd = f"dalfox url {target_url} --custom-payload {payload_file} --worker {conc}"
    else:
        list_path = ask("Path to list of URLs (for dalfox file mode)")
        tguess    = os.path.basename(os.path.dirname(list_path))
        tclean    = sanitize_target_for_dir(tguess)
        temp_dir  = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file  = os.path.join(temp_dir, "dalfox.txt")

        base_cmd = f"dalfox file {list_path} --custom-payload {payload_file} --worker {conc}"

    if skip_mining.startswith("y"):
        base_cmd += " --skip-mining-all"

    base_cmd += f" | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd, shell=True)

def run_xray_interactive():
    """
    xray modes we support:
      - single URL  : xray webscan --url https://target --json-output out.json
      - multi file  : xray webscan --url-file urls.txt --json-output out.json
    optional: --plugins plugin1,plugin2
    """
    mode    = ask("Scan mode? (single/list)", default="single").lower()
    plugins = ask("Plugins list (comma, blank=all)", default="")

    if mode == "single":
        url = ask("Target URL (https://target.com)")
        tclean = sanitize_target_for_dir(url)
    else:
        use_bbp = ask("Use bbp/<target>/httpx.txt ? (y/n)", default="y").lower()
        if use_bbp.startswith("y"):
            base_target = ask("Target name in bbp (e.g. example.com)")
            tclean = sanitize_target_for_dir(base_target)
            httpx_file = os.path.join(BBP_BASE, tclean, "httpx.txt")
            if not os.path.isfile(httpx_file):
                print(Fore.RED + f"[!] {httpx_file} not found, fallback custom path.")
                httpx_file = ask("Custom path to URL list for xray --url-file")
            list_path = httpx_file
        else:
            list_path = ask("Custom path to URL list for xray --url-file")
            tguess    = os.path.basename(os.path.dirname(list_path))
            tclean    = sanitize_target_for_dir(tguess)

    final_dir = os.path.join(XRAY_BASE, tclean)
    ensure_dir(final_dir)

    out_json = os.path.join(final_dir, "xray.json")

    if mode == "single":
        base_cmd = f"xray webscan --url \"{url}\""
    else:
        base_cmd = f"xray webscan --url-file \"{list_path}\""

    if plugins != "":
        base_cmd += f" --plugins {plugins}"

    base_cmd += f" --json-output \"{out_json}\""

    print(Fore.CYAN + f"\n[+] Final report -> {out_json}")
    run_cmd(base_cmd, shell=True)

# =====================================================================
# AUTO MODES (fullpower / attack-focus / custom chain)
# =====================================================================

def run_fullpower_auto():
    fullpower_banner()

    target = ask("Target root (example.com, no https://)")
    speed  = ask("Threads (-t / -c for all tools)", default="50")

    tclean    = sanitize_target_for_dir(target)

    temp_dir  = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    final_dir = os.path.join(FULLPOWER_BASE, tclean)
    ensure_dir(final_dir)

    subs_file    = os.path.join(temp_dir, "subs.txt")
    httpx_file   = os.path.join(temp_dir, "httpx.txt")
    nuclei_final = os.path.join(final_dir, "fullpower.json")

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(Fore.MAGENTA + f"\n[ FULL POWER @ {timestamp} ]")
    print(Fore.MAGENTA + f"Target    : {target}")
    print(Fore.MAGENTA + f"Temp dir  : {temp_dir}")
    print(Fore.MAGENTA + f"Final json: {nuclei_final}")
    print(Fore.YELLOW  + "\nChain: subfinder -> httpx -> nuclei\n")

    # 1. subfinder -> subs.txt
    cmd_subfinder = [
        "subfinder",
        "-d", target,
        "-t", speed,
        "-silent",
        "-o", subs_file
    ]
    print(Fore.CYAN + "\n[1] subfinder -> subs.txt")
    run_cmd(cmd_subfinder)

    # 2. httpx -> httpx.txt
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

    # 3. nuclei -> final json
    cmd_nuclei = [
        "nuclei",
        "-l", httpx_file,
        "-c", speed,
        "-o", nuclei_final
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
    print(Fore.GREEN + f"    Report -> {nuclei_final}\n")

def run_attack_focus_auto():
    attack_banner()

    target   = ask("Target root (example.com)")
    bug_type = ask("Bug type? (xss / sqli / lfi)", default="xss").lower()
    speed    = ask("Speed / threads (default 50)", default="50")

    tclean   = sanitize_target_for_dir(target)

    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    final_dir = os.path.join(ATTACK_BASE, bug_type, tclean)
    ensure_dir(final_dir)

    gau_raw      = os.path.join(temp_dir, "gau_raw.txt")      # step dump
    focus_raw    = os.path.join(temp_dir, "focus_raw.txt")    # gf-filtered
    focus_alive  = os.path.join(temp_dir, "focus_alive.txt")  # httpx alive
    result_json  = os.path.join(final_dir, "result.json")     # final json/report

    print(Fore.YELLOW + f"\nTemp dir : {temp_dir}")
    print(Fore.YELLOW + f"Final    : {result_json}")

    # 1) gau
    shell_gau = f"gau --subs {target} | tee {gau_raw}"
    print(Fore.CYAN + "\n[1] gau -> gau_raw.txt")
    run_cmd(shell_gau, shell=True)

    # 2) gf filter
    gf_pattern = bug_type  # expects ~/.gf/xss.json / sqli.json / lfi.json
    shell_gf   = f"cat {gau_raw} | gf {gf_pattern} | tee {focus_raw}"
    print(Fore.CYAN + "\n[2] gf -> focus_raw.txt")
    run_cmd(shell_gf, shell=True)

    # 3) httpx (alive 200 only)
    cmd_httpx = [
        "httpx",
        "-l", focus_raw,
        "-mc", "200",
        "-t", speed,
        "-silent",
        "-o", focus_alive
    ]
    print(Fore.CYAN + "\n[3] httpx -> focus_alive.txt")
    run_cmd(cmd_httpx)

    # 4) exploit step
    print(Fore.CYAN + "\n[4] exploit -> result.json")

    if bug_type == "xss":
        payload_file = os.path.join(WL_BASE, "xss-payloadbox.txt")
        shell_dalfox = (
            f"dalfox file {focus_alive} "
            f"--custom-payload {payload_file} "
            f"--worker {speed} "
            f"--skip-mining-all "
            f"| tee {result_json}"
        )
        run_cmd(shell_dalfox, shell=True)

    elif bug_type == "sqli":
        shell_sqlmap = (
            "while read -r url; do "
            "echo '[*] Testing SQLi:' \"$url\"; "
            "sqlmap -u \"$url\" --batch --level=1 --risk=1 --random-agent --smart --flush-session; "
            "done < " + focus_alive + " | tee " + result_json
        )
        run_cmd(shell_sqlmap, shell=True)

    elif bug_type == "lfi":
        shell_nuclei = (
            f"nuclei -l {focus_alive} -c {speed} -o {result_json}"
        )
        run_cmd(shell_nuclei, shell=True)

    else:
        print(Fore.RED + f"[!] Unsupported bug_type '{bug_type}' -> skipping exploit step")

    # cleanup temp stage files
    for f in [gau_raw, focus_raw, focus_alive]:
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(Fore.YELLOW + f"[cleanup] removed {f}")
            except:
                print(Fore.RED + f"[!] failed to remove {f}")

    print(Fore.GREEN + "\n[✓] Attack focus done.")
    print(Fore.GREEN + f"    Final report -> {result_json}\n")

def run_custom_chain_auto():
    """
    Mode freestyle:
      - tanya target
      - tanya speed
      - tanya urutan tools apa aja mau dijalankan:
        1=subfinder   (-> subs.txt)
        2=httpx       (subs.txt -> httpx.txt, -mc 200)
        3=nuclei      (httpx.txt -> nuclei_custom.txt)
        4=gau         (-> gau.txt)
        5=xray        (httpx.txt -> xray_custom.json via --url-file)

    semua step nyimpen temp di bbp/<target>/*.txt
    hasil akhir = artifact step terakhir.
    kita copy jadi ~/bug-hunting/custom/<target>/custom.json
    """
    custom_banner()

    target = ask("Target root (example.com)")
    speed  = ask("Threads/speed (default 50)", default="50")
    order  = ask(
        "Input tool order (comma). 1=subfinder,2=httpx,3=nuclei,4=gau,5=xray",
        default="1,2,3"
    )

    tclean    = sanitize_target_for_dir(target)
    temp_dir  = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    final_dir = os.path.join(CUSTOM_BASE, tclean)
    ensure_dir(final_dir)

    subs_file   = os.path.join(temp_dir, "subs.txt")
    httpx_file  = os.path.join(temp_dir, "httpx.txt")
    nuclei_file = os.path.join(temp_dir, "nuclei_custom.txt")
    gau_file    = os.path.join(temp_dir, "gau.txt")
    xray_json   = os.path.join(temp_dir, "xray_custom.json")
    final_json  = os.path.join(final_dir, "custom.json")

    steps = [s.strip() for s in order.split(",") if s.strip() != ""]
    last_artifact = None  # path to final artifact from last executed tool

    for step in steps:
        if step == "1":
            # subfinder
            cmd_subfinder = [
                "subfinder",
                "-d", target,
                "-t", speed,
                "-silent",
                "-o", subs_file
            ]
            print(Fore.CYAN + "\n[custom] subfinder -> subs.txt")
            run_cmd(cmd_subfinder)
            last_artifact = subs_file

        elif step == "2":
            # httpx from subs
            src_list = subs_file
            if not os.path.isfile(src_list):
                print(Fore.RED + f"[!] {src_list} missing. custom httpx needs subs.txt first.")
                src_list = ask("Custom path for httpx -l")
            cmd_httpx = [
                "httpx",
                "-l", src_list,
                "-mc", "200",
                "-t", speed,
                "-silent",
                "-o", httpx_file
            ]
            print(Fore.CYAN + "\n[custom] httpx -> httpx.txt")
            run_cmd(cmd_httpx)
            last_artifact = httpx_file

        elif step == "3":
            # nuclei list mode from httpx
            src_list = httpx_file
            if not os.path.isfile(src_list):
                print(Fore.RED + f"[!] {src_list} missing. custom nuclei needs httpx.txt first.")
                src_list = ask("Custom path for nuclei -l")
            cmd_nuclei = [
                "nuclei",
                "-l", src_list,
                "-c", speed,
                "-o", nuclei_file
            ]
            print(Fore.CYAN + "\n[custom] nuclei -> nuclei_custom.txt")
            run_cmd(cmd_nuclei)
            last_artifact = nuclei_file

        elif step == "4":
            # gau dump
            shell_gau = f"gau --subs {target} | tee {gau_file}"
            print(Fore.CYAN + "\n[custom] gau -> gau.txt")
            run_cmd(shell_gau, shell=True)
            last_artifact = gau_file

        elif step == "5":
            # xray with httpx.txt as url-file default
            src_list = httpx_file
            if not os.path.isfile(src_list):
                print(Fore.RED + f"[!] {src_list} missing. xray default uses httpx.txt alive hosts.")
                src_list = ask("Custom path for xray --url-file")

            plugins = ask("xray plugins (comma) blank=all", default="")

            base_cmd = f"xray webscan --url-file \"{src_list}\""
            if plugins != "":
                base_cmd += f" --plugins {plugins}"
            base_cmd += f" --json-output \"{xray_json}\""

            print(Fore.CYAN + "\n[custom] xray -> xray_custom.json")
            run_cmd(base_cmd, shell=True)
            last_artifact = xray_json

        else:
            print(Fore.RED + f"[!] step '{step}' gak dikenal, skip.")

    # save/copy final artifact jadi custom.json
    if last_artifact and os.path.isfile(last_artifact):
        try:
            shutil.copyfile(last_artifact, final_json)
            print(Fore.GREEN + f"\n[+] Saved final chain result -> {final_json}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to copy final artifact: {e}")
    else:
        print(Fore.RED + "\n[!] No final artifact produced, custom.json not written")

    # optional cleanup block:
    # for f in [subs_file, httpx_file, nuclei_file, gau_file, xray_json]:
    #     if os.path.isfile(f):
    #         try:
    #             os.remove(f)
    #             print(Fore.YELLOW + f"[cleanup] removed {f}")
    #         except:
    #             print(Fore.RED + f"[!] failed to remove {f}")

    print(Fore.GREEN + "\n[✓] Custom chain done.\n")

# =====================================================================
# MENUS
# =====================================================================

def menu_main():
    big_banner()
    print(Fore.CYAN + "[1] Recon & Enum tools")
    print(Fore.CYAN + "[2] Full Power (auto recon end-to-end)")
    print(Fore.CYAN + "[3] Attack Focus (xss / sqli / lfi chain)")
    print(Fore.CYAN + "[4] Xray Scan")
    print(Fore.CYAN + "[5] Custom Chain (you pick steps)")
    print(Fore.CYAN + "[0] Exit\n")

def menu_recon():
    recon_banner()
    print(Fore.CYAN + "[1] subfinder")
    print(Fore.CYAN + "[2] httpx")
    print(Fore.CYAN + "[3] gau")
    print(Fore.CYAN + "[4] nuclei")
    print(Fore.CYAN + "[5] hakrawler")
    print(Fore.CYAN + "[6] ffuf")
    print(Fore.CYAN + "[7] gf")
    print(Fore.CYAN + "[8] dalfox")
    print(Fore.CYAN + "[9] Back to main\n")

def menu_xray():
    xray_banner()
    print(Fore.CYAN + "[1] Run xray scan (single URL / list file)")
    print(Fore.CYAN + "[9] Back to main\n")

def main():
    while True:
        os.system("clear")
        menu_main()
        choice = ask("pilih menu", default="0")

        if choice == "0":
            print(Fore.YELLOW + "bye hacker. stay legal. ✌")
            break

        elif choice == "1":
            # recon submenu
            while True:
                os.system("clear")
                menu_recon()
                rc = ask("recon menu", default="9")

                if rc == "1":
                    run_subfinder_interactive()
                elif rc == "2":
                    run_httpx_interactive()
                elif rc == "3":
                    run_gau_interactive()
                elif rc == "4":
                    run_nuclei_interactive()
                elif rc == "5":
                    run_hakrawler_interactive()
                elif rc == "6":
                    run_ffuf_interactive()
                elif rc == "7":
                    run_gf_interactive()
                elif rc == "8":
                    run_dalfox_interactive()
                elif rc == "9":
                    break
                else:
                    print(Fore.RED + "invalid choice.")
                input(Fore.CYAN + "\n[press ENTER to continue]")

        elif choice == "2":
            # full power auto mode
            os.system("clear")
            run_fullpower_auto()
            input(Fore.CYAN + "\n[press ENTER to continue]")

        elif choice == "3":
            # attack focus auto mode
            os.system("clear")
            run_attack_focus_auto()
            input(Fore.CYAN + "\n[press ENTER to continue]")

        elif choice == "4":
            # xray submenu
            while True:
                os.system("clear")
                menu_xray()
                xc = ask("xray menu", default="9")
                if xc == "1":
                    run_xray_interactive()
                    input(Fore.CYAN + "\n[press ENTER to continue]")
                elif xc == "9":
                    break
                else:
                    print(Fore.RED + "invalid choice.")
                    input(Fore.CYAN + "\n[press ENTER to continue]")

        elif choice == "5":
            # custom chain mode
            os.system("clear")
            run_custom_chain_auto()
            input(Fore.CYAN + "\n[press ENTER to continue]")

        else:
            print(Fore.RED + "invalid choice.")
            input(Fore.CYAN + "\n[press ENTER to continue]")


if __name__ == "__main__":
    main()
