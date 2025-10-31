#!/usr/bin/env python3
import os
import subprocess
import sys
import threading
from datetime import datetime
from colorama import Fore, Style, init as colorama_init
from pyfiglet import figlet_format
from termcolor import colored

# init color
colorama_init(autoreset=True)

HOME = os.path.expanduser("~")

# workspace dirs
BBP_BASE         = os.path.join(HOME, "bug-hunting", "bbp")         # temp / recon workspace per target
FULLPOWER_BASE   = os.path.join(HOME, "bug-hunting", "fullpower")    # final reports for fullpower mode
ATTACK_BASE      = os.path.join(HOME, "bug-hunting")                 # bugtype/<target>
CUSTOM_BASE      = os.path.join(HOME, "bug-hunting", "custom")       # custom/<target>/<target>.json
WL_BASE          = os.path.join(HOME, "Bug-Hunting", "wordlist")     # from setup.sh
XRAY_WRAPPER_BIN = "xray"                                           # we installed wrapper in /usr/local/bin/xray

for d in [BBP_BASE, FULLPOWER_BASE, ATTACK_BASE, CUSTOM_BASE]:
    os.makedirs(d, exist_ok=True)

# ───────────────────────── helpers ─────────────────────────
def banner_main():
    title = figlet_format("BUG-HUNTING", font="slant")
    print(colored(title, "cyan"))
    print(Fore.MAGENTA + "      all-in-one recon / fuzz / exploit console")
    print(Fore.MAGENTA + "      use with permission only 🚨\n")
    print(Fore.YELLOW + "Temp dir     : ~/bug-hunting/bbp/<target>/")
    print(Fore.YELLOW + "FullPower    : ~/bug-hunting/fullpower/<target>/fullpower.json")
    print(Fore.YELLOW + "Attack Focus : ~/bug-hunting/<bugtype>/<target>/result.json")
    print(Fore.YELLOW + "Custom Chain : ~/bug-hunting/custom/<target>/<target>.json\n")

def banner_section(title):
    big = figlet_format(title, font="small")
    print(colored(big, "cyan"))

def ask(prompt, default=None):
    if default is not None:
        val = input(Fore.GREEN + f"{prompt} [{default}]: ").strip()
        return default if val == "" else val
    return input(Fore.GREEN + f"{prompt}: ").strip()

def ask_menu(prompt, choices_map, multi=False, allow_blank=False):
    """
    choices_map: { "1":("desc","value"), "2":("desc","value"), ... }
    multi=False  -> returns single "value"
    multi=True   -> returns list of "value"
    allow_blank=True -> '' allowed, returns [] (multi) / None (single)
    """
    # render
    for key,(desc,val) in choices_map.items():
        print(Fore.YELLOW + f"[{key}] {desc}")
    raw = input(Fore.GREEN + f"{prompt}: ").strip()

    if raw == "" and allow_blank:
        if multi:
            return []
        else:
            return None

    if multi:
        picked_vals = []
        parts = [p.strip() for p in raw.split(",") if p.strip() != ""]
        for p in parts:
            if p in choices_map:
                picked_vals.append(choices_map[p][1])
        return picked_vals
    else:
        if raw in choices_map:
            return choices_map[raw][1]
        return None

def sanitize_target_for_dir(s):
    s = s.strip()
    s = s.replace("http://", "")
    s = s.replace("https://", "")
    s = s.replace("/", "_")
    return s

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def run_cmd(cmd, shell=False):
    """Run command and stream output."""
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

def prompt_nuclei_severity():
    """
    Ask nuclei severity (multi-select), return list or []
    If [] -> no -severity flag (scan all)
    """
    print(Fore.CYAN + "\nSelect nuclei severity (multi, comma separated). ENTER for all:")
    sev_map = {
        "1":("low","low"),
        "2":("medium","medium"),
        "3":("high","high"),
        "4":("critical","critical"),
    }
    sev_list = ask_menu("severity?", sev_map, multi=True, allow_blank=True)
    return sev_list  # [] means all

def prompt_xray_plugins():
    """
    Ask xray plugins (multi). ENTER => all ([])
    mapping follows xray doc.
    """
    print(Fore.CYAN + "\nSelect xray plugins (multi 1,2,3...). ENTER for ALL:")
    plug_map = {
        "1": ("xss","xss"),
        "2": ("sqldet (SQLi)","sqldet"),
        "3": ("cmd-injection","cmd-injection"),
        "4": ("dirscan","dirscan"),
        "5": ("path-traversal","path-traversal"),
        "6": ("ssrf","ssrf"),
        "7": ("baseline","baseline"),
        "8": ("redirect","redirect"),
        "9": ("crlf-injection","crlf-injection"),
        "10":("upload","upload"),
        "11":("brute-force","brute-force"),
        "12":("jsonp","jsonp"),
        "13":("phantasm (poc mgmt)","phantasm"),
    }
    plugs = ask_menu("plugins?", plug_map, multi=True, allow_blank=True)
    return plugs  # [] => all

# ───────────────────────── individual tools ─────────────────────────
def tool_subfinder():
    banner_section("SUBFINDER")
    target = ask("Target domain (example.com)")
    threads = ask("Threads (-t)", default="200")

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

def tool_httpx():
    banner_section("HTTPX")

    # mode pilih sumber list (1=subfinder result in bbp/<target>/subs.txt, 2=custom path)
    choice_map = {
        "1": ("Use ~/bug-hunting/bbp/<target>/subs.txt", "auto"),
        "2": ("Custom path to list (-l)", "custom"),
    }
    src_mode = ask_menu("Pick source list", choice_map, multi=False, allow_blank=False)
    if src_mode == "auto":
        base_name = ask("Target name (folder under bbp/, e.g. example.com)")
        tclean    = sanitize_target_for_dir(base_name)
        temp_dir  = os.path.join(BBP_BASE, tclean)
        subs_path = os.path.join(temp_dir, "subs.txt")
        if not os.path.isfile(subs_path):
            print(Fore.RED + f"[!] subs.txt not found at {subs_path}")
            return
    else:
        subs_path = ask("Custom list path")

    threads = ask("Threads (-t)", default="100")
    mc      = ask("Match status code (-mc)", default="200")

    # output always placed next to list dir (bbp/<target>/httpx.txt if auto mode)
    if src_mode == "auto":
        out_file = os.path.join(temp_dir, "httpx.txt")
    else:
        # guess parent folder of given file
        parent  = os.path.dirname(os.path.abspath(subs_path))
        out_file = os.path.join(parent, "httpx.txt")

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

def tool_gau():
    banner_section("GAU")
    target = ask("Target domain for gau (example.com)")
    tclean   = sanitize_target_for_dir(target)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file = os.path.join(temp_dir, "gau.txt")

    # gau config (.gau.toml) already excludes common images etc
    shell_cmd = f"gau --subs {target} | tee {out_file}"
    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(shell_cmd, shell=True)

def tool_nuclei():
    banner_section("NUCLEI")

    # mode 1=list file, 2=single URL
    choice_map = {
        "1": ("Scan list (-l file)", "list"),
        "2": ("Scan single URL (-u https://..)", "single"),
    }
    scan_mode = ask_menu("Pick mode", choice_map, multi=False, allow_blank=False)

    conc      = ask("Concurrency (-c)", default="50")
    sev_list  = prompt_nuclei_severity()  # [] => all

    if scan_mode == "list":
        # try to help with common path
        auto_choice = ask("Use bbp/<target>/httpx.txt ? (enter target.com or leave blank for custom)", default="")
        if auto_choice.strip() != "":
            tclean    = sanitize_target_for_dir(auto_choice)
            temp_dir  = os.path.join(BBP_BASE, tclean)
            ensure_dir(temp_dir)
            live_list = os.path.join(temp_dir, "httpx.txt")
        else:
            live_list = ask("Custom path to list for nuclei -l")

        out_file = os.path.join(temp_dir, "nuclei.txt") if auto_choice else (os.path.join(os.path.dirname(os.path.abspath(live_list)), "nuclei.txt"))

        base_cmd = [
            "nuclei",
            "-l", live_list,
            "-c", conc,
            "-o", out_file
        ]

    else:
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

    if len(sev_list) > 0:
        base_cmd += ["-severity", ",".join(sev_list)]

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd)

def tool_hakrawler():
    banner_section("HAKRAWLER")
    # 1 single URL crawl
    start_url = ask("Start URL (https://target.com)")
    include_subs = ask("Include subdomains? (y/n)", default="y").lower()
    depth        = ask("Max depth (-d)", default="2")

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

def tool_ffuf():
    banner_section("FFUF")

    target_url = ask("Target fuzz URL (use FUZZ, e.g. https://site.com/FUZZ or ...?q=FUZZ)")
    tclean   = sanitize_target_for_dir(target_url)
    temp_dir = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    print(Fore.YELLOW + "\nWordlist choice:")
    wl_map = {
        "1": ("raft-large-directories.txt", os.path.join(WL_BASE, "raft-large-directories.txt")),
        "2": ("web-extensions.txt",        os.path.join(WL_BASE, "web-extensions.txt")),
        "3": ("api-endpoints.txt",         os.path.join(WL_BASE, "api-endpoints.txt")),
        "4": ("lfi.txt",                   os.path.join(WL_BASE, "lfi.txt")),
        "5": ("sqli.txt",                  os.path.join(WL_BASE, "sqli.txt")),
        "6": ("xss-payloadbox.txt",        os.path.join(WL_BASE, "xss-payloadbox.txt")),
        "7": ("Custom path",               "custom"),
    }

    wl_choice = ask_menu("Choose wordlist", wl_map, multi=False, allow_blank=False)
    if wl_choice == "custom":
        wl_path = ask("Custom wordlist path (absolute)")
    else:
        wl_path = wl_choice

    threads = ask("Threads (-t)", default="50")
    mc      = ask("Match status code (-mc)", default="200")

    out_file = os.path.join(temp_dir, "ffuf.txt")

    # we avoid -o to keep plain txt output
    cmd = f"ffuf -u '{target_url}' -w '{wl_path}' -t {threads} -mc {mc} -c -v -r | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(cmd, shell=True)

def tool_gf():
    banner_section("GF (pattern filter)")
    list_path = ask("Path to list of URLs/params (e.g. ~/bug-hunting/bbp/target/gau.txt)")

    pattern_choice = ask_menu(
        "Select pattern",
        {
            "1":("xss","xss"),
            "2":("sqli","sqli"),
            "3":("lfi","lfi"),
            "4":("ssrf","ssrf"),
            "5":("redirect","redirect"),
            "6":("ssti","ssti"),
        },
        multi=False,
        allow_blank=False
    )
    if pattern_choice is None:
        print(Fore.RED + "[!] invalid pattern choice")
        return

    # output under same bbp/<target>
    parent_dir = os.path.dirname(os.path.abspath(list_path))
    tclean     = sanitize_target_for_dir(os.path.basename(parent_dir))
    temp_dir   = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    out_file   = os.path.join(temp_dir, f"gf-{pattern_choice}.txt")
    shell_cmd  = f"cat {list_path} | gf {pattern_choice} | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(shell_cmd, shell=True)

def tool_dalfox():
    banner_section("DALFOX (XSS scanner)")

    mode_choice = ask_menu(
        "Mode?",
        {
            "1":("List mode (dalfox file <list>)","list"),
            "2":("Single URL (dalfox url <url>)","single"),
        },
        multi=False,
        allow_blank=False
    )

    skip_mining = ask("Skip mining? (--skip-mining-all) y/n", default="y").lower()
    conc        = ask("Concurrency (--worker)", default="30")

    payload_file = os.path.join(WL_BASE, "xss-payloadbox.txt")
    if not os.path.isfile(payload_file):
        payload_file = ask("Custom payload file for --custom-payload", default=payload_file)

    if mode_choice == "single":
        target_url = ask("Target URL for dalfox (e.g. https://site.com/vuln.php?x=FUZZ)")
        tclean     = sanitize_target_for_dir(target_url)
        temp_dir   = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file   = os.path.join(temp_dir, "dalfox.txt")

        base_cmd   = f"dalfox url '{target_url}' --custom-payload '{payload_file}' --worker {conc}"
    else:
        list_path  = ask("List file path for dalfox file mode")
        parent_dir = os.path.dirname(os.path.abspath(list_path))
        tclean     = sanitize_target_for_dir(os.path.basename(parent_dir))
        temp_dir   = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_file   = os.path.join(temp_dir, "dalfox.txt")

        base_cmd   = f"dalfox file '{list_path}' --custom-payload '{payload_file}' --worker {conc}"

    if skip_mining.startswith("y"):
        base_cmd += " --skip-mining-all"

    base_cmd += f" | tee {out_file}"

    print(Fore.CYAN + f"\n[+] Output -> {out_file}")
    run_cmd(base_cmd, shell=True)

def tool_xray():
    banner_section("XRAY WEBSCAN")

    # mode single or list
    mode_choice = ask_menu(
        "Scan mode",
        {
            "1":("Single URL (--url)","single"),
            "2":("Multi from file (--url-file)","list"),
        },
        multi=False,
        allow_blank=False
    )

    # pick plugins
    plugins = prompt_xray_plugins()  # [] => all

    # choose output dir
    if mode_choice == "single":
        url = ask("Target URL (https://target.com)")
        tclean   = sanitize_target_for_dir(url)
        temp_dir = os.path.join(BBP_BASE, tclean)
        ensure_dir(temp_dir)
        out_json = os.path.join(temp_dir, "xray.json")

        cmd = [
            XRAY_WRAPPER_BIN,
            "webscan",
            "--url", url,
            "--json-output", out_json
        ]
    else:
        auto_choice = ask("Use bbp/<target>/httpx.txt ? (enter target.com or blank for custom)", default="")
        if auto_choice.strip() != "":
            tclean   = sanitize_target_for_dir(auto_choice)
            temp_dir = os.path.join(BBP_BASE, tclean)
            ensure_dir(temp_dir)
            url_file = os.path.join(temp_dir, "httpx.txt")
        else:
            url_file = ask("Custom list file for --url-file")
            tclean   = sanitize_target_for_dir(os.path.basename(os.path.dirname(url_file)))
            temp_dir = os.path.join(BBP_BASE, tclean)
            ensure_dir(temp_dir)

        out_json = os.path.join(temp_dir, "xray.json")

        cmd = [
            XRAY_WRAPPER_BIN,
            "webscan",
            "--url-file", url_file,
            "--json-output", out_json
        ]

    if len(plugins) > 0:
        cmd += ["--plugins", ",".join(plugins)]

    print(Fore.CYAN + f"\n[+] Output -> {out_json}")
    run_cmd(cmd)

# ───────────────────────── FULL POWER ─────────────────────────
def run_fullpower():
    banner_section("FULL POWER")

    target = ask("Target root (example.com, NO https://)")
    speed  = ask("Threads (-t/-c for tools)", default="50")

    nuclei_sev = prompt_nuclei_severity()  # always ask severity

    tclean    = sanitize_target_for_dir(target)
    temp_dir  = os.path.join(BBP_BASE, tclean)
    final_dir = os.path.join(FULLPOWER_BASE, tclean)
    ensure_dir(temp_dir)
    ensure_dir(final_dir)

    subs_file    = os.path.join(temp_dir, "subs.txt")
    httpx_file   = os.path.join(temp_dir, "httpx.txt")
    nuclei_file  = os.path.join(final_dir, "fullpower.json")

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(Fore.MAGENTA + f"\n[ FULL POWER @ {ts} ]")
    print(Fore.MAGENTA + f"Target   : {target}")
    print(Fore.MAGENTA + f"Temp dir : {temp_dir}")
    print(Fore.MAGENTA + f"Final    : {nuclei_file}")
    print(Fore.YELLOW  + "\nChain: subfinder -> httpx -> nuclei\n")

    # 1 subfinder
    cmd_sub = [
        "subfinder",
        "-d", target,
        "-t", speed,
        "-silent",
        "-o", subs_file
    ]
    print(Fore.CYAN + "\n[1] subfinder -> subs.txt")
    run_cmd(cmd_sub)

    # 2 httpx
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

    # 3 nuclei (final json)
    nuclei_cmd = [
        "nuclei",
        "-l", httpx_file,
        "-c", speed,
        "-o", nuclei_file
    ]
    if len(nuclei_sev) > 0:
        nuclei_cmd += ["-severity", ",".join(nuclei_sev)]

    print(Fore.CYAN + "\n[3] nuclei -> fullpower.json")
    run_cmd(nuclei_cmd)

    # cleanup
    for f in [subs_file, httpx_file]:
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(Fore.YELLOW + f"[cleanup] removed {f}")
            except:
                print(Fore.RED + f"[!] failed to remove {f}")

    print(Fore.GREEN + "\n[✓] Full power finished.")
    print(Fore.GREEN + f"    Report -> {nuclei_file}\n")

# ───────────────────────── ATTACK FOCUS ─────────────────────────
def run_attack_focus():
    banner_section("ATTACK FOCUS")

    target   = ask("Target root (example.com)")
    bug_type = ask_menu(
        "Bug type?",
        {
            "1":("xss","xss"),
            "2":("sqli","sqli"),
            "3":("lfi","lfi"),
        },
        multi=False,
        allow_blank=False
    )
    if bug_type is None:
        print(Fore.RED + "[!] invalid bug type")
        return

    speed    = ask("Speed / threads (default 50)", default="50")

    # if bug_type -> lfi, we will final-step nuclei -> ask severity now
    nuclei_sev = []
    if bug_type == "lfi":
        nuclei_sev = prompt_nuclei_severity()

    tclean    = sanitize_target_for_dir(target)
    temp_dir  = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    final_dir = os.path.join(ATTACK_BASE, bug_type, tclean)
    ensure_dir(final_dir)

    gau_raw     = os.path.join(temp_dir, "gau_raw.txt")
    focus_raw   = os.path.join(temp_dir, "focus_raw.txt")     # gf filtered
    focus_alive = os.path.join(temp_dir, "focus_alive.txt")   # httpx 200 only
    result_file = os.path.join(final_dir, "result.json")      # final json or text dump

    print(Fore.YELLOW + "\nChain: gau -> gf(bugtype) -> httpx(200) -> exploit tool -> cleanup temp\n")

    # 1 gau
    shell_gau = f"gau --subs {target} | tee {gau_raw}"
    print(Fore.CYAN + "\n[1] gau -> gau_raw.txt")
    run_cmd(shell_gau, shell=True)

    # 2 gf
    shell_gf = f"cat {gau_raw} | gf {bug_type} | tee {focus_raw}"
    print(Fore.CYAN + "\n[2] gf({bug_type}) -> focus_raw.txt")
    run_cmd(shell_gf, shell=True)

    # 3 httpx
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

    # 4 exploit
    print(Fore.CYAN + "\n[4] exploit -> result.json")
    if bug_type == "xss":
        payload_file = os.path.join(WL_BASE, "xss-payloadbox.txt")
        shell_dalfox = (
            f"dalfox file {focus_alive} "
            f"--custom-payload {payload_file} "
            f"--worker {speed} "
            f"--skip-mining-all "
            f"| tee {result_file}"
        )
        run_cmd(shell_dalfox, shell=True)

    elif bug_type == "sqli":
        shell_sqlmap = (
            "while read -r url; do "
            "echo '[*] Testing SQLi:' \"$url\"; "
            "sqlmap -u \"$url\" --batch --level=1 --risk=1 --random-agent --smart --flush-session; "
            "done < " + focus_alive + " | tee " + result_file
        )
        run_cmd(shell_sqlmap, shell=True)

    elif bug_type == "lfi":
        nuclei_cmd = [
            "nuclei",
            "-l", focus_alive,
            "-c", speed,
            "-o", result_file
        ]
        if len(nuclei_sev) > 0:
            nuclei_cmd += ["-severity", ",".join(nuclei_sev)]
        run_cmd(nuclei_cmd)

    # 5 cleanup temp
    for f in [gau_raw, focus_raw, focus_alive]:
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(Fore.YELLOW + f"[cleanup] removed {f}")
            except:
                print(Fore.RED + f"[!] failed to remove {f}")

    print(Fore.GREEN + "\n[✓] Attack focus finished.")
    print(Fore.GREEN + f"    Final report -> {result_file}\n")

# ───────────────────────── CUSTOM CHAIN ─────────────────────────
def run_custom_chain():
    banner_section("CUSTOM CHAIN")

    # 1. ask target
    target = ask("Target root (example.com, NO https://)")
    speed  = ask("Speed / threads (-t/-c/etc)", default="50")

    # 2. ask tool order (multi in order)
    #   subfinder -> subs.txt
    #   gau       -> gau.txt
    #   httpx     -> httpx.txt (from last list)
    #   nuclei    -> final.json (ask severity)
    #   xray      -> final.json (ask plugins)
    tool_map = {
        "1":("subfinder","subfinder"),
        "2":("gau","gau"),
        "3":("httpx","httpx"),
        "4":("nuclei","nuclei"),
        "5":("xray","xray"),
    }
    print(Fore.CYAN + "Tools:")
    chain_list = ask_menu("Enter tool order (e.g. 1,2,3)", tool_map, multi=True, allow_blank=False)
    if not chain_list:
        print(Fore.RED + "[!] no tools selected")
        return

    # figure out which final step is last (for json)
    tclean      = sanitize_target_for_dir(target)
    temp_dir    = os.path.join(BBP_BASE, tclean)
    ensure_dir(temp_dir)

    custom_dir  = os.path.join(CUSTOM_BASE, tclean)
    ensure_dir(custom_dir)

    final_json  = os.path.join(custom_dir, f"{tclean}.json")

    subs_file   = os.path.join(temp_dir, "subs.txt")
    gau_file    = os.path.join(temp_dir, "gau.txt")
    httpx_file  = os.path.join(temp_dir, "httpx.txt")

    # pre-ask nuclei severity if nuclei is in chain
    nuclei_sev = []
    if "nuclei" in chain_list:
        nuclei_sev = prompt_nuclei_severity()

    # pre-ask xray plugins if xray in chain
    xray_plugs = []
    if "xray" in chain_list:
        xray_plugs = prompt_xray_plugins()

    # run chain sequentially
    last_list_for_httpx = None  # store path of last URL list to feed into httpx/nuclei/xray
    # logic: after subfinder -> use subs.txt
    # after gau -> use gau.txt
    # after httpx -> use httpx.txt

    for step in chain_list:
        if step == "subfinder":
            cmd = [
                "subfinder",
                "-d", target,
                "-t", speed,
                "-silent",
                "-o", subs_file
            ]
            print(Fore.CYAN + "\n[chain] subfinder -> subs.txt")
            run_cmd(cmd)
            last_list_for_httpx = subs_file

        elif step == "gau":
            cmd = f"cat {subs_file} | tee {gau_file}"
            print(Fore.CYAN + "\n[chain] gau -> gau.txt")
            run_cmd(cmd, shell=True)
            last_list_for_httpx = gau_file

        elif step == "httpx":
            if not last_list_for_httpx or not os.path.isfile(last_list_for_httpx):
                print(Fore.RED + "[!] httpx has no input list. Skipping httpx.")
                continue
            cmd = [
                "httpx",
                "-l", last_list_for_httpx,
                "-mc", "200",
                "-t", speed,
                "-silent",
                "-o", httpx_file,
            ]
            print(Fore.CYAN + "\n[chain] httpx -> httpx.txt")
            run_cmd(cmd)
            last_list_for_httpx = httpx_file

        elif step == "nuclei":
            # pick best input: prefer httpx_file, else gau_file, else subs_file
            nuclei_input = None
            if os.path.isfile(httpx_file):
                nuclei_input = httpx_file
            elif os.path.isfile(gau_file):
                nuclei_input = gau_file
            elif os.path.isfile(subs_file):
                nuclei_input = subs_file

            if not nuclei_input:
                print(Fore.RED + "[!] nuclei has no input list. Skipping nuclei.")
                continue

            nuclei_cmd = [
                "nuclei",
                "-l", nuclei_input,
                "-c", speed,
                "-o", final_json
            ]
            if len(nuclei_sev) > 0:
                nuclei_cmd += ["-severity", ",".join(nuclei_sev)]

            print(Fore.CYAN + "\n[chain] nuclei -> final json")
            run_cmd(nuclei_cmd)

        elif step == "xray":
            # pick best input for xray: prefer httpx_file else gau_file
            xray_input = None
            if os.path.isfile(httpx_file):
                xray_input = httpx_file
            elif os.path.isfile(gau_file):
                xray_input = gau_file

            if not xray_input:
                print(Fore.RED + "[!] xray has no input list (need URLs with scheme). Skipping xray.")
                continue

            base_xray_cmd = [
                XRAY_WRAPPER_BIN,
                "webscan",
                "--url-file", xray_input,
                "--json-output", final_json
            ]
            if len(xray_plugs) > 0:
                base_xray_cmd += ["--plugins", ",".join(xray_plugs)]

            print(Fore.CYAN + "\n[chain] xray -> final json")
            run_cmd(base_xray_cmd)

    # cleanup all temp .txt we generated (except final_json)
    cleanup_list = [subs_file, gau_file, httpx_file]
    for f in cleanup_list:
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(Fore.YELLOW + f"[cleanup] removed {f}")
            except:
                print(Fore.RED + f"[!] failed to remove {f}")

    print(Fore.GREEN + "\n[✓] Custom chain finished.")
    print(Fore.GREEN + f"    Final report -> {final_json}\n")

# ───────────────────────── MENUS ─────────────────────────
def recon_menu():
    while True:
        os.system("clear")
        banner_section("RECON / DISCOVERY")
        print(Fore.CYAN + "[1] subfinder")
        print(Fore.CYAN + "[2] httpx")
        print(Fore.CYAN + "[3] gau")
        print(Fore.CYAN + "[4] nuclei")
        print(Fore.CYAN + "[5] hakrawler")
        print(Fore.CYAN + "[6] ffuf")
        print(Fore.CYAN + "[7] gf")
        print(Fore.CYAN + "[8] dalfox")
        print(Fore.CYAN + "[9] xray")
        print(Fore.CYAN + "[0] back\n")

        choice = ask("pilih menu", default="0")
        if choice == "1":
            tool_subfinder()
        elif choice == "2":
            tool_httpx()
        elif choice == "3":
            tool_gau()
        elif choice == "4":
            tool_nuclei()
        elif choice == "5":
            tool_hakrawler()
        elif choice == "6":
            tool_ffuf()
        elif choice == "7":
            tool_gf()
        elif choice == "8":
            tool_dalfox()
        elif choice == "9":
            tool_xray()
        elif choice == "0":
            break
        else:
            print(Fore.RED + "invalid choice.")

        input(Fore.CYAN + "\n[press ENTER to continue]")

def main_menu():
    while True:
        os.system("clear")
        banner_main()
        print(Fore.CYAN + "[1] RECON / TOOLS MENU")
        print(Fore.CYAN + "[2] FULL POWER (subfinder -> httpx -> nuclei)")
        print(Fore.CYAN + "[3] ATTACK FOCUS (xss / sqli / lfi chain)")
        print(Fore.CYAN + "[4] CUSTOM CHAIN (build your own combo)")
        print(Fore.CYAN + "[5] XRAY STANDALONE")
        print(Fore.CYAN + "[0] EXIT\n")

        choice = ask("pilih menu", default="0")

        if choice == "1":
            recon_menu()
        elif choice == "2":
            run_fullpower()
            input(Fore.CYAN + "\n[press ENTER to continue]")
        elif choice == "3":
            run_attack_focus()
            input(Fore.CYAN + "\n[press ENTER to continue]")
        elif choice == "4":
            run_custom_chain()
            input(Fore.CYAN + "\n[press ENTER to continue]")
        elif choice == "5":
            tool_xray()
            input(Fore.CYAN + "\n[press ENTER to continue]")
        elif choice == "0":
            print(Fore.YELLOW + "bye hacker. stay legal. ✌")
            break
        else:
            print(Fore.RED + "invalid choice.")
            input(Fore.CYAN + "\n[press ENTER to continue]")

if __name__ == "__main__":
    main_menu()




#
