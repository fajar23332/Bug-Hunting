#!/usr/bin/env python3
# hunt.py - Interactive Bug Hunting CLI (single file)
# Author: generated for Dolvin (adapt & use responsibly)
# Requirements: Python 3.8+. External tools must be installed and in PATH.

import os
import sys
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

# -------------------- Styling --------------------
class S:
    B = "\033[1m"
    U = "\033[4m"
    R = "\033[31m"
    G = "\033[32m"
    Y = "\033[33m"
    C = "\033[36m"
    M = "\033[35m"
    RESET = "\033[0m"

def c(text, color=S.C):
    return f"{color}{text}{S.RESET}"

def banner():
    print(S.M + r"""
  ____             _   _                 _   _           _   _  __
 |  _ \  ___   ___| |_| |__   ___  _ __ | |_| |__   ___ | |_(_)/ _| ___
 | | | |/ _ \ / __| __| '_ \ / _ \| '_ \| __| '_ \ / _ \| __| | |_ / _ \
 | |_| | (_) | (__| |_| | | | (_) | | | | |_| | | | (_) | |_| |  _|  __/
 |____/ \___/ \___|\__|_| |_|\___/|_| |_|\__|_| |_|\___/ \__|_|_|  \___|
"""+S.RESET)
    print(S.B + "  🕵️  Hunt Toolkit — interactive CLI (outputs -> ~/bug-hunting/bbp/<target>/)\n" + S.RESET)

# -------------------- Paths & utils --------------------
HOME = str(Path.home())
OUTPUT_ROOT = os.path.join(HOME, "bug-hunting", "bbp")
WORDLIST_ROOT = os.path.join(HOME, "Bug-Hunting", "wordlist")

def expand(p): return os.path.abspath(os.path.expanduser(p)) if p else p
def ensure_dir(p): os.makedirs(expand(p), exist_ok=True); return expand(p)
def now_ts(): return datetime.now().strftime("%Y%m%dT%H%M%S")
def backup_if_exists(path):
    path = expand(path)
    if os.path.exists(path):
        bak = f"{path}.bak-{now_ts()}"
        shutil.move(path, bak)
        return bak
    return None
def which(binname): return shutil.which(binname)

def run_list(cmd, cwd=None):
    # cmd: list
    print(c("[RUN] " + " ".join(cmd), S.Y))
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=cwd)
        rc = proc.returncode
    except FileNotFoundError as e:
        print(c(f"[ERR] command not found: {e}", S.R))
        return 127
    elapsed = time.time() - t0
    print(c(f"[DONE] Exit={rc} ({elapsed:.1f}s)\n", S.G))
    return rc

def run_shell(cmd, cwd=None):
    print(c("[RUN-SH] " + cmd, S.Y))
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, shell=True, cwd=cwd)
        rc = proc.returncode
    except FileNotFoundError as e:
        print(c(f"[ERR] shell error: {e}", S.R))
        return 127
    elapsed = time.time() - t0
    print(c(f"[DONE] Exit={rc} ({elapsed:.1f}s)\n", S.G))
    return rc

def ask(prompt, default=None):
    if default is not None:
        r = input(c(f"{prompt} ", S.C) + f"[{default}] ")
        return r.strip() or default
    else:
        return input(c(f"{prompt} ", S.C)).strip()

def confirm(prompt, default=True):
    d = "Y/n" if default else "y/N"
    r = input(c(f"{prompt} ({d}) ", S.C)).strip().lower()
    if r == "":
        return default
    return r[0] == "y"

def infer_target_from_path(path):
    path = expand(path)
    parts = Path(path).parts
    # find first element that looks like domain (contains dot)
    for p in reversed(parts):
        if "." in p and len(p) > 3:
            return p
    return None

# -------------------- Menus: tool wrappers --------------------

def subfinder_menu():
    print(S.B + "\n== Subfinder (subdomain enumeration) ==" + S.RESET)
    target = ask("Masukkan target domain (contoh example.com)")
    if not target:
        print("Cancel")
        return
    target = target.replace("http://", "").replace("https://", "").strip("/ ")
    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, target))
    outfile = os.path.join(outdir, "subs.txt")
    threads = ask("Threads", "50")
    if not which("subfinder"):
        print(c("subfinder not found in PATH. Install via `go install ...` or setup.sh", S.R)); return
    cmd = ["subfinder", "-d", target, "-all", "-t", str(threads), "-o", outfile]
    print(c("Preview: " + " ".join(cmd), S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_list(cmd)
        if os.path.exists(outfile):
            n = sum(1 for _ in open(outfile, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {outfile} ({n} lines)", S.G))

def httpx_menu():
    print(S.B + "\n== HTTPX (probe live hosts) ==" + S.RESET)
    inp = ask("Masukkan path list subdomain (mis. ~/bug-hunting/bbp/example.com/subs.txt)")
    inp = expand(inp)
    if not os.path.exists(inp):
        print(c("File not found.", S.R)); return

    # infer target name from the parent folder (not from file name)
    parent_dir = os.path.dirname(inp)             # e.g. /root/bug-hunting/bbp/contentsquare.com
    target = os.path.basename(parent_dir)         # e.g. contentsquare.com
    if not target or target == "" or target == ".":
        # fallback: try to infer from filename
        target = infer_target_from_path(inp) or Path(inp).stem

    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, target))   # ~/bug-hunting/bbp/<target>/
    outfile = os.path.join(outdir, "httpx.txt")              # ~/.../<target>/httpx.txt

    threads = ask("Threads", "50")
    mc = ask("Match codes -mc (contoh: 200,301,302)", "200")
    silent = confirm("Gunakan -silent? (recommended)", True)

    if not which("httpx"):
        print(c("httpx not found in PATH.", S.R)); return

    # build command as list for clarity
    cmd = ["httpx", "-l", inp, "-mc", mc, "-t", str(threads), "-o", outfile]
    if silent:
        # httpx flag is '-silent' (a positional flag), include it
        cmd.insert(-2, "-silent")  # put before '-o' arg

    print(c("Preview: " + " ".join(cmd), S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_list(cmd)
        if os.path.exists(outfile):
            n = sum(1 for _ in open(outfile, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {outfile} ({n} lines)", S.G))
            
def gau_menu():
    print(S.B + "\n== GAU (getallurls) ==" + S.RESET)
    target = ask("Masukkan target domain (contoh example.com)")
    if not target:
        return
    target = target.replace("http://","").replace("https://","").strip("/ ")
    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, target))
    outfile = os.path.join(outdir, "gau.txt")
    threads = ask("Threads", "50")
    blacklist = ask("Blacklist ekstensi (contoh .png,.jpg) (enter=none)", "")
    if not which("gau"):
        print(c("gau not found in PATH.", S.R)); return
    # build shell command
    cmd = f"gau --threads {threads} "
    if blacklist:
        # double-quote blacklist to be safe
        cmd += f"--blacklist \"{blacklist}\" "
    cmd += f"{target} > \"{outfile}\""
    print(c("Preview: " + cmd, S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_shell(cmd)
        if os.path.exists(outfile):
            n = sum(1 for _ in open(outfile, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {outfile} ({n} lines)", S.G))

def wayback_menu():
    print(S.B + "\n== waybackurls ==" + S.RESET)
    target = ask("Masukkan target domain (contoh example.com)")
    if not target: return
    target = target.replace("http://","").replace("https://","").strip("/ ")
    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, target))
    outfile = os.path.join(outdir, "waybackurls.txt")
    if not which("waybackurls"):
        print(c("waybackurls not found in PATH.", S.R)); return
    cmd = f"echo {target} | waybackurls > \"{outfile}\""
    print(c("Preview: " + cmd, S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_shell(cmd)
        if os.path.exists(outfile):
            n = sum(1 for _ in open(outfile, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {outfile} ({n} lines)", S.G))

def hakrawler_menu():
    print(S.B + "\n== Hakrawler (endpoint crawler) ==" + S.RESET)
    target = ask("Masukkan target URL (contoh https://example.com)")
    if not target:
        return

    # auto tambahkan https:// kalau belum ada
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, infer_target_from_path(target) or Path(target).name))
    outfile = os.path.join(outdir, "hakrawler.txt")

    # opsi tambahan
    depth = ask("Depth (-d) [default 2]", "2")
    include_subs = confirm("Gunakan opsi -subs (ikut subdomain)?", False)
    threads = ask("Threads (default 10)", "10")

    if not which("hakrawler"):
        print(c("hakrawler not found in PATH. Install via 'go install github.com/hakluke/hakrawler@latest'", S.R))
        return

    # susun perintah
    cmd = f"echo {target} | hakrawler -d {depth} -t {threads}"
    if include_subs:
        cmd += " -subs"
    cmd += f" > \"{outfile}\""

    print(c("Preview: " + cmd, S.Y))

    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_shell(cmd)
        if os.path.exists(outfile):
            n = sum(1 for _ in open(outfile, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {outfile} ({n} URLs ditemukan)", S.G))
        else:
            print(c("[!] Tidak ada hasil ditemukan, periksa domain atau opsi -subs", S.Y))
def assetfinder_menu():
    print(S.B + "\n== assetfinder ==" + S.RESET)
    target = ask("Masukkan target domain (contoh example.com)")
    if not target: return
    target = target.replace("http://","").replace("https://","").strip("/ ")
    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, target))
    outfile = os.path.join(outdir, "assetfinder.txt")
    if not which("assetfinder"):
        print(c("assetfinder not found in PATH.", S.R)); return
    cmd = f"assetfinder {target} | tee \"{outfile}\""
    print(c("Preview: " + cmd, S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_shell(cmd)
        if os.path.exists(outfile):
            n = sum(1 for _ in open(outfile, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {outfile} ({n} lines)", S.G))

def combine_endpoints_menu():
    print(S.B + "\n== Combine endpoints (gau + wayback + hakrawler) ==" + S.RESET)
    path = ask("Masukkan target/parent folder path (contoh ~/bug-hunting/bbp/example.com) [enter=auto target prompt]", "")
    if not path:
        target = ask("Masukkan target domain (example.com)")
        path = os.path.join(OUTPUT_ROOT, target)
    path = expand(path)
    if not os.path.isdir(path):
        print(c("Folder not found.", S.R)); return
    out = os.path.join(path, "endpoints.txt")
    sources = []
    for name in ("gau.txt", "waybackurls.txt", "hakrawler.txt", "gf_xss.txt", "httpx.txt"):
        p = os.path.join(path, name)
        if os.path.exists(p):
            sources.append(p)
    if not sources:
        print(c("No source files found to combine (gau/wayback/hakrawler ...)", S.Y)); return
    cmd = "cat " + " ".join(f"\"{s}\"" for s in sources) + f" | sort -u > \"{out}\""
    print(c("Preview: " + cmd, S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(out)
        run_shell(cmd)
        if os.path.exists(out):
            n = sum(1 for _ in open(out, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {out} ({n} unique endpoints)", S.G))

def gf_menu():
    print(S.B + "\n== GF pattern filtering ==" + S.RESET)
    inp = ask("Masukkan path file list (mis ~/bug-hunting/bbp/example.com/gau.txt)")
    inp = expand(inp)
    if not os.path.exists(inp):
        print(c("File not found.", S.R)); return
    gf_dir = expand("~/.gf")
    patterns = []
    if os.path.isdir(gf_dir):
        patterns = [p.stem for p in Path(gf_dir).glob("*.json")]
    if patterns:
        print(c("Available patterns: " + ", ".join(patterns[:30]), S.Y))
    else:
        print(c("Warning: ~/.gf patterns not found. You can still type a pattern name (e.g. xss).", S.Y))
    pattern = ask("Pilih pattern (contoh: xss)")
    target = infer_target_from_path(inp) or Path(inp).parent.name
    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, target))
    out = os.path.join(outdir, f"gf_{pattern}.txt")
    if not which("gf"):
        print(c("gf binary not found in PATH.", S.R)); return
    cmd = f"cat \"{inp}\" | gf {pattern} > \"{out}\""
    print(c("Preview: " + cmd, S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(out)
        run_shell(cmd)
        if os.path.exists(out):
            n = sum(1 for _ in open(out, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {out} ({n} lines)", S.G))

def nuclei_menu():
    print(S.B + "\n== Nuclei scanner ==" + S.RESET)
    mode = ask("Mode: 1) single target  2) list file", "2")
    if mode.strip() == "1":
        target = ask("Masukkan target (https://example.com)")
        if not target: return
        target = target.strip()
        input_flag = "-u"
        input_val = target
        outdir = ensure_dir(os.path.join(OUTPUT_ROOT, infer_target_from_path(target) or Path(target).name))
    else:
        fp = ask("Masukkan path list file (contoh ~/bug-hunting/bbp/example.com/httpx.txt)")
        fp = expand(fp)
        if not os.path.exists(fp):
            print(c("File not found.", S.R)); return
        input_flag = "-l"
        input_val = fp
        outdir = ensure_dir(os.path.join(OUTPUT_ROOT, infer_target_from_path(fp) or Path(fp).parent.name))

    outfile = os.path.join(outdir, "nuclei_results.txt")
    severity = ask("Severity (comma separated, enter = ALL severities)", "")
    concurrency = ask("Concurrency -c (default 50)", "50")
    update = confirm("Update nuclei-templates before scan? (takes time)", False)
    if not which("nuclei"):
        print(c("nuclei not found in PATH.", S.R)); return
    if update:
        run_list(["nuclei", "-update-templates"])

    # build base cmd (no -json)
    cmd = ["nuclei", input_flag, input_val, "-c", concurrency, "-o", outfile]

    # only add -severity if user provided a non-empty value
    if severity.strip():
        cmd += ["-severity", severity]

    print(c("Preview: " + " ".join(cmd), S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_list(cmd)
        if os.path.exists(outfile):
            size = os.path.getsize(outfile)
            print(c(f"[OK] Saved -> {outfile} (size: {size} bytes)", S.G))
def ffuf_menu():
    print(S.B + "\n== FFUF (fuzzing) ==" + S.RESET)

    # ensure wordlist dir exists; if not, suggest to run setup
    wl_root = expand(WORDLIST_ROOT)
    sec_root = expand(os.path.join(HOME, "Seclists", "SecLists-master"))
    wl_entries = []
    if os.path.isdir(wl_root):
        wl_entries = sorted([p for p in os.listdir(wl_root) if p.endswith(".txt")])
    else:
        print(c(f"Wordlist dir {wl_root} tidak ditemukan. Kalau belum, jalankan setup.sh dulu.", S.Y))

    # If there are no local wordlists but SecLists is cloned, offer to copy/choose from it
    sec_entries = []
    if not wl_entries and os.path.isdir(sec_root):
        # provide a few sensible defaults (web-content, raft, xss lists)
        candidates = [
            "Discovery/Web-Content/raft-large-directories.txt",
            "Discovery/Web-Content/raft-medium-directories.txt",
            "Discovery/Web-Content/combined_directories.txt",
            "Fuzzing/big-list-of-naughty-strings.txt",
            "Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt",
            "Fuzzing/XSS/human-friendly/XSS-payloadbox.txt"
        ]
        for cpath in candidates:
            full = os.path.join(sec_root, cpath)
            if os.path.exists(full):
                sec_entries.append(full)

    # target: user provides FULL URL containing FUZZ (we don't auto change it)
    target_u = ask("Masukkan target FULL (harus mengandung 'FUZZ', contoh: https://example.com/FUZZ)")
    if not target_u:
        print(c("Cancelled.", S.Y)); return
    if "FUZZ" not in target_u:
        if not confirm("Target tidak mengandung 'FUZZ'. Lanjutkan? (tidak disarankan)", False):
            return

    # choose wordlist source
    print()
    if wl_entries:
        print(c("Wordlists lokal (~/Bug-Hunting/wordlist):", S.Y))
        for i, name in enumerate(wl_entries[:200], 1):
            print(f"  {i}) {name}")
        print(f"  {len(wl_entries)+1}) custom path")
        choose = ask("Pilih nomor wordlist dari daftar atau ketik 'custom' untuk path sendiri", "1")
        if choose == "custom" or (choose.isdigit() and int(choose) == len(wl_entries)+1):
            wl = expand(ask("Masukkan path lengkap ke wordlist (.txt)"))
            if not os.path.exists(wl):
                print(c("Wordlist custom tidak ditemukan: " + wl, S.R)); return
        else:
            # mapped by index
            try:
                idx = int(choose) - 1
                name = wl_entries[idx]
                wl = os.path.join(wl_root, name)
            except Exception as e:
                print(c("Pilihan invalid.", S.R)); return
    elif sec_entries:
        print(c("Tidak ada wordlist lokal, tapi SecLists terdeteksi. Pilih salah satu:", S.Y))
        for i, fp in enumerate(sec_entries, 1):
            print(f"  {i}) {fp}")
        print(f"  {len(sec_entries)+1}) custom path")
        choose = ask("Pilih nomor (atau 'custom')", "1")
        if choose == "custom" or (choose.isdigit() and int(choose) == len(sec_entries)+1):
            wl = expand(ask("Masukkan path lengkap ke wordlist (.txt)"))
            if not os.path.exists(wl):
                print(c("Wordlist custom tidak ditemukan: " + wl, S.R)); return
        else:
            try:
                idx = int(choose) - 1
                wl = sec_entries[idx]
            except Exception:
                print(c("Pilihan invalid.", S.R)); return
    else:
        # no lists at all
        if confirm("Tidak ditemukan wordlist lokal atau SecLists. Mau masukkan path wordlist manual?", True):
            wl = expand(ask("Masukkan path lengkap ke wordlist (.txt)"))
            if not os.path.exists(wl):
                print(c("Wordlist custom tidak ditemukan: " + wl, S.R)); return
        else:
            print(c("Batal. Jalankan setup.sh untuk clone SecLists dan menaruh wordlist lokal.", S.Y))
            return

    # output & options
    out_default_dir = expand(os.path.join(OUTPUT_ROOT, infer_target_from_path(target_u) or "ffuf"))
    ensure_dir(out_default_dir)
    outfile = ask("Nama file output (path atau nama file akan disimpan di folder target)", os.path.join(out_default_dir, "ffuf_result.txt"))
    outfile = expand(outfile)
    threads = ask("Threads (-t)", "20")
    mc = ask("Match codes -mc (contoh: 200,301,302)", "200,301,302")
    extra = ask("Extra ffuf flags (kosong = default '-c -v -r')", "-c -v -r")

    if not which("ffuf"):
        print(c("ffuf not found in PATH.", S.R)); return

    # Build command: use target exactly as user provided for -u
    cmd = f"ffuf -w \"{wl}\" -u '{target_u}' -t {threads} -mc {mc} {extra} -o \"{outfile}\""

    print(c("\nPreview: " + cmd, S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        rc = run_shell(cmd)
        if os.path.exists(outfile):
            size = os.path.getsize(outfile)
            print(c(f"[OK] Saved -> {outfile} (bytes: {size})", S.G))
        else:
            if rc != 0:
                print(c("[!] ffuf exited with non-zero status; cek pesan di atas.", S.R))
            else:
                print(c("[!] ffuf selesai tapi output file tidak ditemukan. Cek opsi -o atau permission.", S.Y))
                
def dalfox_menu():
    print(S.B + "\n== Dalfox (XSS) ==" + S.RESET)
    mode = ask("Mode: 1) url  2) file", "2")
    if mode.strip() == "1":
        target = ask("Masukkan URL (contoh: https://example.com/?q=test)")
        if not target: return
        input_flag = "url"
        input_val = f"\"{target}\""
        target_name = infer_target_from_path(target) or Path(target).hostname if hasattr(Path(target), "hostname") else Path(target).name
    else:
        fp = expand(ask("Masukkan path file (contoh ~/bug-hunting/bbp/example.com/endpoints.txt)"))
        if not os.path.exists(fp):
            print(c("File not found.", S.R)); return
        input_flag = "file"
        input_val = fp
        target_name = infer_target_from_path(fp) or Path(fp).parent.name
    payload_default = os.path.join(WORDLIST_ROOT, "xss.txt")
    use_def = confirm(f"Pakai --custom-payload default {payload_default} ?", True)
    if use_def:
        payload = payload_default
    else:
        payload = expand(ask("Masukkan path payload file"))
        if not os.path.exists(payload):
            print(c("Payload file not found.", S.R)); return
    skip_mining = confirm("Skip mining (--skip-mining-all)? (recommended)", True)
    speed = ask("Kecepatan: 1) Chill (-w10) 2) Balanced (-w30) 3) Turbo (-w60)  (default 2)", "2")
    wmap = {"1":"10","2":"30","3":"60"}
    workers = wmap.get(speed, speed)
    outdir = ensure_dir(os.path.join(OUTPUT_ROOT, target_name))
    outfile = os.path.join(outdir, "dalfox.txt")
    if not which("dalfox"):
        print(c("dalfox not found in PATH.", S.R)); return
    cmd = f"dalfox {input_flag} {input_val} --custom-payload {payload} -w {workers} -o \"{outfile}\""
    if skip_mining:
        cmd += " --skip-mining-all"
    print(c("Preview: " + cmd, S.Y))
    if confirm("Jalankan sekarang?", True):
        backup_if_exists(outfile)
        run_shell(cmd)
        if os.path.exists(outfile):
            n = sum(1 for _ in open(outfile, "r", errors="ignore"))
            print(c(f"[OK] Saved -> {outfile} ({n} lines)", S.G))

def check_env_menu():
    print(S.B + "\n== Environment check ==" + S.RESET)
    bins = ["subfinder","httpx","gau","ffuf","dalfox","nuclei","gf","waybackurls","hakrawler","assetfinder","dnsx"]
    missing = []
    for b in bins:
        if not which(b):
            missing.append(b)
    if not missing:
        print(c("All required binaries appear to be in PATH. Good.", S.G))
    else:
        print(c("Missing tools (install these):", S.Y), ", ".join(missing))
        print(c("Example go install (subfinder/httpx/gau):", S.C))
        print("GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("GO111MODULE=on go install github.com/hahwul/dalfox/v2@latest")
        print("...")

# -------------------- Main menu --------------------
def main_menu():
    while True:
        os.system("clear")
        banner()
        print(S.B + "Main menu:" + S.RESET)
        print(c("[1]", S.Y), "Subfinder          - subdomain enumeration")
        print(c("[2]", S.Y), "HTTPX              - probe live hosts")
        print(c("[3]", S.Y), "GAU                - getallurls (ask target)")
        print(c("[4]", S.Y), "waybackurls        - archive URLs")
        print(c("[5]", S.Y), "hakrawler          - quick crawler")
        print(c("[6]", S.Y), "assetfinder        - asset enumeration")
        print(c("[7]", S.Y), "Combine endpoints  - merge outputs")
        print(c("[8]", S.Y), "GF                 - pattern filtering")
        print(c("[9]", S.Y), "Nuclei             - template scanner")
        print(c("[10]", S.Y), "FFUF               - directory/param fuzzing")
        print(c("[11]", S.Y), "Dalfox             - XSS automation")
        print(c("[12]", S.Y), "Check environment  - missing binaries")
        print(c("[0]", S.R),  "Exit")
        choice = ask("Pilih nomor")
        if choice == "1": subfinder_menu()
        elif choice == "2": httpx_menu()
        elif choice == "3": gau_menu()
        elif choice == "4": wayback_menu()
        elif choice == "5": hakrawler_menu()
        elif choice == "6": assetfinder_menu()
        elif choice == "7": combine_endpoints_menu()
        elif choice == "8": gf_menu()
        elif choice == "9": nuclei_menu()
        elif choice == "10": ffuf_menu()
        elif choice == "11": dalfox_menu()
        elif choice == "12": check_env_menu()
        elif choice == "0": 
            print(c("Bye 👋", S.C))
            sys.exit(0)
        else:
            print(c("Pilihan tidak dikenali.", S.R))
        input(c("\nTekan Enter untuk kembali ke menu..."))

# -------------------- Entrypoint --------------------
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n" + c("Interrupted. Bye.", S.R))
        sys.exit(0)
