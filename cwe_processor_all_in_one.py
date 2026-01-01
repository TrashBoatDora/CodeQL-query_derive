#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CodeQL CWE Batch Processor - All-in-One Version
整合了 interactive_runner.py, batch_process_cwe.py, rm_project_call_function.py 的功能
"""

import os
import sys
import subprocess
from pathlib import Path
import glob
import re
import hashlib
import json
import shutil
import csv
import datetime
import logging
import argparse
from typing import List, Tuple, Dict
from collections import defaultdict

# ==================== ANSI Colors ====================
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"
RESET = "\033[0m"

# ==================== 設定參數區域 ====================
ABOVE_LINES = 0
BELOW_LINES = 0
MODE = "call"
CWES = ["327"]

# ==================== 常數定義 ====================
FN, FS, FE, CSL, CSC, CEL, CEC, BBSL, BBSC, BBEL, BBEC = range(11)

# ==================== 日誌系統 ====================
logger = None

def print_colored(text, color="white"):
    """簡單的顏色輸出函數，同時記錄到日誌"""
    colors = {
        "red": RED,
        "green": GREEN,
        "yellow": YELLOW,
        "blue": BLUE,
        "magenta": MAGENTA,
        "cyan": CYAN,
        "white": WHITE,
        "reset": RESET
    }
    formatted_text = f"{colors.get(color, colors['white'])}{text}{RESET}"
    print(formatted_text)
    
    if logger:
        clean_text = text
        if color == "red":
            logger.error(clean_text)
        elif color == "yellow":
            logger.warning(clean_text)
        elif color in ["green", "cyan"]:
            logger.info(clean_text)
        else:
            logger.info(clean_text)

# ==================== 工具函數 ====================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_input(prompt, default=None):
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()

def fs_safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)

def normalize_cwes(cwes):
    if not cwes:
        return []
    out = set()
    for s in cwes:
        digits = re.sub(r"(?i)cwe[-_\s]*|[^0-9]", "", s).lstrip("0") or "0"
        if len(digits) <= 3:
            digits = digits.zfill(3)
        out.add(digits)
    return sorted(out)

def normalize_callees(callees):
    if not callees:
        return []
    clean = []
    seen = set()
    for c in callees:
        c = c.strip()
        if not c:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$", c):
            continue
        if c not in seen:
            seen.add(c)
            clean.append(c)
    return sorted(clean)

# ==================== 互動式選單函數 ====================

def print_header():
    print(f"{CYAN}============================================{RESET}")
    print(f"{CYAN}   CodeQL CWE Batch Processor - All-in-One  {RESET}")
    print(f"{CYAN}============================================{RESET}")
    print()

def select_language():
    print(f"{YELLOW}1. Select Language{RESET}")
    languages = ["python", "cpp", "java", "go", "javascript"]
    
    available = []
    projects_root = Path("./projects")
    for lang in languages:
        if (projects_root / lang).exists():
            available.append(lang)
    
    if not available:
        print(f"{RED}No project directories found in ./projects/{RESET}")
        return None

    for i, lang in enumerate(available, 1):
        print(f"  {i}. {lang}")
    
    while True:
        choice = get_input("Choose language (number)", "1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(available):
                return available[idx]
        except ValueError:
            pass
        print(f"{RED}Invalid selection.{RESET}")

def select_cwes_interactive():
    print(f"\n{YELLOW}2. Select CWEs{RESET}")
    
    common_cwes = [
        "022", "078", "079", "095", "113", "117", 
        "326", "327", "329", "347", "377", "502", 
        "643", "760", "918", "943", "1333"
    ]
    
    print("Available CWEs:")
    for i in range(0, len(common_cwes), 6):
        chunk = common_cwes[i:i+6]
        print("  " + "  ".join(chunk))
        
    default_cwes = "327"
    print(f"\nEnter CWE IDs separated by space (e.g., '327 078 022')")
    cwes = get_input("CWEs", default_cwes)
    return cwes.split()

def select_mode():
    print(f"\n{YELLOW}3. Select Mode{RESET}")
    modes = ["call", "caller", "bb"]
    for i, mode in enumerate(modes, 1):
        print(f"  {i}. {mode}")
    
    while True:
        choice = get_input("Choose mode (number)", "1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(modes):
                return modes[idx]
        except ValueError:
            pass
        print(f"{RED}Invalid selection.{RESET}")

def select_lines():
    print(f"\n{YELLOW}4. Context Lines{RESET}")
    above = get_input("Lines to remove ABOVE", "0")
    below = get_input("Lines to remove BELOW", "0")
    return above, below

def select_first_only():
    """選擇是否只移除每個檔案的第一個函數"""
    print(f"\n{YELLOW}5. First Function Only{RESET}")
    print("  If enabled, only the first function per file will be removed.")
    choice = get_input("Only remove first function per file? (y/n)", "n")
    return choice.lower() == 'y'

def remove_gitignore_files(output_dir):
    """移除輸出目錄中所有的 .gitignore 檔案"""
    print(f"\n{YELLOW}Removing .gitignore files from output directory...{RESET}")
    
    gitignore_pattern = os.path.join(output_dir, "**", ".gitignore")
    gitignore_files = glob.glob(gitignore_pattern, recursive=True)
    
    removed_count = 0
    for gitignore_file in gitignore_files:
        try:
            os.remove(gitignore_file)
            removed_count += 1
            print(f"  {GREEN}✓{RESET} Removed: {gitignore_file}")
        except Exception as e:
            print(f"  {RED}✗{RESET} Failed to remove {gitignore_file}: {e}")
    
    if removed_count > 0:
        print(f"{GREEN}Successfully removed {removed_count} .gitignore file(s){RESET}")
    else:
        print(f"{YELLOW}No .gitignore files found in output directory{RESET}")
    
    return removed_count

# ==================== JSON 處理函數 ====================

def _norm_cwe_key_for_filter(s: str) -> str:
    digits = re.sub(r"(?i)cwe[-_\s]*|[^0-9]", "", s).lstrip("0") or "0"
    if len(digits) <= 3:
        digits = digits.zfill(3)
    return f"CWE-{digits}"

def _cwe_pass(cwe_key: str, filters):
    if not filters:
        return True
    norm_filters = {_norm_cwe_key_for_filter(x) for x in filters}
    return cwe_key in norm_filters

def _callee_pass(callee: str, filters):
    if not filters:
        return True
    return callee in set(filters)

def _strip_first_component(json_path: str) -> Path:
    parts = Path(json_path).parts
    rel = parts[1:] if len(parts) > 1 else parts
    return Path(*rel)

def _as_blocks(v):
    def _is_one(blk):
        if not isinstance(blk, list) or len(blk) != 11:
            return False
        fn_ok = (blk[FN] is None) or isinstance(blk[FN], str)
        ints_ok = all(isinstance(x, int) for x in blk[FS:])
        return fn_ok and ints_ok

    if isinstance(v, list) and v and _is_one(v):
        return [v]
    if isinstance(v, list) and v and all(_is_one(x) for x in v):
        return v
    return []

def _iter_entries(data):
    if not isinstance(data, dict):
        raise ValueError("JSON 頂層必須是物件(dict)")
    for cwe_key, callee_map in data.items():
        if not isinstance(callee_map, dict):
            raise ValueError(f"{cwe_key} 的值必須是物件(callee 映射)")
        for callee, file_map in callee_map.items():
            if not isinstance(file_map, dict):
                raise ValueError(f"{cwe_key}/{callee} 必須是物件(file 映射)")
            for file_path, blocks_v in file_map.items():
                for blk in _as_blocks(blocks_v):
                    yield (cwe_key, callee, file_path, blk)

def _iter_entries_strict(data):
    if not isinstance(data, dict):
        raise ValueError("JSON 頂層必須是物件(dict)")
    for cwe_key, callee_map in data.items():
        if not isinstance(callee_map, dict):
            raise ValueError(f"{cwe_key} 的值必須是物件(callee 映射)")
        for callee, file_map in callee_map.items():
            if not isinstance(file_map, dict):
                raise ValueError(f"{cwe_key}/{callee} 必須是物件(file 映射)")
            for file_path, blocks_v in file_map.items():
                for blk in _as_blocks(blocks_v):
                    yield (cwe_key, callee, file_path, blk)

# ==================== 檔案處理函數 ====================

def _split_eol(line: str) -> Tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    if line.endswith("\r"):
        return line[:-1], "\r"
    return line, ""

def _blank_region_in_lines(lines: List[str], sL: int, sC: int, eL: int, eC: int, full_lines: bool):
    n = len(lines)
    sL = max(1, min(sL, n))
    eL = max(1, min(eL, n))
    if (eL, eC) < (sL, sC):
        sL, sC, eL, eC = eL, eC, sL, sC

    if full_lines:
        for L in range(sL, eL + 1):
            content, eol = _split_eol(lines[L - 1])
            lines[L - 1] = eol
        return

    if sL == eL:
        content, eol = _split_eol(lines[sL - 1])
        start = max(0, sC - 1)
        end = max(start, min(len(content), eC))
        new_content = content[:start] + content[end:]
        lines[sL - 1] = new_content + eol
        return

    content, eol = _split_eol(lines[sL - 1])
    start = max(0, sC - 1)
    start = min(start, len(content))
    lines[sL - 1] = content[:start] + eol

    for L in range(sL + 1, eL):
        _, eol_m = _split_eol(lines[L - 1])
        lines[L - 1] = eol_m

    contentE, eolE = _split_eol(lines[eL - 1])
    end = max(0, min(len(contentE), eC))
    lines[eL - 1] = contentE[end:] + eolE

def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    ranges = list(ranges)
    ranges.sort()
    merged = [list(ranges[0])]
    for a, b in ranges[1:]:
        last = merged[-1]
        if a <= last[1] + 1:
            last[1] = max(last[1], b)
        else:
            merged.append([a, b])
    return [tuple(x) for x in merged]

def _dedupe_and_coalesce_regions(regions):
    uniq = []
    seen = set()
    for r in regions:
        key = (r[0], r[1], r[2], r[3], r[4])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    full_ranges = []
    partials = []
    for sL, sC, eL, eC, full in uniq:
        if full:
            full_ranges.append((sL, eL))
        else:
            partials.append((sL, sC, eL, eC))

    merged_full = _merge_ranges(full_ranges)

    def covered_by_full(sL, eL):
        for a, b in merged_full:
            if sL >= a and eL <= b:
                return True
        return False

    kept_partials = []
    seen_partials = set()
    for sL, sC, eL, eC in partials:
        if covered_by_full(sL, eL):
            continue
        k = (sL, sC, eL, eC)
        if k in seen_partials:
            continue
        seen_partials.add(k)
        kept_partials.append((sL, sC, eL, eC))

    out = []
    for a, b in merged_full:
        out.append((a, 1, b, 10**9, True))
    for sL, sC, eL, eC in kept_partials:
        out.append((sL, sC, eL, eC, False))
    out.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return out

def _merge_ranges_by_fn(ranges_with_fn):
    """合併同一個 functionName 的區段（相鄰或重疊）"""
    buckets = defaultdict(list)
    for s, e, fn in ranges_with_fn:
        buckets[fn].append((s, e))

    out = []
    for fn, rs in buckets.items():
        rs.sort()
        merged = [list(rs[0])]
        for a, b in rs[1:]:
            last = merged[-1]
            if a <= last[1] + 1:
                last[1] = max(last[1], b)
            else:
                merged.append([a, b])
        out.extend([(a, b, fn) for a, b in merged])

    out.sort(key=lambda x: (x[0], x[1], x[2] or ""))
    return out

# ==================== 核心處理函數 ====================

def remove_targets_and_report(
    cp_root: Path,
    json_file: Path,
    mode: str,
    above: int,
    below: int,
    cwe_filters,
    callee_filters,
    first_only: bool = False,
) -> Dict[str, List[Tuple[int, int, str]]]:
    cp_root = cp_root.expanduser().resolve()
    json_file = json_file.expanduser().resolve()

    with json_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    per_file_regions: Dict[Path, List[Tuple[int, int, int, int, bool]]] = {}
    per_file_line_ranges: Dict[Path, List[Tuple[int, int, str]]] = {}
    
    # 用於追蹤每個檔案已處理的第一個 function（當 first_only=True 時使用）
    per_file_first_fn: Dict[Path, str] = {}

    for cwe_key, callee, json_path, blk in _iter_entries_strict(data):
        if not _cwe_pass(cwe_key, cwe_filters):
            continue
        if not _callee_pass(callee, callee_filters):
            continue

        rel_path = _strip_first_component(json_path)
        abs_path = (cp_root / rel_path).resolve()

        fn, fs, fe, csl, csc, cel, cec, bbsl, bbsc, bbel, bbec = blk
        
        # 如果啟用 first_only 模式，只處理每個檔案的第一個 function
        if first_only:
            if abs_path in per_file_first_fn:
                # 該檔案已經有第一個 function 了
                existing_fn = per_file_first_fn[abs_path]
                if fn != existing_fn:
                    # 不同的 function，跳過
                    continue
            else:
                # 這是該檔案的第一個 function，記錄下來
                per_file_first_fn[abs_path] = fn

        if mode == "call":
            if above > 0 or below > 0:
                sL = max(fs, csl - max(0, above))
                eL = min(fe, cel + max(0, below))
                if sL > eL:
                    continue
                region = (sL, 1, eL, 10**9, True)
                line_range = (sL, eL, fn)
            else:
                region = (csl, 1, cel, 10**9, True)
                line_range = (csl, cel, fn)
        elif mode == "caller":
            region = (fs, 1, fe, 10**9, True)
            line_range = (fs, fe, fn)
        elif mode == "bb":
            region = (bbsl, bbsc, bbel, bbec, False)
            line_range = (bbsl, bbel, fn)
        else:
            continue

        per_file_regions.setdefault(abs_path, []).append(region)
        per_file_line_ranges.setdefault(abs_path, []).append(line_range)

    for fpath, regions in per_file_regions.items():
        if not fpath.exists():
            continue
        regions = _dedupe_and_coalesce_regions(regions)

        with fpath.open("r", encoding="utf-8", errors="ignore", newline="") as fr:
            lines = fr.readlines()

        for sL, sC, eL, eC, full_lines in regions:
            _blank_region_in_lines(lines, sL, sC, eL, eC, full_lines)

        with fpath.open("w", encoding="utf-8", newline="") as fw:
            fw.writelines(lines)

    report: Dict[str, List[Tuple[int, int, str]]] = {}
    for fpath, ranges in per_file_line_ranges.items():
        rel = fpath.resolve().relative_to(cp_root.resolve()).as_posix()
        merged = _merge_ranges_by_fn(ranges)
        report[rel] = [[s, e, fn] for (s, e, fn) in merged]

    out_path = cp_root / "removed_ranges.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[report] {out_path}")
    
    if mode == "call":
        prompt_lines: List[str] = []
        for rel, ranges in sorted(report.items(), key=lambda kv: kv[0]):
            fn_set = {fn for (_, _, fn) in ranges if fn}
            if not fn_set:
                continue
            fn_list = sorted(fn_set, key=lambda s: s.lower())
            fn_part = "、".join(f"{name}()" for name in fn_list)
            prompt_lines.append(f"{rel}|{fn_part}")

        prompt_path = cp_root / "prompt.txt"
        with prompt_path.open("w", encoding="utf-8") as pf:
            for line in prompt_lines:
                pf.write(line + "\n")
        print(f"[prompt] {prompt_path}")
    return report

def process_single_project(project_dir, project_name, json_file, output_base_dir, cwe, mode, above, below, first_only=False):
    """處理單一專案的單一 CWE"""
    p_root = Path(project_dir).expanduser().resolve()
    json_file_path = Path(json_file).expanduser().resolve()
    output_dir = Path(output_base_dir).expanduser().resolve()
    
    cwes = normalize_cwes([cwe])
    
    cwe_tag = f"CWE-{'+'.join(cwes)}" if cwes else "CWE-ALL"
    mode_tag = f"M-{mode}"
    raw_cp_name = f"{p_root.name}__{cwe_tag}__CAL-ALL__{mode_tag}"
    if len(raw_cp_name) > 120:
        suffix = hashlib.sha1(raw_cp_name.encode()).hexdigest()[:10]
        raw_cp_name = raw_cp_name[:100] + "__" + suffix
    
    output_dir.mkdir(parents=True, exist_ok=True)
    cp_root = output_dir / raw_cp_name
    
    def ignore_patterns(path, names):
        ignored = []
        for name in names:
            if name == '.git':
                ignored.append(name)
                continue
            full_path = os.path.join(path, name)
            if os.path.islink(full_path) and not os.path.exists(full_path):
                ignored.append(name)
        return ignored
    
    try:
        shutil.copytree(p_root, cp_root, dirs_exist_ok=True, ignore=ignore_patterns)
    except (shutil.Error, OSError, PermissionError) as e:
        print(f"複製過程中遇到錯誤: {e}")
        try:
            cp_root.mkdir(parents=True, exist_ok=True)
            for item in p_root.iterdir():
                if item.name == '.git':
                    continue
                src = str(item)
                dst = str(cp_root / item.name)
                try:
                    if item.is_file():
                        shutil.copy2(src, dst)
                    elif item.is_dir():
                        shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore_patterns)
                except (OSError, PermissionError, shutil.Error) as e2:
                    continue
        except Exception as e3:
            pass
    
    report = remove_targets_and_report(
        cp_root=cp_root,
        json_file=json_file_path,
        mode=mode,
        above=above,
        below=below,
        cwe_filters=cwes,
        callee_filters=None,
        first_only=first_only
    )
    
    return report

# ==================== 批次處理函數 ====================

def check_vulnerabilities_found(cwe_output_dir, project_name):
    """檢查是否確實發現了漏洞"""
    # 使用更精確的匹配：專案名稱必須在目錄名開頭，後面跟著 "__"
    project_dirs = [d for d in cwe_output_dir.iterdir() if d.is_dir() and d.name.startswith(f"{project_name}__")]
    
    if not project_dirs:
        return 0
    
    total_vulnerabilities = 0
    
    for project_dir in project_dirs:
        removed_ranges_file = project_dir / "removed_ranges.json"
        if removed_ranges_file.exists():
            try:
                with open(removed_ranges_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                non_empty_files = sum(1 for file_ranges in data.values() if file_ranges)
                total_vulnerabilities += non_empty_files
            except (json.JSONDecodeError, Exception):
                pass
        
        prompt_file = project_dir / "prompt.txt"
        if prompt_file.exists():
            try:
                content = prompt_file.read_text(encoding='utf-8').strip()
                if content:
                    total_vulnerabilities += len(content.splitlines())
            except Exception:
                pass
    
    return total_vulnerabilities

def cleanup_empty_output(cwe_output_dir, project_name):
    """清理沒有發現漏洞的專案輸出目錄"""
    # 使用更精確的匹配：專案名稱必須在目錄名開頭，後面跟著 "__"
    project_dirs = [d for d in cwe_output_dir.iterdir() if d.is_dir() and d.name.startswith(f"{project_name}__")]
    
    for project_dir in project_dirs:
        try:
            is_empty = True
            
            removed_ranges_file = project_dir / "removed_ranges.json"
            if removed_ranges_file.exists():
                try:
                    with open(removed_ranges_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    if any(file_ranges for file_ranges in data.values()):
                        is_empty = False
                except:
                    pass
            
            prompt_file = project_dir / "prompt.txt"
            if prompt_file.exists():
                try:
                    content = prompt_file.read_text(encoding='utf-8').strip()
                    if content:
                        is_empty = False
                except:
                    pass
            
            if is_empty:
                shutil.rmtree(project_dir, ignore_errors=True)
                
        except Exception:
            pass

def process_project_batch(project_dir, project_name, json_file, output_base_dir, cwes_list, mode, above, below, first_only=False):
    """處理單一專案的所有 CWE"""
    print_colored(f"處理專案: {project_name}", "yellow")
    
    if not json_file.exists():
        print_colored(f"  ⚠️  警告: 找不到 JSON 檔案: {json_file}", "yellow")
        print_colored("  ⏭️  跳過此專案", "yellow")
        return 0, len(cwes_list)
    
    successful_operations = 0
    total_operations = len(cwes_list)
    
    for cwe in cwes_list:
        print(f"  處理 CWE-{cwe} ...")
        
        cwe_output_dir = output_base_dir / f"CWE-{cwe}"
        cwe_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            process_single_project(
                project_dir=project_dir,
                project_name=project_name,
                json_file=json_file,
                output_base_dir=cwe_output_dir,
                cwe=cwe,
                mode=mode,
                above=above,
                below=below,
                first_only=first_only
            )
            
            has_vulnerabilities = check_vulnerabilities_found(cwe_output_dir, project_name)
            
            if has_vulnerabilities:
                print_colored(f"    ✅ CWE-{cwe} 處理成功 (發現 {has_vulnerabilities} 個漏洞)", "green")
                successful_operations += 1
            else:
                print_colored(f"    ℹ️  CWE-{cwe} 處理完成，但未發現漏洞，已清理空輸出", "yellow")
                cleanup_empty_output(cwe_output_dir, project_name)
                
        except Exception as e:
            print_colored(f"    ❌ CWE-{cwe} 處理失敗: {e}", "red")
    
    success_rate = (successful_operations / total_operations) * 100 if total_operations > 0 else 0
    print_colored(f"  📊 專案 {project_name} 完成: {successful_operations}/{total_operations} 個 CWE 處理成功 ({success_rate:.1f}%)", "cyan")
    print()
    
    return successful_operations, total_operations

def get_directory_stats(output_base_dir, cwes_list):
    """統計輸出目錄的結果"""
    print_colored("🗂️  輸出目錄結構:", "cyan")
    
    total_results = 0
    total_vulnerabilities = 0
    
    for cwe in cwes_list:
        cwe_dir = output_base_dir / f"CWE-{cwe}"
        if cwe_dir.exists():
            project_dirs = [d for d in cwe_dir.iterdir() if d.is_dir()]
            count = len(project_dirs)
            total_results += count
            
            cwe_vulnerabilities = 0
            for project_dir in project_dirs:
                removed_ranges_file = project_dir / "removed_ranges.json"
                if removed_ranges_file.exists():
                    try:
                        with open(removed_ranges_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        cwe_vulnerabilities += sum(1 for file_ranges in data.values() if file_ranges)
                    except:
                        pass
            
            total_vulnerabilities += cwe_vulnerabilities
            
            if count > 0:
                if cwe_vulnerabilities > 0:
                    print(f"  CWE-{cwe}/: {count} 個專案, {cwe_vulnerabilities} 個漏洞檔案")
                else:
                    print_colored(f"  CWE-{cwe}/: {count} 個專案, 但無有效漏洞", "yellow")
            else:
                print_colored(f"  CWE-{cwe}/: 0 個處理結果", "yellow")
        else:
            print_colored(f"  CWE-{cwe}/: 目錄不存在", "red")
    
    return total_results, total_vulnerabilities

def setup_logging(output_dir):
    """設置日誌系統"""
    global logger
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"batch_process_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
        ]
    )
    
    logger = logging.getLogger('batch_process')
    
    return logger, log_file

def count_vulnerabilities_from_json(json_file):
    """從 JSON 檔案統計各 CWE 的漏洞數量"""
    cwe_counts = {}
    
    if not json_file.exists():
        return cwe_counts
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        for cwe_key, cwe_data in data.items():
            if cwe_key.startswith('CWE-'):
                cwe_num = cwe_key.split('-')[1]
                
                count = 0
                if isinstance(cwe_data, dict):
                    for vuln_type, vuln_files in cwe_data.items():
                        if isinstance(vuln_files, dict):
                            for file_path, file_vulns in vuln_files.items():
                                if isinstance(file_vulns, list):
                                    count += len(file_vulns)
                
                cwe_counts[cwe_num] = count
        
    except Exception as e:
        print_colored(f"讀取 JSON 檔案失敗: {json_file} - {e}", "red")
    
    return cwe_counts

def generate_csv_report(projects_dir, json_dir, output_dir, cwes_list):
    """生成 CSV 統計報告"""
    csv_file = output_dir / "vulnerability_statistics.csv"
    
    headers = ['Project Name'] + [f'CWE-{cwe}' for cwe in cwes_list] + ['Total']
    
    project_stats = []
    project_dirs = [d for d in projects_dir.iterdir() if d.is_dir()]
    
    for project_dir in project_dirs:
        project_name = project_dir.name
        json_file = json_dir / project_name / f"{project_name}.json"
        
        cwe_counts = count_vulnerabilities_from_json(json_file)
        
        row = [project_name]
        total_count = 0
        
        for cwe in cwes_list:
            count = cwe_counts.get(cwe, 0)
            row.append(count)
            total_count += count
        
        row.append(total_count)
        project_stats.append(row)
    
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(project_stats)
        
        print_colored(f"✅ CSV 統計報告已生成: {csv_file}", "green")
        
        total_projects = len(project_stats)
        total_vulnerabilities = sum(row[-1] for row in project_stats)
        
        print_colored(f"📊 統計摘要: {total_projects} 個專案，總共 {total_vulnerabilities} 個漏洞", "cyan")
        
        return csv_file
        
    except Exception as e:
        print_colored(f"❌ 生成 CSV 報告失敗: {e}", "red")
        return None

# ==================== 主程式 ====================

def batch_process(projects_dir, json_dir, output_base_dir, language, cwes_list, mode, above, below, dry_run=False, first_only=False):
    """批次處理所有專案"""
    global logger
    
    projects_dir = Path(projects_dir).expanduser().resolve()
    json_dir = Path(json_dir).expanduser().resolve()
    output_base_dir = Path(output_base_dir).expanduser().resolve()
    
    print_colored("=== 批次處理 CWE 漏洞程式碼刪除 ===", "cyan")
    print(f"程式語言: {language}")
    print(f"向上刪除行數: {above}")
    print(f"向下刪除行數: {below}")
    print(f"處理模式: {mode}")
    print(f"只處理第一個函數: {'是' if first_only else '否'}")
    print(f"專案目錄: {projects_dir}")
    print(f"JSON 目錄: {json_dir}")
    print(f"輸出目錄: {output_base_dir}")
    if dry_run:
        print_colored("🔍 模擬運行模式 (不會實際執行)", "yellow")
    print_colored("=========================================", "cyan")
    
    if not projects_dir.exists():
        print_colored(f"❌ 錯誤: 找不到專案目錄 {projects_dir}", "red")
        return 1
    
    if not json_dir.exists():
        print_colored(f"❌ 錯誤: 找不到 JSON 目錄 {json_dir}", "red")
        return 1
    
    if not dry_run:
        output_base_dir.mkdir(parents=True, exist_ok=True)
        logger, log_file = setup_logging(output_base_dir)
        logger.info("=== 批次處理 CWE 漏洞程式碼刪除開始 ===")
        logger.info(f"程式語言: {language}")
        logger.info(f"向上刪除行數: {above}")
        logger.info(f"向下刪除行數: {below}")
        logger.info(f"處理模式: {mode}")
        logger.info(f"專案目錄: {projects_dir}")
        logger.info(f"JSON 目錄: {json_dir}")
        logger.info(f"輸出目錄: {output_base_dir}")
        logger.info(f"日誌檔案: {log_file}")
        print_colored(f"📝 日誌將保存到: {log_file}", "cyan")
    
    total_projects = 0
    processed_projects = 0
    total_operations = 0
    successful_operations = 0
    
    project_dirs = [d for d in projects_dir.iterdir() if d.is_dir()]
    total_projects = len(project_dirs)
    
    if total_projects == 0:
        print_colored("⚠️  警告: 在專案目錄中沒有找到任何子目錄", "yellow")
        return 0
    
    print(f"發現 {total_projects} 個專案")
    print()
    
    if dry_run:
        print_colored("將要處理的專案:", "cyan")
        for project_dir in project_dirs:
            project_name = project_dir.name
            json_file = json_dir / project_name / f"{project_name}.json"
            status = "✅" if json_file.exists() else "❌"
            print(f"  {status} {project_name} - JSON: {json_file}")
        print(f"\n總共 {len(cwes_list)} 個 CWE 類型")
        print(f"預計總操作數: {total_projects * len(cwes_list)}")
        return 0
    
    for project_dir in project_dirs:
        project_name = project_dir.name
        json_file = json_dir / project_name / f"{project_name}.json"
        
        processed_projects += 1
        
        success_count, op_count = process_project_batch(
            project_dir, project_name, json_file, output_base_dir, cwes_list, mode, above, below, first_only
        )
        
        successful_operations += success_count
        total_operations += op_count
    
    print_colored("=========================================", "cyan")
    print_colored("📈 處理總結:", "cyan")
    print(f"  總專案數: {total_projects}")
    print(f"  已處理專案: {processed_projects}")
    print(f"  總操作數: {total_operations}")
    print(f"  成功操作數: {successful_operations}")
    
    if total_operations > 0:
        success_rate = (successful_operations / total_operations) * 100
        color = "green" if success_rate >= 80 else "yellow" if success_rate >= 50 else "red"
        print_colored(f"  成功率: {success_rate:.1f}%", color)
    else:
        print("  成功率: N/A")
    
    print()
    
    total_results, total_vulnerabilities = get_directory_stats(output_base_dir, cwes_list)
    
    print()
    
    if not dry_run:
        print_colored("📊 正在生成 CSV 統計報告...", "cyan")
        csv_file = generate_csv_report(projects_dir, json_dir, output_base_dir, cwes_list)
        
        if logger:
            logger.info("=== 批次處理完成 ===")
            logger.info(f"總專案數: {total_projects}")
            logger.info(f"已處理專案: {processed_projects}")
            logger.info(f"總操作數: {total_operations}")
            logger.info(f"成功操作數: {successful_operations}")
            if total_operations > 0:
                success_rate = (successful_operations / total_operations) * 100
                logger.info(f"成功率: {success_rate:.1f}%")
            logger.info(f"總處理結果: {total_results}")
            logger.info(f"總漏洞檔案: {total_vulnerabilities}")
            if csv_file:
                logger.info(f"CSV 統計報告: {csv_file}")
    
    if total_results > 0:
        if total_vulnerabilities > 0:
            print_colored("✨ 批次處理完成！", "green")
            print_colored(f"📁 總共產生了 {total_results} 個處理結果，發現 {total_vulnerabilities} 個漏洞檔案", "green")
        else:
            print_colored(f"⚠️  批次處理完成，產生了 {total_results} 個處理結果，但沒有發現任何漏洞", "yellow")
    else:
        print_colored("⚠️  批次處理完成，但沒有產生任何結果", "yellow")
    
    if not dry_run and logger:
        print_colored(f"📝 完整日誌已保存到: {log_file}", "green")
    
    return 0

def interactive_main():
    """互動式主程式"""
    clear_screen()
    print_header()
    
    # 1. Language
    language = select_language()
    if not language:
        return
    
    # 2. CWEs
    cwes = select_cwes_interactive()
    
    # 3. Mode
    mode = select_mode()
    
    # 4. Lines
    above, below = select_lines()
    above = int(above)
    below = int(below)
    
    # 5. First Only
    first_only = select_first_only()
    
    # Construct paths
    projects_dir = Path(f"./projects/{language}")
    
    json_dir_map = {
        "python": "python_query_output",
        "cpp": "cpp_query_output",
        "java": "java_query_output",
        "go": "go_query_output",
        "javascript": "js_query_output"
    }
    json_dir_name = json_dir_map.get(language, f"{language}_query_output")
    json_dir = Path(f"./{json_dir_name}")
    
    output_dir_name = f"{language}_{mode}"
    if above > 0 or below > 0:
        output_dir_name += f"_a{above}_b{below}"
        
    output_dir = Path(f"./rm_output/{output_dir_name}")
    
    print(f"\n{CYAN}Configuration:{RESET}")
    print(f"  Language:     {GREEN}{language}{RESET}")
    print(f"  Projects Dir: {projects_dir}")
    print(f"  JSON Dir:     {json_dir}")
    print(f"  CWEs:         {GREEN}{', '.join(cwes)}{RESET}")
    print(f"  Mode:         {GREEN}{mode}{RESET}")
    print(f"  Context:      Above: {above}, Below: {below}")
    print(f"  First Only:   {GREEN}{'Yes' if first_only else 'No'}{RESET}")
    print(f"  Output Dir:   {GREEN}{output_dir}{RESET}")
    
    confirm = get_input("\nProceed? (y/n)", "y")
    if confirm.lower() != 'y':
        print("Aborted.")
        return
    
    print(f"\n{YELLOW}Running batch process...{RESET}")
    
    try:
        batch_process(
            projects_dir=projects_dir,
            json_dir=json_dir,
            output_base_dir=output_dir,
            language=language,
            cwes_list=cwes,
            mode=mode,
            above=above,
            below=below,
            dry_run=False,
            first_only=first_only
        )
        
        # 處理完成後，移除輸出目錄中所有的 .gitignore 檔案
        remove_gitignore_files(str(output_dir))
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        import traceback
        traceback.print_exc()

def cli_main():
    """命令列主程式"""
    parser = argparse.ArgumentParser(description="CodeQL CWE Batch Processor - All-in-One")
    parser.add_argument("--projects-dir", help="專案目錄路徑")
    parser.add_argument("--json-dir", help="JSON 檔案目錄路徑")
    parser.add_argument("--output-dir", help="輸出目錄路徑")
    parser.add_argument("--language", default="python", help="程式語言 (預設: python)")
    parser.add_argument("--cwe-list", nargs="+", help="指定要處理的 CWE 列表")
    parser.add_argument("--mode", default="call", choices=["call", "caller", "bb"], help="刪除模式")
    parser.add_argument("--above", type=int, default=0, help="向上額外刪除的行數")
    parser.add_argument("--below", type=int, default=0, help="向下額外刪除的行數")
    parser.add_argument("--dry-run", action="store_true", help="只顯示將要處理的專案")
    parser.add_argument("--first-only", action="store_true", help="每個檔案只處理第一個函數的漏洞")
    parser.add_argument("--interactive", "-i", action="store_true", help="使用互動式模式")
    args = parser.parse_args()
    
    if args.interactive or (not args.projects_dir and not args.json_dir):
        interactive_main()
    else:
        if not args.projects_dir or not args.json_dir:
            print_colored("❌ 錯誤: 非互動模式需要指定 --projects-dir 和 --json-dir", "red")
            return 1
        
        projects_dir = Path(args.projects_dir)
        json_dir = Path(args.json_dir)
        
        if args.output_dir:
            output_dir = Path(args.output_dir)
        else:
            output_dir_name = f"{args.language}_{args.mode}"
            if args.above > 0 or args.below > 0:
                output_dir_name += f"_a{args.above}_b{args.below}"
            output_dir = Path(f"./rm_output/{output_dir_name}")
        
        cwes_list = args.cwe_list if args.cwe_list else ["327"]
        
        batch_process(
            projects_dir=projects_dir,
            json_dir=json_dir,
            output_base_dir=output_dir,
            language=args.language,
            cwes_list=cwes_list,
            mode=args.mode,
            above=args.above,
            below=args.below,
            dry_run=args.dry_run,
            first_only=args.first_only
        )
        
        if not args.dry_run:
            remove_gitignore_files(str(output_dir))

if __name__ == "__main__":
    try:
        cli_main()
    except KeyboardInterrupt:
        print_colored("\n\n⏹️  用戶中斷處理", "yellow")
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n❌ 發生未預期的錯誤: {e}", "red")
        import traceback
        traceback.print_exc()
        sys.exit(1)
