#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CWE Processor - Bandit + Semgrep 版本
基於 CodeQL 已標記的漏洞檔案，使用 Bandit 和 Semgrep 進行驗證掃描

特點:
1. 只掃描 CodeQL 已標記有漏洞的檔案（大幅減少掃描時間）
2. 每個 CWE 可設定最多找到 N 個有漏洞的檔案就停止
3. 產出四種視角的結果：Bandit、Semgrep、Either、Both
4. 保留原始掃描報告
"""

import os
import sys
import subprocess
from pathlib import Path
import re
import json
import shutil
import csv
import argparse
from typing import List, Tuple, Dict, Set, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict

# ==================== ANSI Colors ====================
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"
RESET = "\033[0m"

# ==================== 常數定義 ====================
# Bandit + Semgrep 同時支援的 CWE
SUPPORTED_CWES = ["022", "078", "079", "095", "326", "327", "329", "502", "918", "943"]

# ============================================================
# Bandit CWE Mapping
# ============================================================
BANDIT_BY_CWE = {
    "022": "B202",
    "078": "B601,B602,B603,B604,B605,B606,B607,B609",
    "079": "B308,B701,B702,B703,B704",
    "095": "B102,B307",
    "326": "B505",
    "327": "B303,B304,B305,B324,B413,B502,B503,B504,B508,B509",
    "329": "B305",
    "502": "B301,B302,B403,B506",
    "918": "B310",
    "943": "B608,B610,B611",
}

# ============================================================
# Semgrep CWE Mapping
# ============================================================
SEMGREP_BY_CWE = {
    "022": (
        "python.flask.security.injection.path-traversal-open.path-traversal-open,"
        "python.django.security.injection.path-traversal.path-traversal-open"
    ),
    "078": (
        "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true,"
        "python.lang.security.audit.dangerous-system-call.dangerous-system-call"
    ),
    "079": (
        "python.flask.security.audit.directly-returned-format-string.directly-returned-format-string,"
        "python.django.security.injection.raw-html-format.raw-html-format"
    ),
    "095": (
        "python.lang.security.audit.eval-detected.eval-detected,"
        "python.lang.security.audit.exec-detected.exec-detected"
    ),
    "326": "python.cryptography.security.insufficient-rsa-key-size.insufficient-rsa-key-size",
    "327": (
        "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5,"
        "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1"
    ),
    "329": "python.cryptography.security.insecure-cipher-mode.insecure-cipher-mode-ecb",
    "502": (
        "python.lang.security.deserialization.avoid-pickle.avoid-pickle,"
        "python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load"
    ),
    "918": (
        "python.flask.security.injection.ssrf-requests.ssrf-requests,"
        "python.django.security.injection.ssrf.ssrf-injection-requests"
    ),
    "943": (
        "python.sqlalchemy.security.sqlalchemy-sql-injection.sqlalchemy-sql-injection,"
        "python.django.security.injection.sql.sql-injection-extra,"
        "python.lang.security.audit.sqli.sqli"
    ),
}


@dataclass
class VulnerabilityRecord:
    """漏洞記錄"""
    file_path: str
    line_start: int
    line_end: int
    scanner: str  # "bandit" or "semgrep"
    rule_id: str
    severity: str
    confidence: str
    description: str


class ScanResult:
    """掃描結果聚合"""
    def __init__(self):
        self.bandit_vulns: List[VulnerabilityRecord] = []
        self.semgrep_vulns: List[VulnerabilityRecord] = []
    
    @property
    def has_bandit(self) -> bool:
        return len(self.bandit_vulns) > 0
    
    @property
    def has_semgrep(self) -> bool:
        return len(self.semgrep_vulns) > 0
    
    @property
    def has_either(self) -> bool:
        return self.has_bandit or self.has_semgrep
    
    @property
    def has_both(self) -> bool:
        return self.has_bandit and self.has_semgrep
    
    def all_vulns(self) -> List[VulnerabilityRecord]:
        return self.bandit_vulns + self.semgrep_vulns


def print_colored(text, color="white"):
    """顏色輸出"""
    colors = {
        "red": RED, "green": GREEN, "yellow": YELLOW,
        "blue": BLUE, "magenta": MAGENTA, "cyan": CYAN,
        "white": WHITE, "reset": RESET
    }
    print(f"{colors.get(color, colors['white'])}{text}{RESET}")


def get_input(prompt, default=None):
    """獲取用戶輸入"""
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()


def check_command(command: str) -> bool:
    """檢查命令是否可用"""
    try:
        result = subprocess.run([command, "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_bandit_cmd() -> str:
    """獲取 Bandit 命令"""
    if check_command(".venv/bin/bandit"):
        return ".venv/bin/bandit"
    return "bandit"


def get_semgrep_cmd() -> str:
    """獲取 Semgrep 命令"""
    if check_command(".venv/bin/semgrep"):
        return ".venv/bin/semgrep"
    return "semgrep"


# ==================== CodeQL 結果解析 ====================

def extract_files_from_codeql_csv(csv_file: Path) -> Set[str]:
    """
    從 CodeQL CSV 檔案中提取檔案路徑
    
    Returns:
        Set[str]: 相對路徑集合（相對於專案根目錄）
    """
    files = set()
    
    if not csv_file.exists():
        return files
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # 跳過標題行
            
            for row in reader:
                if row and len(row) > 0:
                    # 格式: "path: /home/sixsquare/codeQL/projects/django/django/..."
                    path_str = row[0]
                    match = re.search(r'path:\s*(.+)', path_str)
                    if match:
                        full_path = match.group(1).strip()
                        # 提取專案內的相對路徑
                        # 路徑格式: /home/.../projects/{project_name}/{relative_path}
                        parts = full_path.split('/projects/')
                        if len(parts) > 1:
                            after_projects = parts[1]
                            first_slash = after_projects.find('/')
                            if first_slash != -1:
                                relative_path = after_projects[first_slash + 1:]
                                files.add(relative_path)
    except Exception as e:
        print_colored(f"解析 CSV 失敗: {e}", "red")
    
    return files


def extract_files_from_codeql_json(json_file: Path, cwe: str) -> Set[str]:
    """
    從 CodeQL JSON 檔案中提取特定 CWE 的檔案路徑
    
    Returns:
        Set[str]: 相對路徑集合
    """
    files = set()
    
    if not json_file.exists():
        return files
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        cwe_key = f"CWE-{cwe}"
        if cwe_key not in data:
            return files
        
        callee_map = data[cwe_key]
        for callee, file_map in callee_map.items():
            for file_path in file_map.keys():
                # 移除開頭的專案名稱
                parts = Path(file_path).parts
                if len(parts) > 1:
                    relative_path = str(Path(*parts[1:]))
                    files.add(relative_path)
    except Exception as e:
        print_colored(f"解析 JSON 失敗: {e}", "red")
    
    return files


# ==================== Bandit 掃描 ====================

def scan_file_with_bandit(file_path: Path, cwe: str, output_dir: Path) -> List[VulnerabilityRecord]:
    """使用 Bandit 掃描單一檔案"""
    tests = BANDIT_BY_CWE.get(cwe)
    if not tests:
        return []
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 生成安全的檔案名稱
    safe_filename = str(file_path).replace('/', '_').replace('\\', '_')
    output_file = output_dir / f"{safe_filename}.json"
    
    bandit_cmd = get_bandit_cmd()
    cmd = [bandit_cmd, str(file_path), "-t", tests, "-f", "json", "-o", str(output_file)]
    
    vulnerabilities = []
    
    try:
        subprocess.run(cmd, capture_output=True, timeout=60)
        
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for result in data.get("results", []):
                vuln = VulnerabilityRecord(
                    file_path=str(file_path),
                    line_start=result.get("line_number", 0),
                    line_end=result.get("line_number", 0),
                    scanner="bandit",
                    rule_id=result.get("test_id", ""),
                    severity=result.get("issue_severity", ""),
                    confidence=result.get("issue_confidence", ""),
                    description=result.get("issue_text", "")
                )
                vulnerabilities.append(vuln)
                
    except subprocess.TimeoutExpired:
        print_colored(f"  Bandit 掃描超時: {file_path}", "yellow")
    except Exception as e:
        pass  # 靜默處理錯誤
    
    return vulnerabilities


# ==================== Semgrep 掃描 ====================

def scan_file_with_semgrep(file_path: Path, cwe: str, output_dir: Path) -> List[VulnerabilityRecord]:
    """使用 Semgrep 掃描單一檔案"""
    rule_patterns = SEMGREP_BY_CWE.get(cwe)
    if not rule_patterns:
        return []
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 生成安全的檔案名稱
    safe_filename = str(file_path).replace('/', '_').replace('\\', '_')
    output_file = output_dir / f"{safe_filename}.json"
    
    # 將規則字符串分割成列表
    rule_list = [r.strip() for r in rule_patterns.split(",")]
    
    semgrep_cmd = get_semgrep_cmd()
    cmd = [semgrep_cmd, "scan"]
    
    # 添加規則
    for rule in rule_list:
        cmd.extend(["--config", f"r/{rule}"])
    
    cmd.extend([
        "--json",
        "--output", str(output_file),
        "--quiet",
        "--disable-version-check",
        "--metrics", "off",
        str(file_path)
    ])
    
    vulnerabilities = []
    
    try:
        subprocess.run(cmd, capture_output=True, timeout=60, text=True)
        
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for result in data.get("results", []):
                start_line = result.get("start", {}).get("line", 0)
                end_line = result.get("end", {}).get("line", 0)
                extra = result.get("extra", {})
                metadata = extra.get("metadata", {})
                
                vuln = VulnerabilityRecord(
                    file_path=str(file_path),
                    line_start=start_line,
                    line_end=end_line,
                    scanner="semgrep",
                    rule_id=result.get("check_id", ""),
                    severity=metadata.get("impact", extra.get("severity", "")),
                    confidence=metadata.get("confidence", "MEDIUM"),
                    description=extra.get("message", "")
                )
                vulnerabilities.append(vuln)
                
    except subprocess.TimeoutExpired:
        print_colored(f"  Semgrep 掃描超時: {file_path}", "yellow")
    except Exception as e:
        pass  # 靜默處理錯誤
    
    return vulnerabilities


# ==================== 主要掃描流程 ====================

def get_all_python_files(project_path: Path, exclude_dirs: Set[str] = None) -> List[Path]:
    """
    獲取專案中所有 Python 檔案
    
    Args:
        project_path: 專案根目錄
        exclude_dirs: 要排除的目錄名稱集合
        
    Returns:
        List[Path]: Python 檔案路徑列表（相對路徑）
    """
    if exclude_dirs is None:
        exclude_dirs = {
            '.git', '.svn', '.hg',
            '__pycache__', '.pytest_cache', '.mypy_cache',
            'node_modules', '.tox', '.eggs',
            'venv', '.venv', 'env', '.env',
            'build', 'dist', '*.egg-info',
            'site-packages'
        }
    
    python_files = []
    
    try:
        for py_file in project_path.rglob("*.py"):
            # 檢查是否在排除目錄中
            parts = py_file.relative_to(project_path).parts
            if any(excluded in parts for excluded in exclude_dirs):
                continue
            
            # 排除太大的檔案（超過 1MB）
            try:
                if py_file.stat().st_size > 1024 * 1024:
                    continue
            except OSError:
                continue
            
            python_files.append(py_file.relative_to(project_path))
    except Exception:
        pass
    
    return python_files


def load_existing_results(output_base_dir: Path, cwe: str, view_type: str) -> Tuple[Dict[str, Dict[str, ScanResult]], Set[str], int]:
    """
    載入已存在的掃描結果
    
    Args:
        output_base_dir: 輸出根目錄
        cwe: CWE ID
        view_type: 視角類型
        
    Returns:
        Tuple[results, scanned_keys, existing_vuln_count]:
            - results: 已存在的結果（Dict[project_name, Dict[file_path, ScanResult]]）
            - scanned_keys: 已掃描的檔案 key 集合（"project_name/relative_path"）
            - existing_vuln_count: 在指定視角下已有的漏洞檔案數
    """
    results: Dict[str, Dict[str, ScanResult]] = {}
    scanned_keys: Set[str] = set()
    existing_vuln_count = 0
    
    cwe_dir = output_base_dir / f"CWE-{cwe}"
    either_view_file = cwe_dir / "either_view.json"
    
    if not either_view_file.exists():
        return results, scanned_keys, existing_vuln_count
    
    try:
        with open(either_view_file, 'r', encoding='utf-8') as f:
            either_data = json.load(f)
        
        for key, vulns in either_data.items():
            scanned_keys.add(key)
            
            # 解析 key: "project_name/relative_path"
            parts = key.split('/', 1)
            if len(parts) != 2:
                continue
            
            project_name, relative_path = parts
            
            # 重建 ScanResult
            scan_result = ScanResult()
            for v in vulns:
                vuln = VulnerabilityRecord(
                    file_path=v.get("file_path", ""),
                    line_start=v.get("line_start", 0),
                    line_end=v.get("line_end", 0),
                    scanner=v.get("scanner", ""),
                    rule_id=v.get("rule_id", ""),
                    severity=v.get("severity", ""),
                    confidence=v.get("confidence", ""),
                    description=v.get("description", "")
                )
                if vuln.scanner == "bandit":
                    scan_result.bandit_vulns.append(vuln)
                elif vuln.scanner == "semgrep":
                    scan_result.semgrep_vulns.append(vuln)
            
            # 保存到結果
            if project_name not in results:
                results[project_name] = {}
            results[project_name][relative_path] = scan_result
            
            # 根據視角計算已有的漏洞數
            meets_criteria = False
            if view_type == "bandit":
                meets_criteria = scan_result.has_bandit
            elif view_type == "semgrep":
                meets_criteria = scan_result.has_semgrep
            elif view_type == "either":
                meets_criteria = scan_result.has_either
            elif view_type == "both":
                meets_criteria = scan_result.has_both
            
            if meets_criteria:
                existing_vuln_count += 1
                
    except Exception as e:
        print_colored(f"載入既有結果失敗: {e}", "yellow")
    
    return results, scanned_keys, existing_vuln_count


def scan_cwe_files(
    cwe: str,
    projects_dir: Path,
    codeql_output_dir: Path,
    output_base_dir: Path,
    view_type: str = "either",
    max_files: int = 100
) -> Dict[str, Dict[str, ScanResult]]:
    """
    掃描特定 CWE 的檔案
    
    策略：
    1. 先載入已存在的掃描結果，跳過已掃描的檔案
    2. 優先掃描 CodeQL 已標記的檔案
    3. 如果找不滿 max_files，則進行地毯式搜索
    
    Args:
        cwe: CWE ID (如 "327")
        projects_dir: 專案根目錄 (如 ./projects/python)
        codeql_output_dir: CodeQL 輸出目錄 (如 ./python_query_output)
        output_base_dir: 輸出根目錄 (如 ./python_bandit_semgrep_query_output)
        view_type: 視角類型 ("bandit", "semgrep", "either", "both")
        max_files: 在指定視角下，最多找到的有漏洞檔案數
        
    Returns:
        Dict[project_name, Dict[file_path, ScanResult]]
    """
    view_names = {
        "bandit": "Bandit 發現",
        "semgrep": "Semgrep 發現",
        "either": "任一發現",
        "both": "兩者皆發現"
    }
    
    print_colored(f"\n=== 掃描 CWE-{cwe} ===", "cyan")
    print(f"視角: {view_names.get(view_type, view_type)}")
    print(f"目標: 找到 {max_files} 個符合視角條件的檔案")
    
    # ========== 載入已存在的結果 ==========
    results, scanned_keys, files_with_vulns = load_existing_results(output_base_dir, cwe, view_type)
    total_files_scanned = len(scanned_keys)
    
    if scanned_keys:
        print_colored(f"\n已載入 {len(scanned_keys)} 個已掃描檔案，其中 {files_with_vulns} 個符合視角條件", "yellow")
    
    if files_with_vulns >= max_files:
        print_colored(f"已達到目標 {max_files} 個檔案，無需繼續掃描", "green")
        return results
    
    # ========== 階段 1: 優先掃描 CodeQL 標記的檔案 ==========
    print_colored(f"\n--- 階段 1: 掃描 CodeQL 標記的檔案 ---", "yellow")
    
    project_dirs = sorted([d for d in codeql_output_dir.iterdir() if d.is_dir()])
    
    for project_output_dir in project_dirs:
        if files_with_vulns >= max_files:
            break
            
        project_name = project_output_dir.name
        project_path = projects_dir / project_name
        
        if not project_path.exists():
            continue
        
        # 嘗試從 CSV 和 JSON 中提取檔案列表
        csv_file = project_output_dir / f"CWE-{cwe}.csv"
        json_file = project_output_dir / f"{project_name}.json"
        
        codeql_files = set()
        if csv_file.exists():
            codeql_files.update(extract_files_from_codeql_csv(csv_file))
        if json_file.exists():
            codeql_files.update(extract_files_from_codeql_json(json_file, cwe))
        
        if not codeql_files:
            continue
        
        # 過濾掉已掃描的檔案
        unscanned_codeql_files = []
        for rel_path in codeql_files:
            key = f"{project_name}/{rel_path}"
            if key not in scanned_keys:
                unscanned_codeql_files.append(rel_path)
        
        if not unscanned_codeql_files:
            continue
        
        print(f"\n專案: {project_name} ({len(unscanned_codeql_files)}/{len(codeql_files)} 個未掃描的 CodeQL 標記檔案)")
        
        # 準備輸出目錄
        raw_bandit_dir = output_base_dir / project_name / "raw_reports" / "bandit" / f"CWE-{cwe}"
        raw_semgrep_dir = output_base_dir / project_name / "raw_reports" / "semgrep" / f"CWE-{cwe}"
        
        # 初始化專案結果（如果還沒有）
        if project_name not in results:
            results[project_name] = {}
        
        for relative_path in sorted(unscanned_codeql_files):
            if files_with_vulns >= max_files:
                break
            
            file_path = project_path / relative_path
            
            if not file_path.exists() or not file_path.suffix == '.py':
                continue
            
            key = f"{project_name}/{relative_path}"
            scanned_keys.add(key)
            total_files_scanned += 1
            
            # 掃描
            scan_result = ScanResult()
            scan_result.bandit_vulns = scan_file_with_bandit(file_path, cwe, raw_bandit_dir)
            scan_result.semgrep_vulns = scan_file_with_semgrep(file_path, cwe, raw_semgrep_dir)
            
            # 根據視角判斷是否符合條件
            meets_criteria = False
            if view_type == "bandit":
                meets_criteria = scan_result.has_bandit
            elif view_type == "semgrep":
                meets_criteria = scan_result.has_semgrep
            elif view_type == "either":
                meets_criteria = scan_result.has_either
            elif view_type == "both":
                meets_criteria = scan_result.has_both
            
            # 保存所有有漏洞的結果（無論視角）
            if scan_result.has_either:
                results[project_name][relative_path] = scan_result
            
            # 只有符合視角條件的才計入終止計數
            if meets_criteria:
                files_with_vulns += 1
                
                bandit_count = len(scan_result.bandit_vulns)
                semgrep_count = len(scan_result.semgrep_vulns)
                print(f"  ✓ [{files_with_vulns}/{max_files}] {relative_path} "
                      f"(B:{bandit_count}, S:{semgrep_count})")
        
        # 清理空的專案結果
        if not results[project_name]:
            del results[project_name]
    
    print(f"\n階段 1 完成: 累計掃描 {total_files_scanned} 個檔案，找到 {files_with_vulns} 個符合條件")
    
    # ========== 階段 2: 地毯式搜索（如果還沒找滿） ==========
    if files_with_vulns < max_files:
        print_colored(f"\n--- 階段 2: 地毯式搜索（還需 {max_files - files_with_vulns} 個檔案）---", "yellow")
        
        # 獲取所有專案目錄
        all_projects = sorted([d for d in projects_dir.iterdir() if d.is_dir()])
        
        for project_path in all_projects:
            if files_with_vulns >= max_files:
                break
            
            project_name = project_path.name
            
            # 獲取專案中所有 Python 檔案
            all_python_files = get_all_python_files(project_path)
            
            if not all_python_files:
                continue
            
            # 過濾掉已掃描的檔案
            unscanned_files = []
            for rel_path in all_python_files:
                key = f"{project_name}/{rel_path}"
                if key not in scanned_keys:
                    unscanned_files.append(rel_path)
            
            if not unscanned_files:
                continue
            
            print(f"\n專案: {project_name} (地毯式掃描 {len(unscanned_files)} 個未掃描檔案)")
            
            # 準備輸出目錄
            raw_bandit_dir = output_base_dir / project_name / "raw_reports" / "bandit" / f"CWE-{cwe}"
            raw_semgrep_dir = output_base_dir / project_name / "raw_reports" / "semgrep" / f"CWE-{cwe}"
            
            # 如果結果中還沒有這個專案，初始化
            if project_name not in results:
                results[project_name] = {}
            
            files_scanned_in_project = 0
            
            for relative_path in sorted(unscanned_files):
                if files_with_vulns >= max_files:
                    break
                
                file_path = project_path / relative_path
                relative_path_str = str(relative_path)
                
                key = f"{project_name}/{relative_path_str}"
                scanned_keys.add(key)
                total_files_scanned += 1
                files_scanned_in_project += 1
                
                # 每掃描 100 個檔案顯示進度
                if files_scanned_in_project % 100 == 0:
                    print(f"  ... 已掃描 {files_scanned_in_project} 個檔案")
                
                # 掃描
                scan_result = ScanResult()
                scan_result.bandit_vulns = scan_file_with_bandit(file_path, cwe, raw_bandit_dir)
                scan_result.semgrep_vulns = scan_file_with_semgrep(file_path, cwe, raw_semgrep_dir)
                
                # 根據視角判斷是否符合條件
                meets_criteria = False
                if view_type == "bandit":
                    meets_criteria = scan_result.has_bandit
                elif view_type == "semgrep":
                    meets_criteria = scan_result.has_semgrep
                elif view_type == "either":
                    meets_criteria = scan_result.has_either
                elif view_type == "both":
                    meets_criteria = scan_result.has_both
                
                # 保存所有有漏洞的結果（無論視角）
                if scan_result.has_either:
                    results[project_name][relative_path_str] = scan_result
                
                # 只有符合視角條件的才計入終止計數
                if meets_criteria:
                    files_with_vulns += 1
                    
                    bandit_count = len(scan_result.bandit_vulns)
                    semgrep_count = len(scan_result.semgrep_vulns)
                    print(f"  ✓ [{files_with_vulns}/{max_files}] {relative_path_str} "
                          f"(B:{bandit_count}, S:{semgrep_count})")
            
            # 清理空的專案結果
            if not results[project_name]:
                del results[project_name]
    
    print(f"\n掃描完成: 共掃描 {total_files_scanned} 個檔案")
    print(f"符合 {view_names.get(view_type, view_type)} 視角: {files_with_vulns} 個檔案")
    
    return results


def save_aggregated_results(
    cwe: str,
    results: Dict[str, Dict[str, ScanResult]],
    output_base_dir: Path
):
    """
    保存聚合結果（四種視角）
    
    輸出結構:
    - CWE-{cwe}/bandit_view.json       (Bandit 視角)
    - CWE-{cwe}/semgrep_view.json      (Semgrep 視角)
    - CWE-{cwe}/either_view.json       (任一發現)
    - CWE-{cwe}/both_view.json         (兩者皆發現)
    """
    cwe_dir = output_base_dir / f"CWE-{cwe}"
    cwe_dir.mkdir(parents=True, exist_ok=True)
    
    bandit_view = {}    # 只有 Bandit 發現的
    semgrep_view = {}   # 只有 Semgrep 發現的
    either_view = {}    # 任一發現的
    both_view = {}      # 兩者皆發現的
    
    for project_name, file_results in results.items():
        for file_path, scan_result in file_results.items():
            key = f"{project_name}/{file_path}"
            
            # Bandit 視角
            if scan_result.has_bandit:
                bandit_view[key] = [asdict(v) for v in scan_result.bandit_vulns]
            
            # Semgrep 視角
            if scan_result.has_semgrep:
                semgrep_view[key] = [asdict(v) for v in scan_result.semgrep_vulns]
            
            # Either 視角
            if scan_result.has_either:
                either_view[key] = [asdict(v) for v in scan_result.all_vulns()]
            
            # Both 視角
            if scan_result.has_both:
                both_view[key] = [asdict(v) for v in scan_result.all_vulns()]
    
    # 保存各視角結果
    with open(cwe_dir / "bandit_view.json", 'w', encoding='utf-8') as f:
        json.dump(bandit_view, f, ensure_ascii=False, indent=2)
    
    with open(cwe_dir / "semgrep_view.json", 'w', encoding='utf-8') as f:
        json.dump(semgrep_view, f, ensure_ascii=False, indent=2)
    
    with open(cwe_dir / "either_view.json", 'w', encoding='utf-8') as f:
        json.dump(either_view, f, ensure_ascii=False, indent=2)
    
    with open(cwe_dir / "both_view.json", 'w', encoding='utf-8') as f:
        json.dump(both_view, f, ensure_ascii=False, indent=2)
    
    print_colored(f"\n已保存 CWE-{cwe} 聚合結果:", "green")
    print(f"  - bandit_view.json:  {len(bandit_view)} 個檔案")
    print(f"  - semgrep_view.json: {len(semgrep_view)} 個檔案")
    print(f"  - either_view.json:  {len(either_view)} 個檔案")
    print(f"  - both_view.json:    {len(both_view)} 個檔案")


# ==================== 移除漏洞程式碼 ====================

def merge_line_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """合併重疊的行範圍"""
    if not ranges:
        return []
    
    sorted_ranges = sorted(ranges)
    merged = [list(sorted_ranges[0])]
    
    for start, end in sorted_ranges[1:]:
        last = merged[-1]
        if start <= last[1] + 1:
            last[1] = max(last[1], end)
        else:
            merged.append([start, end])
    
    return [tuple(r) for r in merged]


def blank_lines_in_file(file_path: Path, line_ranges: List[Tuple[int, int]]) -> bool:
    """
    將檔案中指定的行範圍清空（變成空行）
    
    Args:
        file_path: 檔案路徑
        line_ranges: [(start_line, end_line), ...] 1-based
        
    Returns:
        bool: 是否成功
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # 合併重疊的行範圍
        merged_ranges = merge_line_ranges(line_ranges)
        
        # 清空指定行（保留換行符）
        for start, end in merged_ranges:
            for i in range(start - 1, min(end, len(lines))):
                # 保留換行符
                if lines[i].endswith('\r\n'):
                    lines[i] = '\r\n'
                elif lines[i].endswith('\n'):
                    lines[i] = '\n'
                elif lines[i].endswith('\r'):
                    lines[i] = '\r'
                else:
                    lines[i] = ''
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        return True
    except Exception as e:
        print_colored(f"清空行失敗 {file_path}: {e}", "red")
        return False


def copy_project_excluding_gitignore(src_dir: Path, dst_dir: Path) -> int:
    """
    複製整個專案，排除 .gitignore 檔案
    
    Args:
        src_dir: 來源專案目錄
        dst_dir: 目標目錄
        
    Returns:
        int: 複製的檔案數量
    """
    file_count = 0
    
    for src_path in src_dir.rglob('*'):
        if src_path.is_file():
            # 跳過 .gitignore 檔案
            if src_path.name == '.gitignore':
                continue
            
            # 計算相對路徑
            relative = src_path.relative_to(src_dir)
            dst_path = dst_dir / relative
            
            # 建立目標目錄
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 複製檔案
            try:
                shutil.copy2(src_path, dst_path)
                file_count += 1
            except Exception:
                pass  # 靜默跳過無法複製的檔案
    
    return file_count


def process_and_remove_vulnerabilities(
    cwe: str,
    view_type: str,  # "bandit", "semgrep", "either", "both"
    projects_dir: Path,
    output_base_dir: Path,
    rm_output_dir: Path
) -> Dict[str, Dict[str, List[Tuple[int, int]]]]:
    """
    處理並移除漏洞程式碼
    
    輸出結構:
    rm_output_bandit_semgrep/
    └── CWE-{cwe}/
        └── {view_type}/
            └── {project_name}/
                ├── (整個專案的所有檔案，.gitignore 除外)
                ├── prompt.txt
                └── removed_ranges.json
    
    Args:
        cwe: CWE ID
        view_type: 視角類型
        projects_dir: 專案根目錄
        output_base_dir: 掃描結果目錄
        rm_output_dir: 移除後的輸出目錄
        
    Returns:
        Dict[project_name, Dict[relative_path, List[(start_line, end_line)]]]
    """
    view_file = output_base_dir / f"CWE-{cwe}" / f"{view_type}_view.json"
    
    if not view_file.exists():
        print_colored(f"找不到視角檔案: {view_file}", "red")
        return {}
    
    with open(view_file, 'r', encoding='utf-8') as f:
        view_data = json.load(f)
    
    if not view_data:
        print_colored(f"CWE-{cwe} {view_type} 視角沒有漏洞資料", "yellow")
        return {}
    
    print_colored(f"\n=== 處理 CWE-{cwe} ({view_type} 視角) ===", "cyan")
    print(f"共 {len(view_data)} 個有漏洞的檔案")
    
    # 準備輸出目錄
    cwe_output_dir = rm_output_dir / f"CWE-{cwe}" / view_type
    
    # 按專案分組漏洞資料
    # file_key 格式: "project_name/relative/path/to/file.py"
    projects_vulns: Dict[str, Dict[str, list]] = defaultdict(dict)
    
    for file_key, vulns in view_data.items():
        parts = file_key.split('/', 1)
        if len(parts) != 2:
            continue
        project_name, relative_path = parts
        projects_vulns[project_name][relative_path] = vulns
    
    all_removed_ranges: Dict[str, Dict[str, List[Tuple[int, int]]]] = {}
    total_projects = 0
    total_vuln_files = 0
    
    for project_name, file_vulns in projects_vulns.items():
        src_project_dir = projects_dir / project_name
        dst_project_dir = cwe_output_dir / project_name
        
        if not src_project_dir.exists():
            print(f"  跳過不存在的專案: {project_name}")
            continue
        
        # 複製整個專案（排除 .gitignore）
        print(f"\n複製專案: {project_name}")
        file_count = copy_project_excluding_gitignore(src_project_dir, dst_project_dir)
        print(f"  已複製 {file_count} 個檔案")
        
        # 處理有漏洞的檔案
        removed_ranges: Dict[str, List[Tuple[int, int]]] = {}
        prompt_files: List[str] = []
        
        for relative_path, vulns in file_vulns.items():
            dst_file = dst_project_dir / relative_path
            
            if not dst_file.exists():
                continue
            
            # 收集要清空的行範圍
            line_ranges = []
            for vuln in vulns:
                start = vuln.get('line_start', 0)
                end = vuln.get('line_end', start)
                if start > 0:
                    line_ranges.append((start, end))
            
            if line_ranges:
                # 清空漏洞行
                blank_lines_in_file(dst_file, line_ranges)
                
                # 記錄移除範圍
                merged = merge_line_ranges(line_ranges)
                removed_ranges[relative_path] = merged
                
                # 加入 prompt
                prompt_files.append(relative_path)
                total_vuln_files += 1
        
        # 在專案目錄下保存 removed_ranges.json
        with open(dst_project_dir / "removed_ranges.json", 'w', encoding='utf-8') as f:
            json.dump(removed_ranges, f, ensure_ascii=False, indent=2)
        
        # 在專案目錄下保存 prompt.txt
        with open(dst_project_dir / "prompt.txt", 'w', encoding='utf-8') as f:
            for file_path in sorted(prompt_files):
                f.write(file_path + '\n')
        
        print(f"  已處理 {len(removed_ranges)} 個有漏洞的檔案")
        print(f"  - removed_ranges.json: {len(removed_ranges)} 筆記錄")
        print(f"  - prompt.txt: {len(prompt_files)} 個檔案")
        
        all_removed_ranges[project_name] = removed_ranges
        total_projects += 1
    
    print_colored(f"\n總計: {total_projects} 個專案, {total_vuln_files} 個有漏洞的檔案", "green")
    
    return all_removed_ranges


# ==================== 互動式介面 ====================

def select_cwes_interactive() -> List[str]:
    """互動式選擇 CWE"""
    print(f"\n{YELLOW}1. 選擇 CWE{RESET}")
    print("支援的 CWE (Bandit + Semgrep 共同支援):")
    for i, cwe in enumerate(SUPPORTED_CWES, 1):
        print(f"  {i:2}. CWE-{cwe}")
    
    print(f"\n輸入選項 (逗號分隔，如 1,2,3 或 all):")
    choice = get_input("選擇", "all")
    
    if choice.lower() == "all":
        return SUPPORTED_CWES.copy()
    
    selected = []
    for part in choice.split(','):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(SUPPORTED_CWES):
                selected.append(SUPPORTED_CWES[idx])
        elif part in SUPPORTED_CWES:
            selected.append(part)
    
    return selected if selected else SUPPORTED_CWES.copy()


def select_view_type() -> str:
    """選擇視角類型"""
    print(f"\n{YELLOW}2. 選擇漏洞判斷視角{RESET}")
    print("  1. bandit  - 只看 Bandit 發現的漏洞")
    print("  2. semgrep - 只看 Semgrep 發現的漏洞")
    print("  3. either  - Bandit 或 Semgrep 任一發現")
    print("  4. both    - Bandit 和 Semgrep 都發現")
    
    choice = get_input("選擇", "3")
    
    views = {"1": "bandit", "2": "semgrep", "3": "either", "4": "both"}
    return views.get(choice, "either")


def select_max_files() -> int:
    """選擇每個 CWE 的最大檔案數"""
    print(f"\n{YELLOW}3. 掃描終止條件{RESET}")
    print("每個 CWE 在選擇的視角下，找到多少個有漏洞的檔案後停止？")
    print("(例如選擇 'both' 視角 + 100 個檔案，會持續掃描直到找到 100 個兩者皆發現漏洞的檔案)")
    
    choice = get_input("最大檔案數", "100")
    
    try:
        return max(1, int(choice))
    except ValueError:
        return 100


def interactive_main():
    """互動式主程式"""
    print_colored("\n" + "=" * 60, "cyan")
    print_colored("  CWE Processor - Bandit + Semgrep 版本", "cyan")
    print_colored("=" * 60, "cyan")
    
    # 檢查掃描器
    print(f"\n{YELLOW}檢查掃描器...{RESET}")
    bandit_ok = check_command(get_bandit_cmd())
    semgrep_ok = check_command(get_semgrep_cmd())
    
    if bandit_ok:
        print_colored("  ✓ Bandit 可用", "green")
    else:
        print_colored("  ✗ Bandit 不可用", "red")
    
    if semgrep_ok:
        print_colored("  ✓ Semgrep 可用", "green")
    else:
        print_colored("  ✗ Semgrep 不可用", "red")
    
    if not (bandit_ok and semgrep_ok):
        print_colored("\n請確保 Bandit 和 Semgrep 都已安裝", "red")
        return
    
    # 選擇選項
    cwes = select_cwes_interactive()
    view_type = select_view_type()
    max_files = select_max_files()
    
    # 設定路徑
    projects_dir = Path("./projects/python")
    codeql_output_dir = Path("./python_query_output")
    output_base_dir = Path("./python_bandit_semgrep_query_output")
    rm_output_dir = Path("./rm_output_bandit_semgrep")
    
    print(f"\n{CYAN}配置:{RESET}")
    print(f"  CWEs:         {', '.join([f'CWE-{c}' for c in cwes])}")
    print(f"  視角:         {view_type}")
    print(f"  每 CWE 上限:  {max_files} 個檔案")
    print(f"  專案目錄:     {projects_dir}")
    print(f"  CodeQL 目錄:  {codeql_output_dir}")
    print(f"  輸出目錄:     {output_base_dir}")
    print(f"  移除輸出:     {rm_output_dir}")
    
    confirm = get_input("\n確認執行? (y/n)", "y")
    if confirm.lower() != 'y':
        print("已取消")
        return
    
    # 執行掃描和處理
    for cwe in cwes:
        # 執行掃描（會自動載入已有結果並繼續掃描）
        results = scan_cwe_files(
            cwe=cwe,
            projects_dir=projects_dir,
            codeql_output_dir=codeql_output_dir,
            output_base_dir=output_base_dir,
            view_type=view_type,
            max_files=max_files
        )
        
        if results:
            save_aggregated_results(cwe, results, output_base_dir)
        
        # 處理並移除漏洞
        process_and_remove_vulnerabilities(
            cwe=cwe,
            view_type=view_type,
            projects_dir=projects_dir,
            output_base_dir=output_base_dir,
            rm_output_dir=rm_output_dir
        )
    
    print_colored("\n=== 全部完成 ===", "green")


# ==================== CLI 主程式 ====================

def cli_main():
    """命令列主程式"""
    parser = argparse.ArgumentParser(
        description="CWE Processor - Bandit + Semgrep 版本"
    )
    parser.add_argument("--cwes", nargs="+", default=None,
                        help="要處理的 CWE 列表 (預設: 全部)")
    parser.add_argument("--view", choices=["bandit", "semgrep", "either", "both"],
                        default="either", help="漏洞判斷視角")
    parser.add_argument("--max-files", type=int, default=100,
                        help="每個 CWE 最多掃描的檔案數")
    parser.add_argument("--scan-only", action="store_true",
                        help="只執行掃描，不移除漏洞")
    parser.add_argument("--process-only", action="store_true",
                        help="只處理已有的掃描結果")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="使用互動式模式")
    
    args = parser.parse_args()
    
    if args.interactive or len(sys.argv) == 1:
        interactive_main()
        return
    
    # 設定路徑
    projects_dir = Path("./projects/python")
    codeql_output_dir = Path("./python_query_output")
    output_base_dir = Path("./python_bandit_semgrep_query_output")
    rm_output_dir = Path("./rm_output_bandit_semgrep")
    
    cwes = args.cwes if args.cwes else SUPPORTED_CWES
    
    for cwe in cwes:
        if not args.process_only:
            # 執行掃描（會自動載入已有結果並繼續掃描）
            results = scan_cwe_files(
                cwe=cwe,
                projects_dir=projects_dir,
                codeql_output_dir=codeql_output_dir,
                output_base_dir=output_base_dir,
                view_type=args.view,
                max_files=args.max_files
            )
            
            if results:
                save_aggregated_results(cwe, results, output_base_dir)
        
        if not args.scan_only:
            process_and_remove_vulnerabilities(
                cwe=cwe,
                view_type=args.view,
                projects_dir=projects_dir,
                output_base_dir=output_base_dir,
                rm_output_dir=rm_output_dir
            )
    
    print_colored("\n=== 完成 ===", "green")


if __name__ == "__main__":
    try:
        cli_main()
    except KeyboardInterrupt:
        print_colored("\n\n已中斷", "yellow")
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n錯誤: {e}", "red")
        import traceback
        traceback.print_exc()
        sys.exit(1)
