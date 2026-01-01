#!/usr/bin/env python3
# [functionName, funcStart, funcEnd, callSL, callSC, callEL, callEC, bbSL, bbSC, bbEL, bbEC]
import argparse
import csv
import json
import re
from pathlib import Path

CWE_LIST = ["CWE-022", "CWE-078", "CWE-079", "CWE-095", "CWE-113", "CWE-117",
            "CWE-326", "CWE-327", "CWE-329", "CWE-347", "CWE-377", "CWE-502",
            "CWE-643", "CWE-760", "CWE-918", "CWE-943", "CWE-1333"]

RE_PATH         = re.compile(r'^path:\s*(.*)$', re.I)
RE_CALL_FUNC    = re.compile(r'^call function:\s*(\d+):(\d+)-(\d+):(\d+)$', re.I)
RE_CALL_IN_FUNC = re.compile(r'^call in function:\s*([^@]+)@(\d+)-(\d+)$', re.I)
RE_CALLEE       = re.compile(r'^callee\s*[:=]\s*(.+)$', re.I)
RE_BASIC_BLOCK  = re.compile(r'^basic block:\s*(\d+):(\d+)-(\d+):(\d+)$', re.I)

def shorten_path(p: str) -> str:
    mark = "/projects/"
    i = p.find(mark)
    return p[i + len(mark):] if i != -1 else p

def parse_row(cells: list[str]):
    path = None
    callee = None
    functionName = None
    func_start = func_end = None
    cSL = cSC = cEL = cEC = None
    bSL = bSC = bEL = bEC = None

    for cell in cells:
        cell = cell.strip().strip('"')
        if not cell:
            continue
        m = RE_PATH.match(cell)
        if m:
            path = shorten_path(m.group(1))
            continue
        m = RE_CALL_FUNC.match(cell)
        if m:
            cSL, cSC, cEL, cEC = map(int, m.groups())
            continue
        m = RE_CALL_IN_FUNC.match(cell)
        if m:
            functionName = m.group(1).strip()
            func_start = int(m.group(2))
            func_end   = int(m.group(3))
            continue
        m = RE_BASIC_BLOCK.match(cell)
        if m:
            bSL, bSC, bEL, bEC = map(int, m.groups())
            continue
        m = RE_CALLEE.match(cell)
        if m:
            callee = m.group(1).strip()
            continue

    if not (callee and path and
            cSL is not None and cSC is not None and cEL is not None and cEC is not None):
        return None

    if func_start is None: func_start = cSL
    if func_end   is None: func_end   = cEL
    if bSL is None: bSL = cSL
    if bSC is None: bSC = cSC
    if bEL is None: bEL = cEL
    if bEC is None: bEC = cEC

    payload = [functionName,func_start, func_end, cSL, cSC, cEL, cEC, bSL, bSC, bEL, bEC]
    return callee, path, payload

def better_payload(new_pl: list[int], old_pl: list[int]) -> bool:
    nfS, nfE = new_pl[1], new_pl[2]
    ofS, ofE = old_pl[1], old_pl[2]
    n_span = nfE - nfS
    o_span = ofE - ofS
    if n_span != o_span:
        return n_span < o_span
    return nfS < ofS

def dedup_insert(sink_for_cwe: dict, callee: str, relpath: str, payload: list[int]) -> None:
    cSL, cSC, cEL, cEC, bSL, bSC, bEL, bEC = payload[3:]
    key = (cSL, cSC, cEL, cEC, bSL, bSC, bEL, bEC)
    callee_map = sink_for_cwe.setdefault(callee, {})
    path_map = callee_map.setdefault(relpath, {})
    if key in path_map:
        if better_payload(payload, path_map[key]):
            path_map[key] = payload
    else:
        path_map[key] = payload

def parse_csv_file(csv_path: Path, sink_for_cwe: dict):
    with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            parsed = parse_row(row)
            if not parsed:
                continue
            callee, relpath, payload = parsed
            dedup_insert(sink_for_cwe, callee, relpath, payload)

def materialize_lists(data_for_cwe: dict) -> dict:
    out = {}
    for callee, path_map in data_for_cwe.items():
        out_paths = {}
        for relpath, dedup_dict in path_map.items():
            out_paths[relpath] = list(dedup_dict.values())
        out[callee] = out_paths
    return out

def main():
    ap = argparse.ArgumentParser(description="將CodeQl解析完的CWE-xxx.csv轉成之後挖洞用的json")
    ap.add_argument("csv_dir", help="放入codeQL解析完後CSV所在的資料夾")
    ap.add_argument("name", help="專案名稱")
    args = ap.parse_args()

    csv_dir = Path(args.csv_dir)
    if not csv_dir.is_dir():
        raise SystemExit(f"找不到資料夾：{csv_dir}")

    data = {cwe: {} for cwe in CWE_LIST}

    for cwe in CWE_LIST:
        for csv_path in sorted(csv_dir.glob(f"*{cwe}*.csv")):
            parse_csv_file(csv_path, data[cwe])
    final = {cwe: materialize_lists(data[cwe]) for cwe in CWE_LIST}

    out_path = csv_dir / f"{args.name}.json"
    out_path.write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
