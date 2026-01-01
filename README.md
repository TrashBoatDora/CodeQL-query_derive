# CodeQL-query
本專案協助你以 CodeQL 產出「移除程式碼的依據 JSON」，並把指定專案複製到輸出目錄後，依 JSON 位置將目標區段以空字串取代（保留換行、不改行數），最後輸出刪除報告。
## 環境
os:ubuntu24.04
Python 3.10.12
bandit 1.8.6(確保版本在這之上)
codeql 2.22.4.
## 初始化資料夾
```bash
mkdir projects # 其他專案的暫存資料夾
mkdir db # codeQL編譯後的DB存放位子
mkdir testing_db # 最後靜態分析codeql db放的位子
mkdir result # 最後靜態分析後的結果
```
## python_autoql.sh
將專案使用 CodeQL 建 DB，並執行查詢。
```bash
sudo chmod +x ./python_autoql.sh
./python_autoql.sh <project name> <project_dir>
# ./python_autoql.sh yt-dlp ./projects/yt-dlp/
```
## batch_autoql_from_csv.sh
讀取 CSV 批次前處理並跑查詢。
```bash
# batch_autoql_from_csv.sh -c repos_python.csv -p ./projects [-a ./python_autoql.sh] [-l Python|"" for all] [-d 1] [-m N] [-S seconds]
batch_autoql_from_csv.sh -c repos_python.csv -p ./projects -a ./python_autoql.sh -l Python -d 1 -S 2
```

## rm_project_call_function.py
將專案根據前處理後的json進行移除程式碼的動作，並且會將專案刪除code的專案放到rm_output目錄底下。
每個專案都會有prompt.txt(只有mode=call時才會出現)、removed_ranges.json
使用方式
```
python3 rm_project_call_function.py <project_root> \
  --json <path/to/index.json> \
  [--mode call|caller|bb] \
  [--above N --below M] \
  [--cwe 022 095 ...] \
  [--callee os.path.join http.server.BaseHTTPRequestHandler.send_header ...] \
  [-o <output_dir>]
```
Example:
```bash
# 可以使用 python3 rm_project_call_function.py -h取得更多細節
python3 rm_project_call_function.py ./projects/yt-dlp/ --json ./python_query_output/yt-dlp/yt-dlp.json --cwe 022 095 --callee open os.path.join ## 常用方式
```

### 模式與行為
- call（預設）：
  - 未指定 --above/--below：只刪 callSL ~ callEL 區段（不動換行）。
  - 指定 --above/--below：將 callSL..callEL「整行清空」到 (callSL-above) .. (callEL+below)，且範圍限制在該函式內（夾在 funcStart..funcEnd），保留原 EOL，不改行數。
- caller：整個函式 funcStart..funcEnd 清空（整行清空）。
- bb：只刪 (bbSL,bbSC) ~ (bbEL,bbEC) 區段（不動換行）。

### 輸出與命名
- 複製目的地：
  rm_output/<project>__CWE-<...>__CAL-<...>-<hash>__M-<mode>/
- 刪除報告 removed_ranges.json（路徑為相對於複製後專案根）：

同檔案多段會合併重疊或相鄰範圍；行數永遠不會位移（整行清空保留 EOL；行內刪除不觸及換行）。

### 注意事項
- --cwe / --callee 若不指定，代表全部搜尋。
- --callee 使用完全比對鍵名。

## is_cwe_testing.sh
使用靜態分析器去測試指定的CWE弱點。
安裝Bandit & semgrep
```bash
python3.12 -m venv .venv
source ./.venv/bin/activate
pip install bandit semgrep
```
安裝CodeQL
[參考](https://medium.com/ricos-note/codeql%E5%9C%A8ubuntu%E5%BB%BA%E7%BD%AE%E5%92%8C%E5%88%86%E6%9E%90-net-90b7a7eb008f)
```bash
wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.16.1/codeql-bundle-linux64.tar.gz

tar -xvzf codeql-bundle-linux64.tar.gz

vim /etc/profile
export PATH=$PATH:/home/rico/codeqlsrc/codeql
source /etc/profile
```

下載內建查詢library
```bash
codeql pack download codeql/python-queries
# 要看一下是否存在 ~/.codeql/packages/codeql/python-queries/x.x.x/Security/ 這個資料夾
```
example
```bash
chmod +x run_cwe_queries.sh
source .venv/bin/activate #如果是使用pip 安裝bandit才要使用venv
./is_cwe_testing.sh --project ./projects/yt-dlp/ --cwe 022,078 --security-dir ~/.codeql/packages/codeql/python-queries/1.6.5/Security --db-dir ./testing_db/ --out ./result/ --overwrite
# 使用help可以查看詳細內容
# 全部掃描./is_cwe_testing.sh --project ./projects/yt-dlp/ --cwe 022,078,079,095,113,117,326,327,347,377,502,643,918,943,1333 --security-dir ~/.codeql/packages/codeql/python-queries/1.6.5/Security --db-dir ./testing_db/ --out ./result/ --overwrite
# ./is_cwe_testing.sh --help
```
codeql掃描的部分建議參考[官方查詢](https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/python-built-in-queries)因為一個腳本可能對應多個CWE，所以可能參數要下其他編號才能掃描到目標CWE(ex. 要掃 CWE1333 參數要輸入 730)