#!/bin/bash
# example: ./python_autoql.sh yt-dlp ./projects/yt-dlp/
if [[ $# -ne 2 ]]; then
    echo "Usage: $(basename "$0") <db name> <project root>"
    exit 1
fi

codeql_db_dir="$(pwd)/db"
output_dir="$(pwd)/python_query_output/$1"
ql_dir="$(pwd)/python-ql"
echo "建立輸出資料夾: $output_dir"
mkdir -p "$output_dir"
ql_list=("CWE-022" "CWE-078" "CWE-079" "CWE-095" "CWE-113" "CWE-117" "CWE-326" "CWE-327" "CWE-329" "CWE-347" "CWE-377" "CWE-502" "CWE-643" "CWE-760" "CWE-918" "CWE-943" "CWE-1333")
codeql database create "$codeql_db_dir/$1" --language=python --source-root "$2" --threads=0 --overwrite
for cwe_number in "${ql_list[@]}";do
    codeql query run "${ql_dir}/${cwe_number}.ql" --database "$codeql_db_dir/$1" --output "${output_dir}/${cwe_number}.bqrs"
    codeql bqrs decode --format=csv --output "${output_dir}/${cwe_number}.csv" "${output_dir}/${cwe_number}.bqrs"
    python3 gen_cwe_json.py ${output_dir} $1
done
rm -f "${output_dir}"/*.bqrs
exit 0