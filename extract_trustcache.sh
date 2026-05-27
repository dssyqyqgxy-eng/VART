#!/bin/bash
# TrustCache Team ID 完整扫描
# 目录: trustcache_local

OUTPUT="trustcache_local"
mkdir -p "${OUTPUT}"

echo "============================================"
echo "  TrustCache Team ID 完整扫描"
echo "============================================"

# ============================================================
# 1. 找所有 TrustCache 文件
# ============================================================
echo ">>> [1/4] 搜索 TrustCache..."

> "${OUTPUT}/all_paths.txt"

paths=(
    "/Library/Apple/System/Library/PrelinkedKernels/trustcache"
    "/System/Library/PrelinkedKernels/trustcache"
    "/var/db/trustcache"
    "/var/db/codetrust"
    "/Library/Preferences/com.apple.security.libraryvalidation.plist"
)

for p in "${paths[@]}"; do
    if [ -f "$p" ]; then
        echo "    ✅ $p" | tee -a "${OUTPUT}/all_paths.txt"
        cp "$p" "${OUTPUT}/" 2>/dev/null
    fi
done

sudo find / -name "*trustcache*" -o -name "*codetrust*" -type f 2>/dev/null | while read f; do
    echo "    🔍 $f" | tee -a "${OUTPUT}/all_paths.txt"
    cp "$f" "${OUTPUT}/" 2>/dev/null
done

# ============================================================
# 2. 提取所有 10 位字母数字组合
# ============================================================
echo ""
echo ">>> [2/4] 提取 Team ID 候选..."

> "${OUTPUT}/all_teamids_raw.txt"

for f in "${OUTPUT}"/*; do
    [ -f "$f" ] || continue
    [[ "$f" == *.txt ]] && continue
    
    echo "    扫描: $(basename $f)"
    strings "$f" | grep -oE '[A-Z0-9]{10}' >> "${OUTPUT}/all_teamids_raw.txt"
done

# ============================================================
# 3. 去重排序
# ============================================================
echo ""
echo ">>> [3/4] 统计排名..."

sort "${OUTPUT}/all_teamids_raw.txt" | uniq -c | sort -rn | head -100 > "${OUTPUT}/top100.txt"

echo "    前 30 个候选:"
head -30 "${OUTPUT}/top100.txt"

# ============================================================
# 4. 过滤噪音
# ============================================================
echo ""
echo ">>> [4/4] 过滤噪音..."

grep -vE '^(.)\1{9}$' "${OUTPUT}/top100.txt" | grep -vE '^[0-9]{10}$' > "${OUTPUT}/filtered.txt"

echo "    有效候选:"
head -30 "${OUTPUT}/filtered.txt"

# 打包
zip -qr trustcache_local.zip "${OUTPUT}/"

echo ""
echo "============================================"
echo "  ✅ trustcache_local.zip"
echo "============================================"
