#!/bin/bash
# 本地 macOS TrustCache 查找脚本
# 用法: ./extract_trustcache.sh

OUTPUT="trustcache_local"
mkdir -p "${OUTPUT}"

echo "============================================"
echo "  本地 TrustCache 查找"
echo "============================================"

# ============================================================
# 1. macOS 系统信任缓存
# ============================================================
echo ">>> [1] macOS 信任缓存..."

for path in \
    "/Library/Apple/System/Library/PrelinkedKernels/trustcache" \
    "/System/Library/PrelinkedKernels/trustcache" \
    "/Library/Preferences/com.apple.security.libraryvalidation.plist" \
    "/var/db/trustcache" \
    "/var/db/codetrust"; do
    
    if [ -f "${path}" ]; then
        echo "    ✅ 找到: ${path} ($(ls -lh "${path}" | awk '{print $5}'))"
        cp "${path}" "${OUTPUT}/" 2>/dev/null || true
        
        # 提取字符串
        bn=$(basename "${path}")
        strings "${path}" | grep -oE '[A-Z][A-Z0-9]{9}' | sort -u > "${OUTPUT}/${bn}_teamids.txt" 2>/dev/null || true
        strings "${path}" | head -100 > "${OUTPUT}/${bn}_strings.txt" 2>/dev/null || true
    fi
done

# ============================================================
# 2. AMFI 运行时缓存
# ============================================================
echo ">>> [2] AMFI 相关..."

# 检查 AMFI 是否在运行
if pgrep -x "amfid" > /dev/null; then
    echo "    amfid 正在运行 (PID: $(pgrep -x amfid))"
else
    echo "    amfid 未运行"
fi

# 信任评估守护进程
if pgrep -x "trustd" > /dev/null; then
    echo "    trustd 正在运行 (PID: $(pgrep -x trustd))"
fi

# ============================================================
# 3. 已知 Team ID 在本地文件中的出现
# ============================================================
echo ">>> [3] Team ID 搜索..."

> "${OUTPUT}/teamid_summary.txt"

for id in 59GAB85EFG SKMME9E2Y7 0000000000 APPLETEAM EQHXZ8M8AV; do
    total=0
    for f in "${OUTPUT}"/*; do
        if [ -f "$f" ] && [[ "$f" != *.txt ]]; then
            c=$(strings "$f" 2>/dev/null | grep -c "$id" || echo 0)
            total=$((total + c))
        fi
    done
    printf "%-15s: %d 次\n" "${id}" "${total}" | tee -a "${OUTPUT}/teamid_summary.txt"
done

# ============================================================
# 4. 搜索 trustcache 相关文件
# ============================================================
echo ">>> [4] 全盘搜索..."

sudo find / -name "*trustcache*" -type f 2>/dev/null | head -10 > "${OUTPUT}/trustcache_paths.txt" 2>/dev/null || true
sudo find / -name "*codetrust*" -type f 2>/dev/null | head -10 >> "${OUTPUT}/trustcache_paths.txt" 2>/dev/null || true

cat "${OUTPUT}/trustcache_paths.txt" 2>/dev/null

echo ""
echo "============================================"
echo "  ✅ 输出: ${OUTPUT}/"
echo "============================================"
