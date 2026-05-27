#!/bin/bash
# iOS 内核 Team ID 提取脚本（精确版）
# 用法: ./extract_teamid.sh

set -e

KERNEL="kernelcache.release"
OUTPUT="kernel_analysis"

mkdir -p "${OUTPUT}"

echo "============================================"
echo "  iOS 内核 Team ID 提取"
echo "============================================"

if [ ! -f "${KERNEL}" ]; then
    echo "❌ 未找到 ${KERNEL}"
    exit 1
fi

echo ">>> 内核: ${KERNEL} ($(ls -lh ${KERNEL} | awk '{print $5}'))"

# ============================================================
# 1. Apple Team ID 格式：[A-Z][A-Z0-9]{9}
# ============================================================
echo ""
echo ">>> [1/6] 提取 Team ID（Apple 格式）..."

strings "${KERNEL}" | grep -oE '[A-Z][A-Z0-9]{9}' | sort | uniq -c | sort -rn | head -50 > "${OUTPUT}/teamid_apple_format.txt"
echo "    → teamid_apple_format.txt"

# ============================================================
# 2. 只提取 10 位字母数字组合
# ============================================================
echo ">>> [2/6] 提取 10 位字母数字..."

strings "${KERNEL}" | grep -oE '[A-Z0-9]{10}' | sort | uniq -c | sort -rn | head -100 > "${OUTPUT}/teamid_10char.txt"
echo "    → teamid_10char.txt"

# ============================================================
# 3. 过滤掉全重复字符的噪音
# ============================================================
echo ">>> [3/6] 过滤噪音..."

grep -vE '^(.)\1{9}$' "${OUTPUT}/teamid_10char.txt" > "${OUTPUT}/teamid_filtered.txt"
echo "    → teamid_filtered.txt"

# ============================================================
# 4. 搜索已知 Team ID
# ============================================================
echo ""
echo ">>> [4/6] 已知 Team ID 搜索..."

KNOWN_IDS=(
    "59GAB85EFG" "SKMME9E2Y7" "0000000000" "APPLETEAM"
    "95M7Z54P8M" "HFJ3M4U732" "EQHXZ8M8AV" "3B6K4J5L8M"
    "FQJ8J3P6X6" "U35G6FL7CE" "3FTAU7JA3Y"
)

> "${OUTPUT}/teamid_known.txt"
for id in "${KNOWN_IDS[@]}"; do
    count=$(strings "${KERNEL}" | grep -c "${id}" 2>/dev/null || echo 0)
    printf "%-15s: %d 次\n" "${id}" "${count}" | tee -a "${OUTPUT}/teamid_known.txt"
done
echo "    → teamid_known.txt"

# ============================================================
# 5. 搜索 Apple OID
# ============================================================
echo ""
echo ">>> [5/6] Apple OID..."

strings "${KERNEL}" | grep "1.2.840.113635" | sort -u > "${OUTPUT}/oid_all.txt"
strings "${KERNEL}" | grep -oE '1\.2\.840\.113635\.100\.[0-9]+\.[0-9]+' | sort -u > "${OUTPUT}/oid_unique.txt"

OID_COUNT=$(wc -l < "${OUTPUT}/oid_unique.txt" 2>/dev/null || echo 0)
echo "    找到 ${OID_COUNT} 个唯一 Apple OID"
echo "    → oid_all.txt"
echo "    → oid_unique.txt"

# ============================================================
# 6. 搜索 AMFI / CoreTrust
# ============================================================
echo ""
echo ">>> [6/6] 签名验证相关..."

strings "${KERNEL}" | grep -i "amfi" > "${OUTPUT}/amfi_strings.txt" 2>/dev/null || true
strings "${KERNEL}" | grep -iE "coretrust|trustcache" > "${OUTPUT}/coretrust_strings.txt" 2>/dev/null || true
strings "${KERNEL}" | grep -iE "teamid|team.identifier" > "${OUTPUT}/teamid_strings.txt" 2>/dev/null || true

echo "    → amfi_strings.txt"
echo "    → coretrust_strings.txt"
echo "    → teamid_strings.txt"

# ============================================================
# 7. 生成报告 + 打包
# ============================================================
echo ""
echo ">>> 生成报告..."

cat > "${OUTPUT}/REPORT.txt" << EOF
============================================
  iOS 内核 Team ID 分析报告
============================================
内核: ${KERNEL}
大小: $(ls -lh ${KERNEL} | awk '{print $5}')
时间: $(date)
============================================

已知 Team ID 出现次数:
$(cat "${OUTPUT}/teamid_known.txt")

Apple OID 数量: ${OID_COUNT}

出现最多的 10 位组合（已过滤噪音）:
$(head -20 "${OUTPUT}/teamid_filtered.txt")

============================================
EOF

echo "    → REPORT.txt"

# 打包
zip -qr kernel_teamid_analysis.zip "${OUTPUT}/"

echo ""
echo "============================================"
echo "  ✅ 完成"
echo "  📥 kernel_teamid_analysis.zip"
echo "  📄 ${OUTPUT}/REPORT.txt"
echo "============================================"
