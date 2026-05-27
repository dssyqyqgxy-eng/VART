#!/bin/bash
# iOS 内核符号提取脚本
# 用法: ./extract_kernel_symbols.sh
# 前提: 项目根目录有 kernelcache.release 文件

set -e

KERNEL="kernelcache.release"
OUTPUT="kernel_analysis"
TOOLS_DIR="./tools"

mkdir -p "${OUTPUT}"

echo "============================================"
echo "  iOS 内核符号提取"
echo "============================================"

# 检查内核文件
if [ ! -f "${KERNEL}" ]; then
    echo "❌ 未找到 ${KERNEL}，请放到项目根目录"
    exit 1
fi

echo ">>> 内核文件: ${KERNEL}"
echo ">>> 大小: $(ls -lh ${KERNEL} | awk '{print $5}')"

# ============================================================
# 1. 直接提取字符串（不需要解密）
# ============================================================
echo ""
echo ">>> [1/8] 提取字符串..."

# Apple 相关字符串
strings "${KERNEL}" | grep -iE "apple|iphone|developer|certificate|identity|trust" > "${OUTPUT}/01_strings_apple.txt" 2>/dev/null || true
echo "    → 01_strings_apple.txt"

# AMFI 相关
strings "${KERNEL}" | grep -i "amfi" > "${OUTPUT}/02_strings_amfi.txt" 2>/dev/null || true
echo "    → 02_strings_amfi.txt"

# Team ID 格式（10位字母数字）
strings "${KERNEL}" | grep -oE '[A-Z0-9]{10}' | sort -u > "${OUTPUT}/03_strings_teamid.txt" 2>/dev/null || true
echo "    → 03_strings_teamid.txt"

# Apple OID
strings "${KERNEL}" | grep -oE '1\.2\.840\.113635\.100\.[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u > "${OUTPUT}/04_strings_oid.txt" 2>/dev/null || true
echo "    → 04_strings_oid.txt"

# 完整 OID 前缀
strings "${KERNEL}" | grep "1.2.840.113635" | sort -u > "${OUTPUT}/05_strings_oid_full.txt" 2>/dev/null || true
echo "    → 05_strings_oid_full.txt"

# CoreTrust 相关
strings "${KERNEL}" | grep -iE "coretrust|trustcache|trustd" > "${OUTPUT}/06_strings_coretrust.txt" 2>/dev/null || true
echo "    → 06_strings_coretrust.txt"

# 签名验证相关
strings "${KERNEL}" | grep -iE "codesign|signature|verify|evaluate|validate" > "${OUTPUT}/07_strings_signing.txt" 2>/dev/null || true
echo "    → 07_strings_signing.txt"

# 硬编码数字
strings "${KERNEL}" | grep -E '^[0-9]{10}$' | sort -u > "${OUTPUT}/08_strings_numbers.txt" 2>/dev/null || true
echo "    → 08_strings_numbers.txt"

echo "    ✅ 字符串提取完成"

# ============================================================
# 2. 检查是否有符号表
# ============================================================
echo ""
echo ">>> [2/8] 检查符号表..."

if file "${KERNEL}" | grep -q "Mach-O"; then
    echo "    Mach-O 格式: ✅"
    
    # 提取符号
    nm "${KERNEL}" 2>/dev/null | grep -iE "amfi|trust|cert|team|sign|verify|evaluate" > "${OUTPUT}/09_symbols_filtered.txt" || true
    echo "    → 09_symbols_filtered.txt"
    
    nm "${KERNEL}" 2>/dev/null > "${OUTPUT}/10_symbols_all.txt" || true
    echo "    → 10_symbols_all.txt"
else
    echo "    ⚠️  加密的 img4 格式，字符串已提取"
fi

# ============================================================
# 3. 查找已知 Apple Team ID
# ============================================================
echo ""
echo ">>> [3/8] 搜索已知 Team ID..."

KNOWN_IDS=(
    "59GAB85EFG"
    "SKMME9E2Y7"
    "0000000000"
    "APPLETEAM"
    "95M7Z54P8M"
    "HFJ3M4U732"
    "EQHXZ8M8AV"
    "3B6K4J5L8M"
)

> "${OUTPUT}/11_known_teamids.txt"
for id in "${KNOWN_IDS[@]}"; do
    count=$(strings "${KERNEL}" | grep -c "${id}" 2>/dev/null || echo 0)
    echo "    ${id}: ${count} 次" | tee -a "${OUTPUT}/11_known_teamids.txt"
done
echo "    → 11_known_teamids.txt"

# ============================================================
# 4. 提取所有唯一 OID
# ============================================================
echo ""
echo ">>> [4/8] 统计 Apple OID..."

strings "${KERNEL}" | grep -oE '1\.2\.840\.113635\.100\.[0-9]+\.[0-9]+' | sort -u > "${OUTPUT}/12_oid_unique.txt" 2>/dev/null || true
echo "    找到 $(wc -l < ${OUTPUT}/12_oid_unique.txt 2>/dev/null || echo 0) 个 Apple OID"
echo "    → 12_oid_unique.txt"

# ============================================================
# 5. 搜索 Profile/描述文件相关
# ============================================================
echo ""
echo ">>> [5/8] 搜索描述文件相关..."

strings "${KERNEL}" | grep -iE "provision|profile|entitlement|embedded" > "${OUTPUT}/13_strings_profile.txt" 2>/dev/null || true
echo "    → 13_strings_profile.txt"

# ============================================================
# 6. 提取所有 10 位字母数字组合（可能是 Team ID）
# ============================================================
echo ""
echo ">>> [6/8] 提取可能的 Team ID..."

# 10位大写字母数字
strings "${KERNEL}" | grep -oE '[A-Z0-9]{10}' | sort | uniq -c | sort -rn | head -50 > "${OUTPUT}/14_possible_teamids.txt" 2>/dev/null || true
echo "    → 14_possible_teamids.txt"

# ============================================================
# 7. 搜索 OID 完整值
# ============================================================
echo ""
echo ">>> [7/8] 搜索 OID 完整上下文..."

for oid_prefix in "6.1" "6.2" "6.3" "6.4" "6.5"; do
    strings "${KERNEL}" | grep "1.2.840.113635.100.${oid_prefix}" >> "${OUTPUT}/15_oid_context.txt" 2>/dev/null || true
done
echo "    → 15_oid_context.txt"

# ============================================================
# 8. 生成汇总报告
# ============================================================
echo ""
echo ">>> [8/8] 生成报告..."

cat > "${OUTPUT}/REPORT.md" << EOF
# iOS 内核符号分析报告

**固件**: ${KERNEL}
**分析时间**: $(date)
**内核大小**: $(ls -lh ${KERNEL} | awk '{print $5}')

---

## 文件清单

| 文件 | 内容 |
|------|------|
| 01_strings_apple.txt | Apple 相关字符串 |
| 02_strings_amfi.txt | AMFI 相关 |
| 03_strings_teamid.txt | Team ID 格式 |
| 04_strings_oid.txt | Apple OID |
| 05_strings_oid_full.txt | 完整 OID 行 |
| 06_strings_coretrust.txt | CoreTrust 相关 |
| 07_strings_signing.txt | 签名验证 |
| 09_symbols_filtered.txt | 过滤后的符号 |
| 11_known_teamids.txt | 已知 Team ID 出现次数 |
| 12_oid_unique.txt | 唯一 OID 列表 |
| 14_possible_teamids.txt | 可能的 Team ID |
| 15_oid_context.txt | OID 上下文 |

---

## 已知 Team ID 搜索结果

\`\`\`
$(cat "${OUTPUT}/11_known_teamids.txt" 2>/dev/null || echo "无")
\`\`\`

## Apple OID 数量

$(wc -l < "${OUTPUT}/12_oid_unique.txt" 2>/dev/null || echo 0) 个唯一 OID
EOF

echo "    → REPORT.md"

# ============================================================
echo ""
echo "============================================"
echo "  ✅ 分析完成！"
echo "  📁 输出: ${OUTPUT}/"
echo "  📄 报告: ${OUTPUT}/REPORT.md"
echo "============================================"
