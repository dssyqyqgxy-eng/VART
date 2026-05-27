#!/bin/bash
# iOS 内核符号提取 + 打包上传脚本
# 用法: ./extract_and_upload.sh
# 前提: 项目根目录有 kernelcache.release 文件

set -e

KERNEL="kernelcache.release"
OUTPUT="kernel_analysis"

mkdir -p "${OUTPUT}"

echo "============================================"
echo "  iOS 内核符号提取 + 打包"
echo "============================================"

# 检查内核文件
if [ ! -f "${KERNEL}" ]; then
    echo "❌ 未找到 ${KERNEL}，请放到项目根目录"
    exit 1
fi

echo ">>> 内核: ${KERNEL} ($(ls -lh ${KERNEL} | awk '{print $5}'))"

# ============================================================
# 1. 提取字符串
# ============================================================
echo ""
echo ">>> [1/3] 提取字符串..."

strings "${KERNEL}" | grep -iE "apple|iphone|developer|certificate|identity|trust" > "${OUTPUT}/01_strings_apple.txt" 2>/dev/null || true
strings "${KERNEL}" | grep -i "amfi" > "${OUTPUT}/02_strings_amfi.txt" 2>/dev/null || true
strings "${KERNEL}" | grep -oE '[A-Z0-9]{10}' | sort -u > "${OUTPUT}/03_teamid_candidates.txt" 2>/dev/null || true
strings "${KERNEL}" | grep "1.2.840.113635" | sort -u > "${OUTPUT}/04_oid_strings.txt" 2>/dev/null || true
strings "${KERNEL}" | grep -iE "coretrust|trustcache|trustd" > "${OUTPUT}/05_coretrust_strings.txt" 2>/dev/null || true
strings "${KERNEL}" | grep -iE "codesign|signature|verify|evaluate|validate" > "${OUTPUT}/06_signing_strings.txt" 2>/dev/null || true
strings "${KERNEL}" | grep -iE "provision|profile|entitlement|embedded" > "${OUTPUT}/07_profile_strings.txt" 2>/dev/null || true

echo "    ✅ 字符串提取完成"

# ============================================================
# 2. 提取符号
# ============================================================
echo ""
echo ">>> [2/3] 提取符号..."

if file "${KERNEL}" | grep -q "Mach-O"; then
    echo "    Mach-O 格式: ✅"
    nm "${KERNEL}" 2>/dev/null | grep -iE "amfi|trust|cert|team|sign|verify|evaluate" > "${OUTPUT}/08_symbols_filtered.txt" || true
    nm "${KERNEL}" 2>/dev/null > "${OUTPUT}/09_symbols_all.txt" || true
else
    echo "    ⚠️  img4 格式，跳过符号表"
fi

echo "    ✅ 符号提取完成"

# ============================================================
# 3. 分析 + 报告 + 打包
# ============================================================
echo ""
echo ">>> [3/3] 分析 + 打包..."

# 已知 Team ID 搜索
> "${OUTPUT}/10_known_teamids.txt"
for id in 59GAB85EFG SKMME9E2Y7 0000000000 APPLETEAM 95M7Z54P8M HFJ3M4U732 EQHXZ8M8AV; do
    count=$(strings "${KERNEL}" 2>/dev/null | grep -c "${id}" || echo 0)
    echo "    ${id}: ${count} 次" | tee -a "${OUTPUT}/10_known_teamids.txt"
done

# 出现最多的 10 位字母数字组合
strings "${KERNEL}" | grep -oE '[A-Z0-9]{10}' | sort | uniq -c | sort -rn | head -50 > "${OUTPUT}/11_top_teamids.txt" 2>/dev/null || true

# 唯一 OID
strings "${KERNEL}" | grep -oE '1\.2\.840\.113635\.100\.[0-9]+\.[0-9]+' | sort -u > "${OUTPUT}/12_oid_unique.txt" 2>/dev/null || true
OID_COUNT=$(wc -l < "${OUTPUT}/12_oid_unique.txt" 2>/dev/null || echo 0)

# 生成报告
cat > "${OUTPUT}/REPORT.txt" << EOF
============================================
  iOS 内核符号分析报告
============================================
内核文件: ${KERNEL}
大小:     $(ls -lh ${KERNEL} | awk '{print $5}')
时间:     $(date)
Apple OID: ${OID_COUNT} 个

已知 Team ID:
$(cat "${OUTPUT}/10_known_teamids.txt" 2>/dev/null || echo "无")

文件清单:
  01_strings_apple.txt       - Apple 相关字符串
  02_strings_amfi.txt        - AMFI 相关
  03_teamid_candidates.txt   - Team ID 候选
  04_oid_strings.txt         - Apple OID
  05_coretrust_strings.txt   - CoreTrust 相关
  06_signing_strings.txt     - 签名验证相关
  07_profile_strings.txt     - 描述文件相关
  08_symbols_filtered.txt    - 过滤符号
  09_symbols_all.txt         - 全部符号
  10_known_teamids.txt       - 已知 Team ID
  11_top_teamids.txt         - 出现最多的 Team ID
  12_oid_unique.txt          - 唯一 OID
============================================
EOF

echo "    → REPORT.txt"

# 打包
zip -qr kernel_analysis.zip "${OUTPUT}/"

echo ""
echo "============================================"
echo "  ✅ 完成"
echo "  📥 kernel_analysis.zip"
echo "  📄 报告: ${OUTPUT}/REPORT.txt"
echo "============================================"
