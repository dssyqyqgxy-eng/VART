#!/bin/bash
# macOS 完整签名验证分析
# 分析所有可能参与代码签名验证的组件

OUTPUT="signing_analysis"
mkdir -p "${OUTPUT}"

echo "============================================"
echo "  macOS 签名验证框架分析"
echo "============================================"

# ============================================================
# 1. amfid - 核心验证守护进程
# ============================================================
echo ">>> [1/6] amfid..."

AMFID="/usr/libexec/amfid"
if [ -f "${AMFID}" ]; then
    strings "${AMFID}" | grep -oE '[A-Z][A-Z0-9]{9}' | sort | uniq -c | sort -rn | head -20 > "${OUTPUT}/amfid_teamid.txt"
    strings "${AMFID}" | grep "1.2.840.113635" | sort -u > "${OUTPUT}/amfid_oid.txt"
    strings "${AMFID}" | grep -iE "team|trust|verify|cert|valid|evaluate|policy" > "${OUTPUT}/amfid_strings.txt"
    echo "    ✅ amfid 完成"
else
    echo "    ⚠️  未找到 amfid"
fi

# ============================================================
# 2. Security.framework - 证书/信任框架
# ============================================================
echo ">>> [2/6] Security.framework..."

SEC="/System/Library/Frameworks/Security.framework/Versions/A/Security"
if [ -f "${SEC}" ]; then
    strings "${SEC}" | grep -oE '[A-Z][A-Z0-9]{9}' | sort | uniq -c | sort -rn | head -20 > "${OUTPUT}/security_teamid.txt"
    strings "${SEC}" | grep "1.2.840.113635" | sort -u > "${OUTPUT}/security_oid.txt"
    strings "${SEC}" | grep -iE "coretrust|trustcache|anchor|evaluate" > "${OUTPUT}/security_trust.txt"
    echo "    ✅ Security 完成"
fi

# ============================================================
# 3. MobileCoreServices (LaunchServices)
# ============================================================
echo ">>> [3/6] LaunchServices..."

LS="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/LaunchServices"
if [ -f "${LS}" ]; then
    strings "${LS}" | grep -oE '[A-Z][A-Z0-9]{9}' | sort | uniq -c | sort -rn | head -20 > "${OUTPUT}/ls_teamid.txt"
    strings "${LS}" | grep -iE "teamid|registration|install|validate" > "${OUTPUT}/ls_strings.txt"
    echo "    ✅ LaunchServices 完成"
fi

# ============================================================
# 4. dyld - 动态链接器
# ============================================================
echo ">>> [4/6] dyld..."

DYLD="/usr/lib/dyld"
if [ -f "${DYLD}" ]; then
    strings "${DYLD}" | grep -iE "teamid|amfi|codesign|trustcache" > "${OUTPUT}/dyld_strings.txt"
    echo "    ✅ dyld 完成"
fi

# ============================================================
# 5. trustd - 信任评估守护进程
# ============================================================
echo ">>> [5/6] trustd..."

TRUSTD="/usr/libexec/trustd"
if [ -f "${TRUSTD}" ]; then
    strings "${TRUSTD}" | grep -oE '[A-Z][A-Z0-9]{9}' | sort | uniq -c | sort -rn | head -20 > "${OUTPUT}/trustd_teamid.txt"
    strings "${TRUSTD}" | grep "1.2.840.113635" | sort -u > "${OUTPUT}/trustd_oid.txt"
    echo "    ✅ trustd 完成"
fi

# ============================================================
# 6. 全局搜索已知 Team ID
# ============================================================
echo ">>> [6/6] 全局搜索已知 Team ID..."

> "${OUTPUT}/all_known_teamids.txt"
for id in 59GAB85EFG SKMME9E2Y7 0000000000 APPLETEAM EQHXZ8M8AV; do
    total=0
    for f in "${AMFID}" "${SEC}" "${LS}" "${DYLD}" "${TRUSTD}"; do
        if [ -f "$f" ]; then
            c=$(strings "$f" 2>/dev/null | grep -c "$id" || echo 0)
            total=$((total + c))
        fi
    done
    printf "%-15s: %d 次\n" "${id}" "${total}" | tee -a "${OUTPUT}/all_known_teamids.txt"
done

# ============================================================
# 打包
# ============================================================
zip -qr signing_analysis.zip "${OUTPUT}/"

echo ""
echo "============================================"
echo "  ✅ signing_analysis.zip"
echo "============================================"
