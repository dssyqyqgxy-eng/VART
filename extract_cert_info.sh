#!/bin/bash
# 从开发者证书提取 OID 和完整信息
# 用法: ./extract_cert_info.sh

set -e

CERT="开发者证书.p12"
OUTPUT="cert_extracted"

mkdir -p "${OUTPUT}"

if [ ! -f "${CERT}" ]; then
    echo "❌ 未找到 ${CERT}，请放到项目根目录"
    exit 1
fi

echo "============================================"
echo "  开发者证书分析"
echo "============================================"
echo ">>> 证书: ${CERT}"

# ============================================================
# 1. 导出叶子证书（尝试多种密码）
# ============================================================
echo ">>> [1] 导出证书..."

# 尝试空密码
openssl pkcs12 -in "${CERT}" -clcerts -nokeys -passin pass:"" -out "${OUTPUT}/cert.pem" 2>/dev/null && echo "    密码: 空" && FOUND=1

# 尝试密码 1
if [ -z "${FOUND}" ]; then
    openssl pkcs12 -in "${CERT}" -clcerts -nokeys -passin pass:"1" -out "${OUTPUT}/cert.pem" 2>/dev/null && echo "    密码: 1" && FOUND=1
fi

# 尝试无密码保护
if [ -z "${FOUND}" ]; then
    openssl pkcs12 -in "${CERT}" -clcerts -nokeys -nodes -out "${OUTPUT}/cert.pem" 2>/dev/null && echo "    无密码保护" && FOUND=1
fi

if [ -z "${FOUND}" ]; then
    echo "    ❌ 无法提取证书，请手动输入密码"
    openssl pkcs12 -in "${CERT}" -clcerts -nokeys -out "${OUTPUT}/cert.pem"
fi

echo "    ✅ cert.pem"

# 导出完整链
openssl pkcs12 -in "${CERT}" -nokeys -nodes -out "${OUTPUT}/fullchain.pem" 2>/dev/null || true

# ============================================================
# 2. OID 提取
# ============================================================
echo ">>> [2] Apple OID..."

> "${OUTPUT}/oid_all.txt"
echo "--- Apple 自定义 OID ---" >> "${OUTPUT}/oid_all.txt"
openssl x509 -in "${OUTPUT}/cert.pem" -text -noout | grep "1.2.840.113635" >> "${OUTPUT}/oid_all.txt" 2>/dev/null || true

echo "--- 所有扩展 OID ---" >> "${OUTPUT}/oid_all.txt"
openssl x509 -in "${OUTPUT}/cert.pem" -text -noout | grep -A1 "Extension" >> "${OUTPUT}/oid_all.txt" 2>/dev/null || true

cat "${OUTPUT}/oid_all.txt"

OID_COUNT=$(grep -c "1.2.840" "${OUTPUT}/oid_all.txt" 2>/dev/null || echo 0)
echo "    找到 ${OID_COUNT} 个 Apple OID"

# ============================================================
# 3. Team ID
# ============================================================
echo ""
echo ">>> [3] Team ID..."

openssl x509 -in "${OUTPUT}/cert.pem" -subject -noout > "${OUTPUT}/subject_raw.txt" 2>/dev/null || true
grep -oE 'OU ?= ?[A-Z0-9]+' "${OUTPUT}/subject_raw.txt" > "${OUTPUT}/teamid.txt" 2>/dev/null || true

cat "${OUTPUT}/teamid.txt"

# ============================================================
# 4. 基本信息
# ============================================================
echo ""
echo ">>> [4] 基本信息..."

openssl x509 -in "${OUTPUT}/cert.pem" -subject -noout | tee "${OUTPUT}/subject.txt"
openssl x509 -in "${OUTPUT}/cert.pem" -issuer -noout | tee "${OUTPUT}/issuer.txt"
openssl x509 -in "${OUTPUT}/cert.pem" -serial -noout | tee "${OUTPUT}/serial.txt"
openssl x509 -in "${OUTPUT}/cert.pem" -dates -noout | tee "${OUTPUT}/dates.txt"
openssl x509 -in "${OUTPUT}/cert.pem" -fingerprint -sha256 -noout | tee "${OUTPUT}/fingerprint.txt"

# ============================================================
# 5. 完整证书信息
# ============================================================
echo ""
echo ">>> [5] 完整证书..."

openssl x509 -in "${OUTPUT}/cert.pem" -text -noout > "${OUTPUT}/cert_full.txt"
echo "    ✅ cert_full.txt"

# ============================================================
# 6. 打包
# ============================================================
echo ""
echo ">>> [6] 打包..."

zip -qr cert_extracted.zip "${OUTPUT}/"

echo ""
echo "============================================"
echo "  ✅ cert_extracted.zip"
echo "============================================"
