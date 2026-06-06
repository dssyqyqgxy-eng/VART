#!/bin/bash
# ============================================================
# Tips.app 完整证书链生成器（无删减版）
# 有效期: 2020-01-01 ~ 9999-12-31
# 序列号: 根=02, 中间=0121, 叶子=64EFEAFEC239E8A5
# 签名算法: sha1WithRSAEncryption
# 输出: 根/中间/叶子 .cer + .key，叶子 .p12（密码: 1）
# ============================================================

OUTPUT_DIR="${1:-./cert_output}"
mkdir -p "$OUTPUT_DIR"

# ============================================================
# 创建根证书配置文件
# ============================================================
cat > "$OUTPUT_DIR/root.cnf" << 'EOF'
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only

[ req_distinguished_name ]
C = US
O = Apple Inc.
OU = Apple Certification Authority
CN = Apple Root CA

[ v3_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
certificatePolicies = 1.2.840.113635.100.1.2, 1.2.840.113635.100.5.1
EOF

# ============================================================
# 创建中间证书配置文件
# ============================================================
cat > "$OUTPUT_DIR/intermediate.cnf" << 'EOF'
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only

[ req_distinguished_name ]
C = US
O = Apple Inc.
OU = Apple Certification Authority
CN = Apple Code Signing Certification Authority

[ v3_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = 1.2.840.113635.100.1.2, 1.2.840.113635.100.5.1
EOF

# ============================================================
# 创建叶子证书配置文件（完整 OID）
# ============================================================
cat > "$OUTPUT_DIR/leaf.cnf" << 'EOF'
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only

[ req_distinguished_name ]
C = US
O = Apple Inc.
OU = Apple Software
CN = Software Signing

[ v3_leaf ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://crl.apple.com/codesigning.crl
1.2.840.113635.100.6.22 = ASN1:NULL
certificatePolicies = @pol

[pol]
policyIdentifier = 1.2.840.113635.100.5.1
CPS.1 = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
EOF

echo "============================================================"
echo "Tips.app 完整证书链生成器"
echo "============================================================"
echo "有效期: 2020-01-01 ~ 9999-12-31"
echo "序列号: 根=0x02, 中间=0x0121, 叶子=0x64EFEAFEC239E8A5"
echo "签名算法: sha1WithRSAEncryption"
echo "============================================================"

# ============================================================
# 1. 根证书
# ============================================================
echo ""
echo "[1/4] 生成 Apple Root CA"

openssl genrsa -out "$OUTPUT_DIR/Apple_Root_CA.key" 2048
if [ $? -ne 0 ]; then
    echo "  ❌ 生成私钥失败"
    exit 1
fi

openssl req -x509 -new -key "$OUTPUT_DIR/Apple_Root_CA.key" -out "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -days 36500 -set_serial 0x02 -sha1 \
  -config "$OUTPUT_DIR/root.cnf" -extensions v3_ca

if [ -f "$OUTPUT_DIR/Apple_Root_CA.cer" ]; then
    echo "  ✅ Apple_Root_CA.cer"
    echo "  ✅ Apple_Root_CA.key"
else
    echo "  ❌ 根证书生成失败"
    exit 1
fi

# ============================================================
# 2. 中间证书
# ============================================================
echo ""
echo "[2/4] 生成 Apple Code Signing Certification Authority"

openssl genrsa -out "$OUTPUT_DIR/Apple_Code_Signing_CA.key" 2048
if [ $? -ne 0 ]; then
    echo "  ❌ 生成私钥失败"
    exit 1
fi

openssl req -new -key "$OUTPUT_DIR/Apple_Code_Signing_CA.key" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -sha1 -config "$OUTPUT_DIR/intermediate.cnf"

openssl x509 -req -in "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  -CA "$OUTPUT_DIR/Apple_Root_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Root_CA.key" \
  -days 36500 -set_serial 0x0121 -sha1 \
  -extfile "$OUTPUT_DIR/intermediate.cnf" -extensions v3_ca

if [ -f "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" ]; then
    echo "  ✅ Apple_Code_Signing_CA.cer"
    echo "  ✅ Apple_Code_Signing_CA.key"
else
    echo "  ❌ 中间证书生成失败"
    exit 1
fi

# ============================================================
# 3. 叶子证书
# ============================================================
echo ""
echo "[3/4] 生成 Software Signing (Tips.app 克隆版)"

openssl genrsa -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" 2048
if [ $? -ne 0 ]; then
    echo "  ❌ 生成私钥失败"
    exit 1
fi

openssl req -new -key "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -sha1 -config "$OUTPUT_DIR/leaf.cnf"

openssl x509 -req -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -CA "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -days 36500 -set_serial 0x64EFEAFEC239E8A5 -sha1 \
  -extfile "$OUTPUT_DIR/leaf.cnf" -extensions v3_leaf

if [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" ]; then
    echo "  ✅ Software_Signing_Tips_Clone.cer"
    echo "  ✅ Software_Signing_Tips_Clone.key"
else
    echo "  ❌ 叶子证书生成失败"
    exit 1
fi

# ============================================================
# 4. 生成 P12（包含私钥 + 完整证书链）
# ============================================================
echo ""
echo "[4/4] 生成 P12（包含私钥 + 完整证书链）"

# 合并完整证书链
cat "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Apple_Root_CA.cer" > "$OUTPUT_DIR/chain.pem"

# 生成 P12
openssl pkcs12 -export -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" \
  -inkey "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -certfile "$OUTPUT_DIR/chain.pem" \
  -passout pass:1 \
  -name "Software Signing"

if [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" ]; then
    P12_SIZE=$(stat -f%z "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" 2>/dev/null || stat -c%s "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" 2>/dev/null)
    echo "  ✅ Software_Signing_Tips_Clone.p12 (密码: 1, 大小: $P12_SIZE 字节)"
else
    echo "  ❌ P12 生成失败"
fi

# ============================================================
# 清理临时文件
# ============================================================
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/chain.pem

# ============================================================
# 验证证书
# ============================================================
echo ""
echo "============================================================"
echo "验证证书"
echo "============================================================"

echo ""
echo "根证书序列号:"
openssl x509 -in "$OUTPUT_DIR/Apple_Root_CA.cer" -noout -serial

echo ""
echo "中间证书序列号:"
openssl x509 -in "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -noout -serial

echo ""
echo "叶子证书序列号:"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -noout -serial

echo ""
echo "叶子证书 OID:"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -text -noout | grep -E "([0-9]+\.)+[0-9]+" | head -20

echo ""
echo "叶子证书 UserNotice:"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -text -noout | grep -A 3 "User Notice"

echo ""
echo "证书链验证:"
openssl verify -CAfile "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -untrusted "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer"

# ============================================================
# 汇总
# ============================================================
echo ""
echo "============================================================"
echo "生成完成"
echo "============================================================"
echo "输出目录: $OUTPUT_DIR"
echo ""
ls -lh "$OUTPUT_DIR" | grep -E "\.(cer|key|p12)$" | awk '{print "  📄 " $9 " (" $5 ")"}'
echo ""
echo "P12 密码: 1"
echo "============================================================"
