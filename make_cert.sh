#!/bin/bash
# ============================================================
# Tips.app 完整证书链生成器（无删减完整版）
# 包含：根证书、中间证书、叶子证书
# 所有 OID：1.2.840.113635.100.1.2, 1.2.840.113635.100.5.1, 1.2.840.113635.100.6.22
# UserNotice 完整文本
# CRL 分发点
# 序列号固定：根=02, 中间=0121, 叶子=64EFEAFEC239E8A5
# 有效期：2020-01-01 到 9999-12-31
# 签名算法：sha1WithRSAEncryption
# 输出：Apple_Root_CA.cer/.key, Apple_Code_Signing_CA.cer/.key, Software_Signing_Tips_Clone.cer/.key/.p12
# P12 密码：1
# ============================================================

OUTPUT_DIR="${1:-./cert_output}"
mkdir -p "$OUTPUT_DIR"

# ============================================================
# 1. 根证书配置文件
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
# 2. 中间证书配置文件
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
# 3. 叶子证书配置文件（包含所有 OID 和 UserNotice）
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
userNotice.1 = @notice

[notice]
explicitText = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
EOF

echo "============================================================"
echo "Tips.app 完整证书链生成器"
echo "============================================================"
echo "有效期: 2020-01-01 ~ 9999-12-31"
echo "序列号: 根=0x02, 中间=0x0121, 叶子=0x64EFEAFEC239E8A5"
echo "签名算法: sha1WithRSAEncryption"
echo "P12 密码: 1"
echo "============================================================"

# ============================================================
# 生成根证书
# ============================================================
echo ""
echo "[1/5] 生成 Apple Root CA 私钥"
openssl genrsa -out "$OUTPUT_DIR/Apple_Root_CA.key" 2048
echo ""

echo "[2/5] 生成 Apple Root CA 证书"
openssl req -x509 -new -key "$OUTPUT_DIR/Apple_Root_CA.key" -out "$OUTPUT_DIR/Apple_Root_CA_tmp.cer" \
  -days 36500 -set_serial 0x02 -sha1 \
  -config "$OUTPUT_DIR/root.cnf" -extensions v3_ca

# 修改根证书有效期
openssl x509 -in "$OUTPUT_DIR/Apple_Root_CA_tmp.cer" -out "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
rm -f "$OUTPUT_DIR/Apple_Root_CA_tmp.cer"
echo "  ✅ Apple_Root_CA.cer"
echo "  ✅ Apple_Root_CA.key"

# ============================================================
# 生成中间证书
# ============================================================
echo ""
echo "[3/5] 生成 Apple Code Signing CA 证书"
openssl genrsa -out "$OUTPUT_DIR/Apple_Code_Signing_CA.key" 2048
openssl req -new -key "$OUTPUT_DIR/Apple_Code_Signing_CA.key" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -config "$OUTPUT_DIR/intermediate.cnf"
openssl x509 -req -in "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" -out "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer" \
  -CA "$OUTPUT_DIR/Apple_Root_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Root_CA.key" \
  -days 36500 -set_serial 0x0121 -sha1 \
  -config "$OUTPUT_DIR/intermediate.cnf" -extensions v3_ca

# 修改中间证书有效期
openssl x509 -in "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
rm -f "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer"
echo "  ✅ Apple_Code_Signing_CA.cer"
echo "  ✅ Apple_Code_Signing_CA.key"

# ============================================================
# 生成叶子证书
# ============================================================
echo ""
echo "[4/5] 生成 Software Signing 叶子证书"
openssl genrsa -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" 2048
openssl req -new -key "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -config "$OUTPUT_DIR/leaf.cnf"
openssl x509 -req -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer" \
  -CA "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -days 36500 -set_serial 0x64EFEAFEC239E8A5 -sha1 \
  -config "$OUTPUT_DIR/leaf.cnf" -extensions v3_leaf

# 修改叶子证书有效期
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
rm -f "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer"
echo "  ✅ Software_Signing_Tips_Clone.cer"
echo "  ✅ Software_Signing_Tips_Clone.key"

# ============================================================
# 生成 P12（包含私钥 + 完整证书链）
# ============================================================
echo ""
echo "[5/5] 生成 P12 文件（包含私钥 + 完整证书链）"

# 合并完整证书链
cat "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Apple_Root_CA.cer" > "$OUTPUT_DIR/fullchain.pem"

# 生成 P12
openssl pkcs12 -export -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" \
  -inkey "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -certfile "$OUTPUT_DIR/fullchain.pem" \
  -passout pass:1 \
  -name "Software Signing"

echo "  ✅ Software_Signing_Tips_Clone.p12 (密码: 1)"

# ============================================================
# 清理临时文件
# ============================================================
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/fullchain.pem

# ============================================================
# 验证 P12 内容
# ============================================================
echo ""
echo "============================================================"
echo "验证 P12 文件内容"
echo "============================================================"
echo ""
echo "P12 中的证书数量:"
openssl pkcs12 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" -nokeys -passin pass:1 2>/dev/null | grep -c "BEGIN CERTIFICATE"
echo ""
echo "P12 中的私钥:"
openssl pkcs12 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" -nocerts -passin pass:1 -passout pass:tmp 2>/dev/null | grep -c "BEGIN PRIVATE"
echo ""
echo "P12 文件大小:"
ls -lh "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" | awk '{print "  " $5}'

# ============================================================
# 验证证书链
# ============================================================
echo ""
echo "============================================================"
echo "验证证书链"
echo "============================================================"
openssl verify -CAfile "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -untrusted "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer"

# ============================================================
# 显示所有 OID
# ============================================================
echo ""
echo "============================================================"
echo "叶子证书包含的 OID"
echo "============================================================"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -text -noout | grep -E "([0-9]+\.)+[0-9]+"

# ============================================================
# 汇总
# ============================================================
echo ""
echo "============================================================"
echo "生成完成"
echo "============================================================"
echo "输出目录: $OUTPUT_DIR"
echo ""
echo "输出文件:"
ls -lh "$OUTPUT_DIR" | grep -E "\.(cer|key|p12)$" | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo "P12 密码: 1"
echo "============================================================"
