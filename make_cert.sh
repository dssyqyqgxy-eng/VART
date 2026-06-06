#!/bin/bash
# ============================================================
# Tips.app 完整证书链生成器（无删减完整版）
# ============================================================

OUTPUT_DIR="${1:-./cert_output}"
mkdir -p "$OUTPUT_DIR"

# ============================================================
# 根证书配置
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
# 中间证书配置
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
# 叶子证书配置（包含所有 OID 和 UserNotice）
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
echo "有效期: 2020-01-01 ~ 9999-12-31"
echo "序列号: 根=0x02, 中间=0x0121, 叶子=0x64EFEAFEC239E8A5"
echo "============================================================"

# ============================================================
# 1. 根证书
# ============================================================
echo ""
echo "[1/4] 生成 Apple Root CA"

openssl genrsa -out "$OUTPUT_DIR/Apple_Root_CA.key" 2048
openssl req -x509 -new -key "$OUTPUT_DIR/Apple_Root_CA.key" -out "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -days 3650000 -set_serial 0x02 \
  -config "$OUTPUT_DIR/root.cnf" -extensions v3_ca

# 修改有效期
openssl x509 -in "$OUTPUT_DIR/Apple_Root_CA.cer" -out "$OUTPUT_DIR/Apple_Root_CA_fixed.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
mv "$OUTPUT_DIR/Apple_Root_CA_fixed.cer" "$OUTPUT_DIR/Apple_Root_CA.cer"

echo "  ✅ Apple_Root_CA.cer / .key"

# ============================================================
# 2. 中间证书
# ============================================================
echo ""
echo "[2/4] 生成 Apple Code Signing Certification Authority"

openssl genrsa -out "$OUTPUT_DIR/Apple_Code_Signing_CA.key" 2048
openssl req -new -key "$OUTPUT_DIR/Apple_Code_Signing_CA.key" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -config "$OUTPUT_DIR/intermediate.cnf"

openssl x509 -req -in "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  -CA "$OUTPUT_DIR/Apple_Root_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Root_CA.key" \
  -days 3650000 -set_serial 0x0121 \
  -config "$OUTPUT_DIR/intermediate.cnf" -extensions v3_ca

# 修改有效期
openssl x509 -in "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -out "$OUTPUT_DIR/Apple_Code_Signing_CA_fixed.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
mv "$OUTPUT_DIR/Apple_Code_Signing_CA_fixed.cer" "$OUTPUT_DIR/Apple_Code_Signing_CA.cer"

echo "  ✅ Apple_Code_Signing_CA.cer / .key"

# ============================================================
# 3. 叶子证书
# ============================================================
echo ""
echo "[3/4] 生成 Software Signing (Tips.app 克隆版)"

openssl genrsa -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" 2048
openssl req -new -key "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -config "$OUTPUT_DIR/leaf.cnf"

openssl x509 -req -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -CA "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -days 3650000 -set_serial 0x64EFEAFEC239E8A5 \
  -config "$OUTPUT_DIR/leaf.cnf" -extensions v3_leaf

# 修改有效期
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone_fixed.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
mv "$OUTPUT_DIR/Software_Signing_Tips_Clone_fixed.cer" "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer"

echo "  ✅ Software_Signing_Tips_Clone.cer / .key"

# ============================================================
# 4. 生成 P12
# ============================================================
echo ""
echo "[4/4] 生成 P12（包含私钥 + 完整证书链）"

cat "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Apple_Root_CA.cer" > "$OUTPUT_DIR/fullchain.pem"

openssl pkcs12 -export -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" \
  -inkey "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -certfile "$OUTPUT_DIR/fullchain.pem" \
  -passout pass:1 \
  -name "Software Signing"

echo "  ✅ Software_Signing_Tips_Clone.p12 (密码: 1)"

# ============================================================
# 清理
# ============================================================
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/fullchain.pem "$OUTPUT_DIR"/*.cnf

# ============================================================
# 验证
# ============================================================
echo ""
echo "============================================================"
echo "验证有效期"
echo "============================================================"
echo "根证书:"
openssl x509 -in "$OUTPUT_DIR/Apple_Root_CA.cer" -noout -dates
echo ""
echo "中间证书:"
openssl x509 -in "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -noout -dates
echo ""
echo "叶子证书:"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -noout -dates

echo ""
echo "============================================================"
echo "验证叶子证书 OID"
echo "============================================================"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -text -noout | grep -E "([0-9]+\.)+[0-9]+"

echo ""
echo "============================================================"
echo "生成完成"
echo "============================================================"
echo "输出目录: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR" | grep -E "\.(cer|key|p12)$"
echo ""
echo "P12 密码: 1"
echo "============================================================"
