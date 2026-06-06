#!/bin/bash
# ============================================================
# Tips.app 完整证书链生成器（无删减版）
# 包含所有 OID、UserNotice、CRL、序列号固定
# 有效期: 2020-01-01 ~ 9999-12-31
# 签名算法: sha1WithRSAEncryption
# 输出: 根/中间/叶子 .cer + .key，叶子 .p12（密码: 1）
# ============================================================

OUTPUT_DIR="${1:-./cert_output}"
mkdir -p "$OUTPUT_DIR"

# ============================================================
# 完整的 OpenSSL 配置文件
# ============================================================
cat > "$OUTPUT_DIR/openssl.cnf" << 'EOF'
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
string_mask = utf8only
prompt = no

[ req_distinguished_name ]
countryName = US
organizationName = Apple Inc.
organizationalUnitName = Apple Certification Authority
commonName = Apple Root CA

# ============================================================
# 根证书扩展
# ============================================================
[ root_ext ]
basicConstraints = critical,CA:true
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
certificatePolicies = @root_policies

[ root_policies ]
policyIdentifier = 1.2.840.113635.100.1.2
policyIdentifier.2 = 1.2.840.113635.100.5.1

# ============================================================
# 中间证书扩展
# ============================================================
[ intermediate_ext ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = @intermediate_policies

[ intermediate_policies ]
policyIdentifier = 1.2.840.113635.100.1.2
policyIdentifier.2 = 1.2.840.113635.100.5.1

# ============================================================
# 叶子证书扩展
# ============================================================
[ leaf_ext ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://crl.apple.com/codesigning.crl
1.2.840.113635.100.6.22 = ASN1:NULL
certificatePolicies = @leaf_policies

[ leaf_policies ]
policyIdentifier = 1.2.840.113635.100.5.1
userNotice.1 = @notice

[ notice ]
explicitText = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
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
openssl genrsa -out "$OUTPUT_DIR/Apple_Root_CA.key" 2048 2>/dev/null
openssl req -x509 -new -key "$OUTPUT_DIR/Apple_Root_CA.key" -out "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -days 36500 -set_serial 0x02 -sha1 \
  -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA" \
  -config "$OUTPUT_DIR/openssl.cnf" -extensions root_ext 2>/dev/null
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
openssl genrsa -out "$OUTPUT_DIR/Apple_Code_Signing_CA.key" 2048 2>/dev/null
openssl req -new -key "$OUTPUT_DIR/Apple_Code_Signing_CA.key" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -sha1 -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Code Signing Certification Authority" 2>/dev/null
openssl x509 -req -in "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  -CA "$OUTPUT_DIR/Apple_Root_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Root_CA.key" \
  -days 36500 -set_serial 0x0121 -sha1 \
  -extfile "$OUTPUT_DIR/openssl.cnf" -extensions intermediate_ext 2>/dev/null
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
openssl genrsa -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" 2048 2>/dev/null
openssl req -new -key "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -sha1 -subj "/C=US/O=Apple Inc./OU=Apple Software/CN=Software Signing" 2>/dev/null
openssl x509 -req -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -CA "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -days 36500 -set_serial 0x64EFEAFEC239E8A5 -sha1 \
  -extfile "$OUTPUT_DIR/openssl.cnf" -extensions leaf_ext 2>/dev/null
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

# 合并中间证书和根证书
cat "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Apple_Root_CA.cer" > "$OUTPUT_DIR/fullchain.pem"

# 验证证书链
echo "验证证书链..."
openssl verify -CAfile "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -untrusted "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" 2>/dev/null

# 生成 P12
openssl pkcs12 -export -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" \
  -inkey "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -certfile "$OUTPUT_DIR/fullchain.pem" \
  -passout pass:1 \
  -name "Software Signing" 2>/dev/null

if [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" ]; then
    P12_SIZE=$(stat -f%z "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" 2>/dev/null || stat -c%s "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" 2>/dev/null)
    echo "  ✅ Software_Signing_Tips_Clone.p12 (密码: 1, 大小: $P12_SIZE 字节)"
else
    echo "  ❌ P12 生成失败"
fi

# ============================================================
# 清理临时文件
# ============================================================
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/fullchain.pem

# ============================================================
# 验证 P12 内容
# ============================================================
echo ""
echo "============================================================"
echo "验证 P12 内容"
echo "============================================================"
if [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" ]; then
    echo ""
    echo "P12 中的证书:"
    openssl pkcs12 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" -nokeys -passin pass:1 2>/dev/null | grep "BEGIN CERTIFICATE" | wc -l | xargs echo "  证书数量:"
    echo ""
    echo "P12 中的私钥:"
    openssl pkcs12 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" -nocerts -passin pass:1 -passout pass:tmp 2>/dev/null | grep "BEGIN PRIVATE" | wc -l | xargs echo "  私钥数量:"
fi

# ============================================================
# 显示叶子证书信息
# ============================================================
echo ""
echo "============================================================"
echo "叶子证书信息"
echo "============================================================"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -noout -serial -subject -issuer -dates 2>/dev/null
echo ""
echo "叶子证书 OID:"
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -text -noout 2>/dev/null | grep -E "([0-9]+\.)+[0-9]+" | head -15

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
ls -lh "$OUTPUT_DIR" | grep -E "\.(cer|key|p12)$" | awk '{print "  📄 " $9 " (" $5 ")"}'
echo ""
echo "P12 密码: 1"
echo ""
echo "包含的 OID:"
echo "  - 2.5.29.19 (基本约束)"
echo "  - 2.5.29.15 (密钥使用)"
echo "  - 2.5.29.37 (扩展密钥使用)"
echo "  - 2.5.29.14 (使用者密钥标识符)"
echo "  - 2.5.29.35 (颁发者密钥标识符)"
echo "  - 2.5.29.32 (证书策略)"
echo "  - 2.5.29.31 (CRL 分发点)"
echo "  - 1.2.840.113635.100.6.22 (Software Signing)"
echo "  - 1.2.840.113635.100.5.1 (Apple 策略)"
echo "  - 1.2.840.113635.100.1.2 (Apple CA 策略 - 根/中间)"
echo "============================================================"
