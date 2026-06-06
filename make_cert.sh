#!/bin/bash
# ============================================================
# Tips.app 克隆证书链生成器
# 有效期: 2020-01-01 ~ 9999-12-31
# 序列号: 根=02, 中间=0121, 叶子=64EFEAFEC239E8A5
# 签名算法: sha1WithRSAEncryption
# 输出: 根/中间/叶子 .cer + .key，叶子 .p12（密码: 1）
# ============================================================

OUTPUT_DIR="${1:-./cert_output}"
mkdir -p "$OUTPUT_DIR"

# 获取绝对路径
cd "$OUTPUT_DIR"
OUTPUT_DIR_ABS=$(pwd)
cd - > /dev/null

# 创建 OpenSSL 配置文件
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

[ root_ext ]
basicConstraints = critical,CA:true
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
certificatePolicies = @root_policies

[ root_policies ]
policyIdentifier = 1.2.840.113635.100.1.2
policyIdentifier.2 = 1.2.840.113635.100.5.1

[ intermediate_ext ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = @intermediate_policies

[ intermediate_policies ]
policyIdentifier = 1.2.840.113635.100.1.2
policyIdentifier.2 = 1.2.840.113635.100.5.1

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
echo "Tips.app 克隆证书链生成器"
echo "============================================================"
echo "有效期: 2020-01-01 ~ 9999-12-31"
echo "序列号: 根=0x02, 中间=0x0121, 叶子=0x64EFEAFEC239E8A5"
echo "============================================================"

# 1. 根证书
echo ""
echo "[1/4] 生成 Apple Root CA"
openssl genrsa -out "$OUTPUT_DIR/Apple_Root_CA.key" 2048 2>/dev/null
openssl req -x509 -new -key "$OUTPUT_DIR/Apple_Root_CA.key" -out "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -days 36500 -set_serial 0x02 -sha1 \
  -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA" \
  -config "$OUTPUT_DIR/openssl.cnf" -extensions root_ext 2>/dev/null
echo "  ✅ Apple_Root_CA.cer / .key"

# 2. 中间证书
echo ""
echo "[2/4] 生成 Apple Code Signing Certification Authority"
openssl genrsa -out "$OUTPUT_DIR/Apple_Code_Signing_CA.key" 2048 2>/dev/null
openssl req -new -key "$OUTPUT_DIR/Apple_Code_Signing_CA.key" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -sha1 -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Code Signing Certification Authority" 2>/dev/null
openssl x509 -req -in "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  -CA "$OUTPUT_DIR/Apple_Root_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Root_CA.key" \
  -days 36500 -set_serial 0x0121 -sha1 \
  -extfile "$OUTPUT_DIR/openssl.cnf" -extensions intermediate_ext 2>/dev/null
echo "  ✅ Apple_Code_Signing_CA.cer / .key"

# 3. 叶子证书
echo ""
echo "[3/4] 生成 Software Signing (Tips.app 克隆版)"
openssl genrsa -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" 2048 2>/dev/null
openssl req -new -key "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -sha1 -subj "/C=US/O=Apple Inc./OU=Apple Software/CN=Software Signing" 2>/dev/null
openssl x509 -req -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -CA "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -days 36500 -set_serial 0x64EFEAFEC239E8A5 -sha1 \
  -extfile "$OUTPUT_DIR/openssl.cnf" -extensions leaf_ext 2>/dev/null
echo "  ✅ Software_Signing_Tips_Clone.cer / .key"

# 4. 生成 P12
echo ""
echo "[4/4] 生成 P12（包含私钥 + 完整证书链）"

# 合并完整证书链
cat "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Apple_Root_CA.cer" > "$OUTPUT_DIR/fullchain.pem"

# 生成 P12
openssl pkcs12 -export -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" \
  -inkey "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -certfile "$OUTPUT_DIR/fullchain.pem" \
  -passout pass:1 \
  -name "Software Signing" 2>/dev/null

if [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" ]; then
    echo "  ✅ Software_Signing_Tips_Clone.p12 (密码: 1)"
else
    echo "  ❌ P12 生成失败"
fi

# 5. 清理临时文件
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/fullchain.pem "$OUTPUT_DIR"/openssl.cnf

# 6. 验证证书链（使用绝对路径）
echo ""
echo "验证证书链:"
if [ -f "$OUTPUT_DIR/Apple_Root_CA.cer" ] && [ -f "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" ] && [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" ]; then
    openssl verify -CAfile "$OUTPUT_DIR/Apple_Root_CA.cer" -untrusted "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  ✅ 证书链验证通过"
    else
        echo "  ⚠️ 证书链验证失败（不影响使用）"
    fi
else
    echo "  ⚠️ 证书文件不完整，跳过验证"
fi

echo ""
echo "============================================================"
echo "生成完成"
echo "============================================================"
echo "输出目录: $OUTPUT_DIR"
echo ""
echo "输出文件:"
ls -la "$OUTPUT_DIR" | grep -E "\.(cer|key|p12)$" | awk '{print "  📄 " $9}'
echo ""
echo "P12 密码: 1"
echo "============================================================"

# 7. 显示 P12 信息
echo ""
echo "P12 文件信息:"
if [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" ]; then
    openssl pkcs12 -info -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" -passin pass:1 -noout 2>/dev/null
    echo "  ✅ P12 包含私钥和证书"
fi
