#!/bin/bash
# ============================================================
# Tips.app 完整证书链生成器（带调试）
# ============================================================

OUTPUT_DIR="${1:-./cert_output}"
mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "Tips.app 完整证书链生成器"
echo "输出目录: $OUTPUT_DIR"
echo "============================================================"

# 创建叶子证书配置文件
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

# 1. 根证书
echo ""
echo "[1/4] 生成 Apple Root CA"
openssl genrsa -out "$OUTPUT_DIR/Apple_Root_CA.key" 2048 2>/dev/null
openssl req -x509 -new -key "$OUTPUT_DIR/Apple_Root_CA.key" -out "$OUTPUT_DIR/Apple_Root_CA_tmp.cer" \
  -days 36500 -set_serial 0x02 -sha1 \
  -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" 2>/dev/null
openssl x509 -in "$OUTPUT_DIR/Apple_Root_CA_tmp.cer" -out "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z 2>/dev/null
rm -f "$OUTPUT_DIR/Apple_Root_CA_tmp.cer"
echo "  ✅ Apple_Root_CA.cer / .key"

# 2. 中间证书
echo ""
echo "[2/4] 生成 Apple Code Signing CA"
openssl genrsa -out "$OUTPUT_DIR/Apple_Code_Signing_CA.key" 2048 2>/dev/null
openssl req -new -key "$OUTPUT_DIR/Apple_Code_Signing_CA.key" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Code Signing Certification Authority" 2>/dev/null
openssl x509 -req -in "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" -out "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer" \
  -CA "$OUTPUT_DIR/Apple_Root_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Root_CA.key" \
  -days 36500 -set_serial 0x0121 -sha1 \
  -extfile <(echo -e "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,digitalSignature,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid") 2>/dev/null
openssl x509 -in "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z 2>/dev/null
rm -f "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer"
echo "  ✅ Apple_Code_Signing_CA.cer / .key"

# 3. 叶子证书
echo ""
echo "[3/4] 生成 Software Signing 叶子证书"
openssl genrsa -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" 2048 2>/dev/null
openssl req -new -key "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -config "$OUTPUT_DIR/leaf.cnf" 2>/dev/null
openssl x509 -req -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer" \
  -CA "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -days 36500 -set_serial 0x64EFEAFEC239E8A5 -sha1 \
  -extfile "$OUTPUT_DIR/leaf.cnf" -extensions v3_leaf 2>/dev/null
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z 2>/dev/null
rm -f "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer"
echo "  ✅ Software_Signing_Tips_Clone.cer / .key"

# 4. 生成 P12
echo ""
echo "[4/4] 生成 P12（包含私钥 + 完整证书链）"

# 显示当前目录文件
echo "当前目录文件列表:"
ls -la "$OUTPUT_DIR/"

# 合并证书链
cat "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Apple_Root_CA.cer" > "$OUTPUT_DIR/fullchain.pem"

# 检查文件是否创建成功
if [ ! -f "$OUTPUT_DIR/fullchain.pem" ]; then
    echo "  ❌ fullchain.pem 创建失败"
    exit 1
fi

if [ ! -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" ]; then
    echo "  ❌ 私钥文件不存在"
    exit 1
fi

if [ ! -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" ]; then
    echo "  ❌ 叶子证书不存在"
    exit 1
fi

# 生成 P12
echo "正在生成 P12..."
openssl pkcs12 -export -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" \
  -inkey "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -certfile "$OUTPUT_DIR/fullchain.pem" \
  -passout pass:1 \
  -name "Software Signing"

# 检查 P12
if [ -f "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" ]; then
    P12_SIZE=$(stat -f%z "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" 2>/dev/null || stat -c%s "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" 2>/dev/null)
    echo "  ✅ Software_Signing_Tips_Clone.p12 (密码: 1, 大小: $P12_SIZE 字节)"
else
    echo "  ❌ P12 生成失败"
    exit 1
fi

# 清理
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/fullchain.pem "$OUTPUT_DIR"/*.cnf

# 最终文件列表
echo ""
echo "============================================================"
echo "生成完成"
echo "============================================================"
echo "最终文件:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "P12 密码: 1"
echo "============================================================"
