#!/bin/bash
# 2020-01-01 到 9999-12-31 证书生成脚本

OUTPUT_DIR="${1:-./cert_output}"
mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "Tips.app 证书链生成器 (2020-9999)"
echo "============================================================"

# 创建叶子证书扩展配置
cat > "$OUTPUT_DIR/leaf.conf" << 'EOF'
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
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
echo ">>> 根证书"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUTPUT_DIR/Apple_Root_CA.key" \
  -out "$OUTPUT_DIR/Apple_Root_CA_tmp.cer" \
  -days 36500 -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# 修改根证书有效期
openssl x509 -in "$OUTPUT_DIR/Apple_Root_CA_tmp.cer" -out "$OUTPUT_DIR/Apple_Root_CA.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
rm -f "$OUTPUT_DIR/Apple_Root_CA_tmp.cer"

# 2. 中间证书
echo ">>> 中间证书"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -out "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Code Signing Certification Authority"

openssl x509 -req -in "$OUTPUT_DIR/Apple_Code_Signing_CA.csr" \
  -out "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer" \
  -CA "$OUTPUT_DIR/Apple_Root_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Root_CA.key" \
  -days 36500 \
  -extfile <(echo "basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,digitalSignature,keyCertSign,cRLSign")

# 修改中间证书有效期
openssl x509 -in "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer" -out "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
rm -f "$OUTPUT_DIR/Apple_Code_Signing_CA_tmp.cer"

# 3. 叶子证书
echo ">>> 叶子证书"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -subj "/C=US/O=Apple Inc./OU=Apple Software/CN=Software Signing"

openssl x509 -req -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.csr" \
  -out "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer" \
  -CA "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -CAkey "$OUTPUT_DIR/Apple_Code_Signing_CA.key" \
  -days 36500 \
  -extfile "$OUTPUT_DIR/leaf.conf"

# 修改叶子证书有效期
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer" -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -setstart 20200101000000Z -setend 99991231235959Z
rm -f "$OUTPUT_DIR/Software_Signing_Tips_Clone_tmp.cer"

# 4. 生成 P12
echo ">>> 生成 P12"
cat "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" "$OUTPUT_DIR/Apple_Root_CA.cer" > "$OUTPUT_DIR/chain.pem"
openssl pkcs12 -export -out "$OUTPUT_DIR/Software_Signing_Tips_Clone.p12" \
  -inkey "$OUTPUT_DIR/Software_Signing_Tips_Clone.key" \
  -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" \
  -certfile "$OUTPUT_DIR/chain.pem" \
  -passout pass:1 \
  -name "Software Signing"

# 清理
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/chain.pem

echo "============================================================"
echo "完成！有效期验证："
openssl x509 -in "$OUTPUT_DIR/Apple_Root_CA.cer" -noout -dates
openssl x509 -in "$OUTPUT_DIR/Apple_Code_Signing_CA.cer" -noout -dates
openssl x509 -in "$OUTPUT_DIR/Software_Signing_Tips_Clone.cer" -noout -dates
echo "============================================================"
