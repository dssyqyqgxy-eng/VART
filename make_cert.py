#!/usr/bin/env python3
"""Tips.app 叶子证书完整克隆生成器
- 包含所有 Apple 私有 OID（可见 + 隐藏）
- 完全复制原证书的结构、策略、CRL
- 有效期: 1600-01-01 ~ 9999-12-31
- 序列号: 固定为原证书序列号
- 包含代码签名、密钥用途、CRL 分发点
"""
import datetime, os, sys
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ============================================================
OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./cert_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 原证书的固定序列号
FIXED_SERIAL = 0x64EFEAFEC239E8A5

# ============================================================
# Apple 私有 OID 定义
# ============================================================
# 策略 OID
OID_APPLE_POLICY_5_1 = ObjectIdentifier("1.2.840.113635.100.5.1")
OID_APPLE_CA_POLICY = ObjectIdentifier("1.2.840.113635.100.1.2")

# Software Signing 标识 OID
OID_SOFTWARE_SIGNING = ObjectIdentifier("1.2.840.113635.100.6.22")

# 可见平台 OID (1.2.840.113635.100.6.1.x)
VISIBLE_PLATFORM_OIDS = [
    ObjectIdentifier(f"1.2.840.113635.100.6.1.{i}") 
    for i in range(1, 11)  # 1-10
]

# 隐藏 OID
HIDDEN_OIDS = [
    "1.2.840.113635.100.1.115",
    "1.2.840.113635.100.6.86",
    "1.2.840.113635.100.6.87",
    "1.2.840.113635.100.6.27.11.1",
    "1.2.840.113635.100.6.27.18",
    "1.2.840.113635.100.6.1.14",
    "1.2.840.113635.100.6.1.21",
    "1.2.840.113635.100.6.1.22",
    "1.2.840.113635.100.6.1.25",
    "1.2.840.113635.100.6.1.13",
    "1.2.840.113635.100.6.2.10",
    "1.2.840.113635.100.6.51",
    "1.3.6.1.5.5.7.1.12",
]

def gen_key(bits=2048):
    return rsa.generate_private_key(65537, bits, default_backend())

def add_apple_extensions(builder):
    """添加所有 Apple 私有扩展（值为 NULL）"""
    # 可见平台 OID
    for oid in VISIBLE_PLATFORM_OIDS:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid, b'\x05\x00'), critical=False)
    
    # 隐藏 OID
    for oid_str in HIDDEN_OIDS:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier(oid_str), b'\x05\x00'), critical=False)
    
    # Software Signing 标识 OID
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_SOFTWARE_SIGNING, b'\x05\x00'), critical=False)
    
    return builder

# ============================================================
# 1. 生成根证书
# ============================================================
print("=" * 60)
print("Tips.app 完整克隆证书链")
print("有效期: 1600-01-01 ~ 9999-12-31")
print("序列号: 固定 (原证书)")
print("=" * 60)

root_key = gen_key()
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Apple Root CA"),
])

root_builder = x509.CertificateBuilder()
root_builder = root_builder.subject_name(root_subject)
root_builder = root_builder.issuer_name(root_subject)
root_builder = root_builder.serial_number(x509.random_serial_number())
root_builder = root_builder.not_valid_before(datetime.datetime(1600, 1, 1, tzinfo=datetime.timezone.utc))
root_builder = root_builder.not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc))
root_builder = root_builder.public_key(root_key.public_key())
root_builder = root_builder.add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True)
root_builder = root_builder.add_extension(
    x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                  content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False,
                  encipher_only=False, decipher_only=False), critical=True)
root_builder = root_builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
# 根证书添加 Apple CA 策略
root_builder = root_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
    ]), critical=False)

root_cert = root_builder.sign(root_key, hashes.SHA256(), default_backend())

with open(os.path.join(OUTPUT_DIR, "Apple_Root_CA.cer"), "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.PEM))
print("✅ Apple_Root_CA.cer")

# ============================================================
# 2. 生成中间证书
# ============================================================
print("\n>>> Apple Code Signing Certification Authority")
intermediate_key = gen_key()
intermediate_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Apple Code Signing Certification Authority"),
])

intermediate_builder = x509.CertificateBuilder()
intermediate_builder = intermediate_builder.subject_name(intermediate_subject)
intermediate_builder = intermediate_builder.issuer_name(root_subject)
intermediate_builder = intermediate_builder.serial_number(x509.random_serial_number())
intermediate_builder = intermediate_builder.not_valid_before(datetime.datetime(1600, 1, 1, tzinfo=datetime.timezone.utc))
intermediate_builder = intermediate_builder.not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc))
intermediate_builder = intermediate_builder.public_key(intermediate_key.public_key())
intermediate_builder = intermediate_builder.add_extension(
    x509.BasicConstraints(ca=True, path_length=0), critical=True)
intermediate_builder = intermediate_builder.add_extension(
    x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                  content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False,
                  encipher_only=False, decipher_only=False), critical=True)
intermediate_builder = intermediate_builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)
intermediate_builder = intermediate_builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)

intermediate_cert = intermediate_builder.sign(root_key, hashes.SHA256(), default_backend())

with open(os.path.join(OUTPUT_DIR, "Apple_Code_Signing_CA.cer"), "wb") as f:
    f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
print("✅ Apple_Code_Signing_CA.cer")

# ============================================================
# 3. 生成叶子证书 (Software Signing)
# ============================================================
print("\n>>> Software Signing (Tips.app 克隆版)")
leaf_key = gen_key()
leaf_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Software"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Software Signing"),
])

leaf_builder = x509.CertificateBuilder()
leaf_builder = leaf_builder.subject_name(leaf_subject)
leaf_builder = leaf_builder.issuer_name(intermediate_subject)
leaf_builder = leaf_builder.serial_number(FIXED_SERIAL)  # 固定序列号
leaf_builder = leaf_builder.not_valid_before(datetime.datetime(1600, 1, 1, tzinfo=datetime.timezone.utc))
leaf_builder = leaf_builder.not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc))
leaf_builder = leaf_builder.public_key(leaf_key.public_key())

# 基本约束
leaf_builder = leaf_builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True)

# 密钥用途 (critical) - 只有数字签名
leaf_builder = leaf_builder.add_extension(
    x509.KeyUsage(digital_signature=True, content_commitment=False,
                  key_encipherment=False, data_encipherment=False,
                  key_agreement=False, key_cert_sign=False, crl_sign=False,
                  encipher_only=False, decipher_only=False), critical=True)

# 扩展密钥用途 (critical) - 代码签名
leaf_builder = leaf_builder.add_extension(
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)

# 密钥标识
leaf_builder = leaf_builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
leaf_builder = leaf_builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)

# 策略 OID 1.2.840.113635.100.5.1 (带 User Notice)
# 原证书中的文本
user_notice_text = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
leaf_builder = leaf_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(
            OID_APPLE_POLICY_5_1,
            policy_qualifiers=[x509.UserNotice(notice_text=user_notice_text)]
        ),
    ]), critical=False)

# CRL 分发点
leaf_builder = leaf_builder.add_extension(
    x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://crl.apple.com/codesigning.crl")],
            relative_name=None, reasons=None, crl_issuer=None
        )
    ]), critical=False)

# 添加所有 Apple 私有扩展
leaf_builder = add_apple_extensions(leaf_builder)

leaf_cert = leaf_builder.sign(intermediate_key, hashes.SHA256(), default_backend())

# 保存叶子证书
leaf_name = "Software_Signing_Tips_Clone"
with open(os.path.join(OUTPUT_DIR, f"{leaf_name}.cer"), "wb") as f:
    f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
with open(os.path.join(OUTPUT_DIR, f"{leaf_name}.der"), "wb") as f:
    f.write(leaf_cert.public_bytes(serialization.Encoding.DER))
print(f"✅ {leaf_name}.cer / .der")

# ============================================================
# 4. 生成 P12
# ============================================================
print("\n>>> 生成 P12")
from cryptography.hazmat.primitives.serialization import pkcs12
p12_pass = b"1"
p12_data = pkcs12.serialize_key_and_certificates(
    b"Software Signing",
    leaf_key, leaf_cert,
    [intermediate_cert, root_cert],
    serialization.BestAvailableEncryption(p12_pass)
)
with open(os.path.join(OUTPUT_DIR, f"{leaf_name}.p12"), "wb") as f:
    f.write(p12_data)
print(f"✅ {leaf_name}.p12 (密码: 1)")

# ============================================================
# 5. 输出汇总
# ============================================================
print("\n" + "=" * 60)
print("生成完成")
print("=" * 60)
print(f"输出目录: {OUTPUT_DIR}")
print(f"\n包含的 OID:")
print(f"  - 1.2.840.113635.100.5.1 (策略，带 User Notice)")
print(f"  - 1.2.840.113635.100.6.22 (Software Signing 标识, NULL)")
for oid in VISIBLE_PLATFORM_OIDS[:3]:
    print(f"  - {oid} (平台, NULL)")
print(f"  - ... 共 {len(VISIBLE_PLATFORM_OIDS)} 个可见 OID")
print(f"  - ... 共 {len(HIDDEN_OIDS)} 个隐藏 OID")
print(f"\nCRL 分发点: http://crl.apple.com/codesigning.crl")
