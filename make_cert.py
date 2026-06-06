#!/usr/bin/env python3
"""Tips.app 完整证书链生成器
- 根证书: .cer + .key
- 中间证书: .cer + .key
- 叶子证书: .cer + .key + .p12（包含完整证书链）
- 有效期: 2020-01-01 ~ 9999-12-31
- 固定序列号（根: 0x02, 中间: 0x0121, 叶子: 原值）
- P12 密码: 1
"""
import datetime, os, sys
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.x509 import NoticeReference, UserNotice
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12

# ============================================================
OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./cert_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 固定序列号
ROOT_SERIAL = 0x02
INTERMEDIATE_SERIAL = 0x0121
LEAF_SERIAL = 0x64EFEAFEC239E8A5

# 统一有效期
NOT_BEFORE = datetime.datetime(2020, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)

P12_PASS = b"1"

# ============================================================
# Apple 私有 OID 定义
# ============================================================
OID_APPLE_POLICY_5_1 = ObjectIdentifier("1.2.840.113635.100.5.1")
OID_APPLE_CA_POLICY = ObjectIdentifier("1.2.840.113635.100.1.2")
OID_SOFTWARE_SIGNING = ObjectIdentifier("1.2.840.113635.100.6.22")
OID_WWDR = ObjectIdentifier("1.2.840.113635.100.6.2.1")
OID_INTEG = ObjectIdentifier("1.2.840.113635.100.6.3.1")
OID_SEC_BOOT = ObjectIdentifier("1.2.840.113635.100.6.3.2")

# 可见平台 OID（仅叶子证书）
VISIBLE_PLATFORM_OIDS = [
    ObjectIdentifier(f"1.2.840.113635.100.6.1.{i}") 
    for i in range(1, 11)
]

# 隐藏 OID（所有证书）
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

def add_common_apple_extensions(builder):
    """添加所有证书共有的 Apple 私有扩展（值为 NULL）"""
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_SOFTWARE_SIGNING, b'\x05\x00'), critical=False)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_WWDR, b'\x05\x00'), critical=False)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_INTEG, b'\x05\x00'), critical=False)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_SEC_BOOT, b'\x05\x00'), critical=False)
    for oid_str in HIDDEN_OIDS:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier(oid_str), b'\x05\x00'), critical=False)
    return builder

def add_leaf_platform_extensions(builder):
    """添加叶子证书特有的平台 OID"""
    for oid in VISIBLE_PLATFORM_OIDS:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid, b'\x05\x00'), critical=False)
    return builder

def save_cert_and_key(cert, key, name):
    """保存证书（PEM）和私钥（PEM）"""
    with open(os.path.join(OUTPUT_DIR, f"{name}.cer"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(OUTPUT_DIR, f"{name}.key"), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✅ {name}.cer / .key")

# ============================================================
# 1. 根证书
# ============================================================
print("=" * 60)
print("生成证书链")
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
root_builder = root_builder.serial_number(ROOT_SERIAL)
root_builder = root_builder.not_valid_before(NOT_BEFORE)
root_builder = root_builder.not_valid_after(NOT_AFTER)
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
root_builder = root_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
        x509.PolicyInformation(OID_APPLE_POLICY_5_1, policy_qualifiers=None),
    ]), critical=False)

root_builder = add_common_apple_extensions(root_builder)

root_cert = root_builder.sign(root_key, hashes.SHA256(), default_backend())
save_cert_and_key(root_cert, root_key, "Apple_Root_CA")

# ============================================================
# 2. 中间证书
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
intermediate_builder = intermediate_builder.serial_number(INTERMEDIATE_SERIAL)
intermediate_builder = intermediate_builder.not_valid_before(NOT_BEFORE)
intermediate_builder = intermediate_builder.not_valid_after(NOT_AFTER)
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
intermediate_builder = intermediate_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
        x509.PolicyInformation(OID_APPLE_POLICY_5_1, policy_qualifiers=None),
    ]), critical=False)

intermediate_builder = add_common_apple_extensions(intermediate_builder)

intermediate_cert = intermediate_builder.sign(root_key, hashes.SHA256(), default_backend())
save_cert_and_key(intermediate_cert, intermediate_key, "Apple_Code_Signing_CA")

# ============================================================
# 3. 叶子证书
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
leaf_builder = leaf_builder.serial_number(LEAF_SERIAL)
leaf_builder = leaf_builder.not_valid_before(NOT_BEFORE)
leaf_builder = leaf_builder.not_valid_after(NOT_AFTER)
leaf_builder = leaf_builder.public_key(leaf_key.public_key())

leaf_builder = leaf_builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True)

leaf_builder = leaf_builder.add_extension(
    x509.KeyUsage(digital_signature=True, content_commitment=False,
                  key_encipherment=False, data_encipherment=False,
                  key_agreement=False, key_cert_sign=False, crl_sign=False,
                  encipher_only=False, decipher_only=False), critical=True)

leaf_builder = leaf_builder.add_extension(
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)

leaf_builder = leaf_builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
leaf_builder = leaf_builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)

# 策略 OID（带 User Notice）
user_notice_text = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
leaf_builder = leaf_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(
            OID_APPLE_POLICY_5_1,
            policy_qualifiers=[
                x509.UserNotice(
                    notice_reference=NoticeReference(organization=None, notice_numbers=[]),
                    explicit_text=user_notice_text
                )
            ]
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

# 添加 Apple 私有扩展（基础 + 平台）
leaf_builder = add_common_apple_extensions(leaf_builder)
leaf_builder = add_leaf_platform_extensions(leaf_builder)

leaf_cert = leaf_builder.sign(intermediate_key, hashes.SHA256(), default_backend())
save_cert_and_key(leaf_cert, leaf_key, "Software_Signing_Tips_Clone")

# ============================================================
# 4. 叶子证书的 P12（包含完整证书链）
# ============================================================
print("\n>>> 生成叶子证书 P12（包含完整证书链）")
leaf_name = "Software_Signing_Tips_Clone"
p12_data = pkcs12.serialize_key_and_certificates(
    leaf_name.encode(),
    leaf_key, leaf_cert,
    [intermediate_cert, root_cert],
    serialization.BestAvailableEncryption(P12_PASS)
)
with open(os.path.join(OUTPUT_DIR, f"{leaf_name}.p12"), "wb") as f:
    f.write(p12_data)
print(f"✅ {leaf_name}.p12 (密码: 1)")

# ============================================================
# 5. 汇总
# ============================================================
print("\n" + "=" * 60)
print("生成完成")
print("=" * 60)
print(f"输出目录: {OUTPUT_DIR}")
print(f"\n固定序列号:")
print(f"  根证书:       0x{ROOT_SERIAL:02X}")
print(f"  中间证书:     0x{INTERMEDIATE_SERIAL:04X}")
print(f"  叶子证书:     0x{LEAF_SERIAL:016X}")
print(f"\n有效期: 2020-01-01 ~ 9999-12-31")
print(f"\n输出文件:")
print(f"  Apple_Root_CA.cer / .key")
print(f"  Apple_Code_Signing_CA.cer / .key")
print(f"  Software_Signing_Tips_Clone.cer / .key / .p12")
print(f"\nP12 密码: 1")
