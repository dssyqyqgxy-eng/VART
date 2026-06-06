#!/usr/bin/env python3
"""Tips.app 完整证书链生成器
- 统一有效期: 2020-01-01 ~ 9999-12-31
- 固定序列号（根: 0x02, 中间: 0x0121, 叶子: 0x64EFEAFEC239E8A5）
- 签名算法: sha1WithRSAEncryption
- 完整保留原证书所有 OID
- 输出: 根/中间/叶子 .cer + .key，叶子 .p12（密码: 1）
"""
import datetime, os, sys
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.x509 import UserNotice
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
NOT_BEFORE = datetime.datetime(2010, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
P12_PASS = b"1"

# Apple OID
OID_APPLE_CA_POLICY = ObjectIdentifier("1.2.840.113635.100.1.2")
OID_APPLE_POLICY_5_1 = ObjectIdentifier("1.2.840.113635.100.5.1")
OID_SOFTWARE_SIGNING = ObjectIdentifier("1.2.840.113635.100.6.22")

def gen_key(bits=2048):
    return rsa.generate_private_key(65537, bits, default_backend())

def save_cert_and_key(cert, key, name):
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

# 基本约束
root_builder = root_builder.add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True)

# 密钥使用
root_builder = root_builder.add_extension(
    x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                  content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False,
                  encipher_only=False, decipher_only=False), critical=True)

# 使用者密钥标识符
root_builder = root_builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)

# 证书策略（包含 1.2.840.113635.100.1.2 和 1.2.840.113635.100.5.1）
root_builder = root_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
        x509.PolicyInformation(OID_APPLE_POLICY_5_1, policy_qualifiers=None),
    ]), critical=False)

root_cert = root_builder.sign(root_key, hashes.SHA1(), default_backend())
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

# 基本约束
intermediate_builder = intermediate_builder.add_extension(
    x509.BasicConstraints(ca=True, path_length=0), critical=True)

# 密钥使用
intermediate_builder = intermediate_builder.add_extension(
    x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                  content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False,
                  encipher_only=False, decipher_only=False), critical=True)

# 使用者密钥标识符
intermediate_builder = intermediate_builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)

# 颁发者密钥标识符
intermediate_builder = intermediate_builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)

# 证书策略（包含 1.2.840.113635.100.1.2 和 1.2.840.113635.100.5.1）
intermediate_builder = intermediate_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
        x509.PolicyInformation(OID_APPLE_POLICY_5_1, policy_qualifiers=None),
    ]), critical=False)

intermediate_cert = intermediate_builder.sign(root_key, hashes.SHA1(), default_backend())
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

# 基本约束
leaf_builder = leaf_builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True)

# 密钥使用
leaf_builder = leaf_builder.add_extension(
    x509.KeyUsage(digital_signature=True, content_commitment=False,
                  key_encipherment=False, data_encipherment=False,
                  key_agreement=False, key_cert_sign=False, crl_sign=False,
                  encipher_only=False, decipher_only=False), critical=True)

# 扩展密钥使用
leaf_builder = leaf_builder.add_extension(
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)

# 使用者密钥标识符
leaf_builder = leaf_builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)

# 颁发者密钥标识符
leaf_builder = leaf_builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)

# 证书策略（包含 1.2.840.113635.100.5.1，不含 1.2）
user_notice_text = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
leaf_builder = leaf_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(
            OID_APPLE_POLICY_5_1,
            policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text=user_notice_text)]
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

# Software Signing OID
leaf_builder = leaf_builder.add_extension(
    x509.UnrecognizedExtension(OID_SOFTWARE_SIGNING, b'\x05\x00'), critical=False)

leaf_cert = leaf_builder.sign(intermediate_key, hashes.SHA1(), default_backend())
save_cert_and_key(leaf_cert, leaf_key, "Software_Signing_Tips_Clone")

# ============================================================
# 4. 叶子证书 P12
# ============================================================
print("\n>>> 生成叶子证书 P12（包含完整证书链）")
p12_data = pkcs12.serialize_key_and_certificates(
    b"Software Signing",
    leaf_key, leaf_cert,
    [intermediate_cert, root_cert],
    serialization.BestAvailableEncryption(P12_PASS)
)
with open(os.path.join(OUTPUT_DIR, "Software_Signing_Tips_Clone.p12"), "wb") as f:
    f.write(p12_data)
print("✅ Software_Signing_Tips_Clone.p12 (密码: 1)")

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
print(f"\n输出文件:")
print(f"  Apple_Root_CA.cer / .key")
print(f"  Apple_Code_Signing_CA.cer / .key")
print(f"  Software_Signing_Tips_Clone.cer / .key / .p12")
print(f"\nP12 密码: 1")
