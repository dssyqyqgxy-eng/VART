#!/usr/bin/env python3
"""
Tips.app 完整证书链生成器
有效期: 2020-01-01 ~ 9999-12-31
签名算法: sha1WithRSAEncryption
输出: 根/中间/叶子 .cer + .key，叶子 .p12（密码: 1）
"""
import datetime, os, sys
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.x509 import UserNotice
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

# ============================================================
OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./cert_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 固定序列号
ROOT_SERIAL = 0x02
INTERMEDIATE_SERIAL = 0x0121
LEAF_SERIAL = 0x64EFEAFEC239E8A5

# 固定有效期
NOT_BEFORE = datetime.datetime(2020, 1, 1, 0, 0, 0)
NOT_AFTER = datetime.datetime(9999, 12, 31, 23, 59, 59)

# Apple OID
OID_APPLE_CA_POLICY = ObjectIdentifier("1.2.840.113635.100.1.2")
OID_APPLE_POLICY_5_1 = ObjectIdentifier("1.2.840.113635.100.5.1")
OID_SOFTWARE_SIGNING = ObjectIdentifier("1.2.840.113635.100.6.22")

def gen_key():
    return rsa.generate_private_key(65537, 2048)

def save_cert_and_key(cert, key, name):
    with open(os.path.join(OUTPUT_DIR, f"{name}.cer"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(OUTPUT_DIR, f"{name}.key"), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"  ✅ {name}.cer / .key")

# ============================================================
print("=" * 60)
print("Tips.app 完整证书链生成器")
print(f"有效期: {NOT_BEFORE.date()} ~ {NOT_AFTER.date()}")
print(f"序列号: 根=0x{ROOT_SERIAL:02X}, 中间=0x{INTERMEDIATE_SERIAL:04X}, 叶子=0x{LEAF_SERIAL:016X}")
print("=" * 60)

# 1. 根证书
print("\n[1/4] 生成 Apple Root CA")
root_key = gen_key()
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Apple Root CA"),
])
root_cert = (
    x509.CertificateBuilder()
    .subject_name(root_subject)
    .issuer_name(root_subject)
    .public_key(root_key.public_key())
    .serial_number(ROOT_SERIAL)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                      content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False,
                      encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
    .add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
            x509.PolicyInformation(OID_APPLE_POLICY_5_1, policy_qualifiers=None),
        ]), critical=False)
    .sign(root_key, hashes.SHA1())
)
save_cert_and_key(root_cert, root_key, "Apple_Root_CA")

# 2. 中间证书
print("\n[2/4] 生成 Apple Code Signing Certification Authority")
intermediate_key = gen_key()
intermediate_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Apple Code Signing Certification Authority"),
])
intermediate_cert = (
    x509.CertificateBuilder()
    .subject_name(intermediate_subject)
    .issuer_name(root_subject)
    .public_key(intermediate_key.public_key())
    .serial_number(INTERMEDIATE_SERIAL)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(
        x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                      content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False,
                      encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
    .add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
            x509.PolicyInformation(OID_APPLE_POLICY_5_1, policy_qualifiers=None),
        ]), critical=False)
    .sign(root_key, hashes.SHA1())
)
save_cert_and_key(intermediate_cert, intermediate_key, "Apple_Code_Signing_CA")

# 3. 叶子证书
print("\n[3/4] 生成 Software Signing (Tips.app 克隆版)")
leaf_key = gen_key()
leaf_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Software"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Software Signing"),
])
leaf_cert = (
    x509.CertificateBuilder()
    .subject_name(leaf_subject)
    .issuer_name(intermediate_subject)
    .public_key(leaf_key.public_key())
    .serial_number(LEAF_SERIAL)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=False), critical=True)
    .add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)
    .add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.apple.com/codesigning.crl")],
                relative_name=None, reasons=None, crl_issuer=None
            )
        ]), critical=False)
    .add_extension(x509.UnrecognizedExtension(OID_SOFTWARE_SIGNING, b'\x05\x00'), critical=False)
    .add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                OID_APPLE_POLICY_5_1,
                policy_qualifiers=[UserNotice(notice_reference=None, explicit_text="This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes.")]
            )
        ]), critical=False)
    .sign(intermediate_key, hashes.SHA1())
)
save_cert_and_key(leaf_cert, leaf_key, "Software_Signing_Tips_Clone")

# 4. P12
print("\n[4/4] 生成 P12（包含私钥 + 完整证书链）")
p12_data = pkcs12.serialize_key_and_certificates(
    b"Software Signing",
    leaf_key, leaf_cert,
    [intermediate_cert, root_cert],
    serialization.BestAvailableEncryption(b"1")
)
with open(os.path.join(OUTPUT_DIR, "Software_Signing_Tips_Clone.p12"), "wb") as f:
    f.write(p12_data)
print("  ✅ Software_Signing_Tips_Clone.p12 (密码: 1)")

# 验证
print("\n" + "=" * 60)
print("验证证书有效期")
print("=" * 60)
print(f"根证书: {root_cert.not_valid_before.date()} ~ {root_cert.not_valid_after.date()}")
print(f"中间证书: {intermediate_cert.not_valid_before.date()} ~ {intermediate_cert.not_valid_after.date()}")
print(f"叶子证书: {leaf_cert.not_valid_before.date()} ~ {leaf_cert.not_valid_after.date()}")

print("\n" + "=" * 60)
print("生成完成")
print("=" * 60)
print(f"输出目录: {OUTPUT_DIR}")
print("\n输出文件:")
for f in os.listdir(OUTPUT_DIR):
    if f.endswith(('.cer', '.key', '.p12')):
        print(f"  📄 {f}")
print("\nP12 密码: 1")
print("=" * 60)
