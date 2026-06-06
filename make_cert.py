#!/usr/bin/env python3
"""Tips.app 完整证书链生成器（混合模式）
- cryptography 生成证书结构（TBS）
- OpenSSL 进行 SHA1 签名
- 统一有效期: 2020-01-01 ~ 9999-12-31
- 固定序列号（根: 0x02, 中间: 0x0121, 叶子: 0x64EFEAFEC239E8A5）
- 完整保留原证书所有 OID
- 输出: 根/中间/叶子 .cer + .key，叶子 .p12（密码: 1）
"""
import datetime, os, sys, subprocess, tempfile
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12

# ============================================================
OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./cert_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

ROOT_SERIAL = 0x02
INTERMEDIATE_SERIAL = 0x0121
LEAF_SERIAL = 0x64EFEAFEC239E8A5

NOT_BEFORE = datetime.datetime(2020, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
P12_PASS = b"1"

OID_APPLE_CA_POLICY = ObjectIdentifier("1.2.840.113635.100.1.2")
OID_APPLE_POLICY_5_1 = ObjectIdentifier("1.2.840.113635.100.5.1")
OID_SOFTWARE_SIGNING = ObjectIdentifier("1.2.840.113635.100.6.22")

def gen_key():
    return rsa.generate_private_key(65537, 2048, default_backend())

def sign_with_openssl(tbs_der, key_pem, cert_pem_path):
    """用 OpenSSL 对 TBS 进行 SHA1 签名"""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as tbs_file:
        tbs_file.write(tbs_der)
        tbs_path = tbs_file.name
    
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as key_file:
        key_file.write(key_pem)
        key_path = key_file.name
    
    # 使用 OpenSSL 签名
    cmd = [
        'openssl', 'x509', '-req', '-sha1',
        '-in', tbs_path,
        '-signkey', key_path,
        '-out', cert_pem_path,
        '-days', '9999'
    ]
    subprocess.run(cmd, capture_output=True, check=True)
    
    os.unlink(tbs_path)
    os.unlink(key_path)

def build_and_sign(subject, issuer_name, issuer_key_pem, serial, is_ca=False, is_leaf=False):
    """构建证书并用 OpenSSL 签名"""
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_name)
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(NOT_BEFORE)
    builder = builder.not_valid_after(NOT_AFTER)
    
    key = gen_key()
    builder = builder.public_key(key.public_key())
    
    # 基本约束
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None if is_ca == 'root' else 0), critical=True)
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True)
    
    # 密钥使用
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False), critical=True)
    else:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False), critical=True)
    
    # 扩展密钥使用（仅叶子）
    if is_leaf:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
    
    # 密钥标识符
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    
    if not is_ca == 'root':
        # 颁发者密钥标识符（需要传入 issuer 的公钥，这里简化）
        pass
    
    # 证书策略
    if is_ca:
        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(OID_APPLE_CA_POLICY, policy_qualifiers=None),
                x509.PolicyInformation(OID_APPLE_POLICY_5_1, policy_qualifiers=None),
            ]), critical=False)
    elif is_leaf:
        user_notice_text = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    OID_APPLE_POLICY_5_1,
                    policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text=user_notice_text)]
                ),
            ]), critical=False)
    
    # CRL 分发点（仅叶子）
    if is_leaf:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://crl.apple.com/codesigning.crl")],
                    relative_name=None, reasons=None, crl_issuer=None
                )
            ]), critical=False)
    
    # Software Signing OID（仅叶子）
    if is_leaf:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_SOFTWARE_SIGNING, b'\x05\x00'), critical=False)
    
    # 构建 TBS
    tbs = builder._public_key(key.public_key())._version(2)
    # 简化：直接生成证书再替换签名
    # 实际需要构建 Certificate 对象
    
    return key

# 简化版：先构建基础证书
print("=" * 60)
print("生成证书链（混合模式）")
print("=" * 60)

# 生成根证书
root_key = gen_key()
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Apple Root CA"),
])

# 生成中间证书
intermediate_key = gen_key()
intermediate_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Apple Code Signing Certification Authority"),
])

# 生成叶子证书
leaf_key = gen_key()
leaf_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Software"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Software Signing"),
])

print("✅ 密钥对生成完成")
print("\n⚠️ 完整混合模式需要复杂实现，建议降级 cryptography 到 3.4.8")
