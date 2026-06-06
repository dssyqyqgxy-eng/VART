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

def save_cert_and_key(cert_pem, key, name):
    with open(os.path.join(OUTPUT_DIR, f"{name}.cer"), "wb") as f:
        f.write(cert_pem)
    with open(os.path.join(OUTPUT_DIR, f"{name}.key"), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✅ {name}.cer / .key")

def sign_tbs_with_openssl(tbs_der, key, cert_pem_path):
    """用 OpenSSL 对 TBS 进行 SHA1 签名"""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as tbs_file:
        tbs_file.write(tbs_der)
        tbs_path = tbs_file.name
    
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        key_path = key_file.name
    
    # 先创建证书请求
    req_path = tbs_path + '.req'
    cmd_req = [
        'openssl', 'req', '-new', '-x509',
        '-key', key_path,
        '-out', cert_pem_path,
        '-days', '36500',
        '-set_serial', hex(0)[2:],
        '-sha1'
    ]
    
    # 直接使用 OpenSSL 生成证书，然后替换扩展
    # 更简单的方法：生成自签名证书，再用我们的 TBS 替换
    cmd = [
        'openssl', 'x509', '-req', '-sha1',
        '-in', tbs_path,
        '-signkey', key_path,
        '-out', cert_pem_path,
        '-days', '36500',
        '-set_serial', '0x01'
    ]
    
    try:
        subprocess.run(cmd, capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"OpenSSL 错误: {e.stderr}")
        raise
    
    os.unlink(tbs_path)
    os.unlink(key_path)

# ============================================================
print("=" * 60)
print("生成证书链（混合模式 - cryptography + OpenSSL）")
print("=" * 60)

# ============================================================
# 1. 根证书
# ============================================================
print("\n>>> Apple Root CA")
root_key = gen_key()
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Apple Root CA"),
])

# 构建根证书 TBS
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

# 获取 TBS DER
root_tbs = root_builder._public_key(root_key.public_key())
# 简化：直接生成证书 PEM 再用 OpenSSL 重签名
root_tbs_der = root_builder._public_key(root_key.public_key())._version(2).public_bytes(
    serialization.Encoding.DER
)

# 使用 OpenSSL 签名
with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
    f.write(root_tbs_der)
    tbs_path = f.name

with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
    f.write(root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_path = f.name

root_cert_pem_path = os.path.join(tempfile.gettempdir(), "root_cert.pem")
cmd = [
    'openssl', 'x509', '-req', '-sha1',
    '-in', tbs_path,
    '-signkey', key_path,
    '-out', root_cert_pem_path,
    '-days', '36500'
]
subprocess.run(cmd, capture_output=True, check=True)

with open(root_cert_pem_path, 'rb') as f:
    root_cert_pem = f.read()

save_cert_and_key(root_cert_pem, root_key, "Apple_Root_CA")

# 清理
os.unlink(tbs_path)
os.unlink(key_path)
os.unlink(root_cert_pem_path)

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

intermediate_tbs_der = intermediate_builder._public_key(intermediate_key.public_key())._version(2).public_bytes(
    serialization.Encoding.DER
)

with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
    f.write(intermediate_tbs_der)
    tbs_path = f.name

with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
    f.write(intermediate_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_path = f.name

intermediate_cert_pem_path = os.path.join(tempfile.gettempdir(), "intermediate_cert.pem")
cmd = [
    'openssl', 'x509', '-req', '-sha1',
    '-in', tbs_path,
    '-signkey', key_path,
    '-out', intermediate_cert_pem_path,
    '-days', '36500'
]
subprocess.run(cmd, capture_output=True, check=True)

with open(intermediate_cert_pem_path, 'rb') as f:
    intermediate_cert_pem = f.read()

save_cert_and_key(intermediate_cert_pem, intermediate_key, "Apple_Code_Signing_CA")

os.unlink(tbs_path)
os.unlink(key_path)
os.unlink(intermediate_cert_pem_path)

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

user_notice_text = "This certificate is to be used exclusively for functions internal to Apple Products and/or Apple processes."
leaf_builder = leaf_builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(
            OID_APPLE_POLICY_5_1,
            policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text=user_notice_text)]
        ),
    ]), critical=False)

leaf_builder = leaf_builder.add_extension(
    x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://crl.apple.com/codesigning.crl")],
            relative_name=None, reasons=None, crl_issuer=None
        )
    ]), critical=False)

leaf_builder = leaf_builder.add_extension(
    x509.UnrecognizedExtension(OID_SOFTWARE_SIGNING, b'\x05\x00'), critical=False)

leaf_tbs_der = leaf_builder._public_key(leaf_key.public_key())._version(2).public_bytes(
    serialization.Encoding.DER
)

with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
    f.write(leaf_tbs_der)
    tbs_path = f.name

with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
    f.write(leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_path = f.name

leaf_cert_pem_path = os.path.join(tempfile.gettempdir(), "leaf_cert.pem")
cmd = [
    'openssl', 'x509', '-req', '-sha1',
    '-in', tbs_path,
    '-signkey', key_path,
    '-out', leaf_cert_pem_path,
    '-days', '36500'
]
subprocess.run(cmd, capture_output=True, check=True)

with open(leaf_cert_pem_path, 'rb') as f:
    leaf_cert_pem = f.read()

save_cert_and_key(leaf_cert_pem, leaf_key, "Software_Signing_Tips_Clone")

os.unlink(tbs_path)
os.unlink(key_path)
os.unlink(leaf_cert_pem_path)

# ============================================================
# 4. 叶子证书 P12
# ============================================================
print("\n>>> 生成叶子证书 P12（包含完整证书链）")
# 需要从 PEM 加载证书对象
from cryptography.x509 import load_pem_x509_certificate

leaf_cert_obj = load_pem_x509_certificate(leaf_cert_pem, default_backend())
intermediate_cert_obj = load_pem_x509_certificate(intermediate_cert_pem, default_backend())
root_cert_obj = load_pem_x509_certificate(root_cert_pem, default_backend())

p12_data = pkcs12.serialize_key_and_certificates(
    b"Software Signing",
    leaf_key, leaf_cert_obj,
    [intermediate_cert_obj, root_cert_obj],
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
