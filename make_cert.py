#!/usr/bin/env python3
"""漏洞测试证书生成 + Mac 强制信任验证"""
import datetime, os, sys, subprocess, shutil
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ============================================================
# 配置 - 和之前一样
# ============================================================
TEAM_ID = sys.argv[1] if len(sys.argv) > 1 else "59GAB85EFG"
OUTPUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "./cert_output"
CERT_PASS = "1"
DAYS = 2912000

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# OID 定义
# ============================================================
OID_ROOT_GENERIC   = ObjectIdentifier("1.2.840.113635.100.1.2")
OID_ROOT_CODESIGN  = ObjectIdentifier("1.2.840.113635.100.1.108")
OID_ROOT_PRIVATE   = ObjectIdentifier("1.2.840.113635.100.1.115")
OID_POLICY_5_1     = ObjectIdentifier("1.2.840.113635.100.5.1")
OID_APPLE_ISSUED_1 = ObjectIdentifier("1.2.840.113635.100.6.86")
OID_APPLE_ISSUED_2 = ObjectIdentifier("1.2.840.113635.100.6.87")
OID_PROD_MARK      = ObjectIdentifier("1.2.840.113635.100.6.27.11.1")
OID_LEAF_MARK      = ObjectIdentifier("1.2.840.113635.100.6.27.18")
OID_IPA_SIGNING    = ObjectIdentifier("1.2.840.113635.100.6.1.13")
OID_WWDR           = ObjectIdentifier("1.2.840.113635.100.6.2.1")
OID_INTEG          = ObjectIdentifier("1.2.840.113635.100.6.3.1")
OID_SEC_BOOT       = ObjectIdentifier("1.2.840.113635.100.6.3.2")
OID_1_x = [ObjectIdentifier(f"1.2.840.113635.100.6.1.{i}") for i in 
           [1,2,3,4,5,6,7,8,9,10,14,21,22,25]]

# 测试专用 OID
OID_UNKNOWN_CRITICAL = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
OID_CUSTOM_POLICY    = ObjectIdentifier("1.3.6.1.4.1.99999.2.1")
MALICIOUS_OCSP_URL   = "http://10.255.255.1/ocsp"

RESULTS = []

# ============================================================
# 工具函数
# ============================================================
def gen_key(bits=2048):
    return rsa.generate_private_key(65537, bits, default_backend())

def write_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.TraditionalOpenSSL,
                 serialization.NoEncryption()))

def write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def write_cert_der(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

# ============================================================
# 强制信任验证
# ============================================================
def verify_with_forced_trust(cert_path, test_name):
    """将证书导入临时钥匙串并强制信任，然后验证"""
    print(f"\n🔍 测试: {test_name}")
    
    tmp_keychain = os.path.join(OUTPUT_DIR, f"tmp_{hash(test_name) % 10000}.keychain")
    tmp_password = "test123"
    
    try:
        # 清理旧钥匙串
        subprocess.run(["security", "delete-keychain", tmp_keychain],
                      capture_output=True, stderr=subprocess.DEVNULL)
        subprocess.run(["rm", "-rf", tmp_keychain + "-db"], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        
        # 创建新钥匙串
        result = subprocess.run(
            ["security", "create-keychain", "-p", tmp_password, tmp_keychain],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  ❌ 创建钥匙串失败: {result.stderr.strip()}")
            RESULTS.append((test_name, "❌ 钥匙串创建失败", result.stderr))
            return
        
        # 解锁
        subprocess.run(
            ["security", "unlock-keychain", "-p", tmp_password, tmp_keychain],
            capture_output=True, text=True
        )
        
        # 设为默认搜索列表
        subprocess.run(
            ["security", "list-keychains", "-d", "user", "-s", tmp_keychain],
            capture_output=True, text=True
        )
        
        # 导入证书
        result = subprocess.run(
            ["security", "add-certificates", "-k", tmp_keychain, cert_path],
            capture_output=True, text=True
        )
        if "error" in result.stderr.lower() or result.returncode != 0:
            print(f"  ❌ 导入失败: {result.stderr.strip()}")
            RESULTS.append((test_name, "❌ 导入失败", result.stderr))
            restore_keychains()
            return
        
        # 强制信任
        cert_name = os.path.basename(cert_path)
        result = subprocess.run(
            ["security", "add-trusted-cert", "-r", "trustRoot", 
             "-p", "ssl", "-p", "basic", "-p", "codeSign",
             "-k", tmp_keychain, cert_path],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  ⚠️  设置信任失败（继续测试）: {result.stderr.strip()}")
        
        # 验证
        result = subprocess.run(
            ["security", "verify-cert", "-k", tmp_keychain, "-c", cert_path],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        
        if "certificate verification successful" in output.lower():
            print(f"  ✅ 验证通过！可能触发了宽松机制")
            RESULTS.append((test_name, "✅ 验证通过（漏洞触发）", output))
        elif "CSSMERR" in output or "errSec" in output:
            print(f"  ❌ 证书被拒绝（正常）")
            RESULTS.append((test_name, "❌ 被拒绝", output))
        else:
            print(f"  ⚠️  结果: {output.strip()[-200:]}")
            RESULTS.append((test_name, "⚠️  未知", output))
        
    except subprocess.TimeoutExpired:
        print(f"  ⏰ 超时（OCSP 网络阻塞）")
        RESULTS.append((test_name, "⏰ OCSP 超时", ""))
    except Exception as e:
        print(f"  💥 错误: {e}")
        RESULTS.append((test_name, f"💥 {e}", ""))
    finally:
        restore_keychains()

def restore_keychains():
    """恢复默认钥匙串"""
    default_keychain = os.path.expanduser("~/Library/Keychains/login.keychain-db")
    subprocess.run(
        ["security", "list-keychains", "-d", "user", "-s", default_keychain],
        capture_output=True, stderr=subprocess.DEVNULL
    )

# ============================================================
# 测试 1：畸形日期
# ============================================================
def test_malformed_date():
    test_name = "畸形日期 (13月)"
    print(f"\n>>> [TEST 1] {test_name}")
    
    key = gen_key()
    pub = key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Malformed Date")
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime(2050, 12, 31, tzinfo=datetime.timezone.utc))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
    
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    der_data = cert.public_bytes(serialization.Encoding.DER)
    # 把 12 月改成 13 月
    der_data = der_data.replace(b'205012', b'205013')
    
    cert_path = os.path.join(OUTPUT_DIR, "test1_malformed_date.crt")
    with open(cert_path, "wb") as f:
        f.write(der_data)
    write_key(os.path.join(OUTPUT_DIR, "test1_key.key"), key)
    
    verify_with_forced_trust(cert_path, test_name)

# ============================================================
# 测试 2：未知关键扩展
# ============================================================
def test_unknown_critical_ext():
    test_name = "未知关键扩展"
    print(f"\n>>> [TEST 2] {test_name}")
    
    key = gen_key()
    pub = key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Unknown Critical Ext")
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=DAYS))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_UNKNOWN_CRITICAL, b'\x30\x00'), critical=True)
    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(OID_CUSTOM_POLICY, policy_qualifiers=None),
        ]), critical=False)
    
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    cert_path = os.path.join(OUTPUT_DIR, "test2_unknown_critical.crt")
    write_cert(cert_path, cert)
    write_key(os.path.join(OUTPUT_DIR, "test2_key.key"), key)
    
    verify_with_forced_trust(cert_path, test_name)

# ============================================================
# 测试 3：不可达 OCSP
# ============================================================
def test_unreachable_ocsp():
    test_name = "不可达 OCSP"
    print(f"\n>>> [TEST 3] {test_name}")
    
    key = gen_key()
    pub = key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Unreachable OCSP")
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=DAYS))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
    builder = builder.add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                x509.oid.AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(MALICIOUS_OCSP_URL)
            )
        ]), critical=False)
    
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    cert_path = os.path.join(OUTPUT_DIR, "test3_unreachable_ocsp.crt")
    write_cert(cert_path, cert)
    write_key(os.path.join(OUTPUT_DIR, "test3_key.key"), key)
    
    verify_with_forced_trust(cert_path, test_name)

# ============================================================
# 测试 4：分水岭弱密钥
# ============================================================
def test_legacy_weak_key():
    test_name = "分水岭弱密钥 (512-bit RSA)"
    print(f"\n>>> [TEST 4] {test_name}")
    
    try:
        key = gen_key(512)
    except Exception as e:
        print(f"  ⚠️  512-bit 密钥生成失败: {e}")
        RESULTS.append((test_name, "⚠️  生成失败", str(e)))
        return
    
    pub = key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Legacy 512-bit")
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime(2013, 7, 1, tzinfo=datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime(2024, 7, 1, tzinfo=datetime.timezone.utc))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
    
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    cert_path = os.path.join(OUTPUT_DIR, "test4_legacy_weak_key.crt")
    write_cert(cert_path, cert)
    write_key(os.path.join(OUTPUT_DIR, "test4_key.key"), key)
    
    verify_with_forced_trust(cert_path, test_name)

# ============================================================
# 测试 5：高仿 Apple 证书（对比用）
# ============================================================
def test_fake_apple_cert():
    """生成一个和之前一样的高仿 Apple 证书，测试苹果特有 OID 的反应"""
    test_name = "高仿 Apple 证书 (完整 OID)"
    print(f"\n>>> [TEST 5] {test_name}")
    
    key = gen_key()
    pub = key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, TEAM_ID),
        x509.NameAttribute(NameOID.COMMON_NAME, "Apple Development"),
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=DAYS))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(OID_POLICY_5_1, policy_qualifiers=[
                "https://www.apple.com/certificateauthority/"]),
            x509.PolicyInformation(OID_ROOT_PRIVATE, policy_qualifiers=None),
            x509.PolicyInformation(OID_APPLE_ISSUED_1, policy_qualifiers=None),
            x509.PolicyInformation(OID_APPLE_ISSUED_2, policy_qualifiers=None),
            x509.PolicyInformation(OID_PROD_MARK, policy_qualifiers=None),
            x509.PolicyInformation(OID_LEAF_MARK, policy_qualifiers=None),
        ]), critical=False)
    
    for oid in OID_1_x:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid, b'\x05\x00'), critical=False)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_IPA_SIGNING, TEAM_ID.encode()), critical=False)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_WWDR, b'\x05\x00'), critical=False)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_INTEG, b'\x05\x00'), critical=False)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_SEC_BOOT, b'\x05\x00'), critical=False)
    
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    cert_path = os.path.join(OUTPUT_DIR, "test5_fake_apple.crt")
    write_cert(cert_path, cert)
    write_key(os.path.join(OUTPUT_DIR, "test5_key.key"), key)
    
    verify_with_forced_trust(cert_path, test_name)

# ============================================================
# 主流程
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Apple 漏洞测试证书生成器 + Mac 强制信任验证")
    print(f"输出目录: {OUTPUT_DIR}")
    print("=" * 60)
    
    test_malformed_date()
    test_unknown_critical_ext()
    test_unreachable_ocsp()
    test_legacy_weak_key()
    test_fake_apple_cert()
    
    print("\n\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    for name, status, _ in RESULTS:
        print(f"  {status} | {name}")
    
    print(f"\n✅ 所有测试完成。证书保存在: {OUTPUT_DIR}")
    print("💡 如果看到 '✅ 验证通过'，说明可能触发了宽松机制，值得拿到 iOS 上深入测试")
