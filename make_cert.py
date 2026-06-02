#!/usr/bin/env python3
"""漏洞测试证书生成 + Mac 本地一键验证"""
import datetime, os, sys, subprocess, tempfile
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./vuln_test_certs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- 测试专用 OID ---
OID_UNKNOWN_CRITICAL = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
OID_CUSTOM_POLICY    = ObjectIdentifier("1.3.6.1.4.1.99999.2.1")
MALICIOUS_OCSP_URL   = "http://10.255.255.1/ocsp"

RESULTS = []

def gen_key_512():
    return rsa.generate_private_key(65537, 512, default_backend())

def gen_key_2048():
    return rsa.generate_private_key(65537, 2048, default_backend())

def write_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.TraditionalOpenSSL,
                 serialization.NoEncryption()))

def write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def verify_with_security(cert_path, test_name):
    """调用 macOS 的 security verify-cert 命令验证证书"""
    print(f"\n🔍 验证: {test_name}")
    try:
        result = subprocess.run(
            ["security", "verify-cert", "-c", cert_path],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        print(output)

        # 判断结果
        if "certificate verification successful" in output.lower():
            RESULTS.append((test_name, "✅ 验证通过", output))
        elif "CSSMERR" in output or "errSec" in output or "certificate is invalid" in output.lower():
            RESULTS.append((test_name, "❌ 证书被拒绝", output))
        else:
            RESULTS.append((test_name, "⚠️  结果未知", output))
    except subprocess.TimeoutExpired:
        RESULTS.append((test_name, "⏰ 超时（可能是OCSP网络阻塞）", ""))
    except Exception as e:
        RESULTS.append((test_name, f"💥 执行错误: {e}", ""))

# ============================================================
# 测试 1：畸形日期
# ============================================================
def test_malformed_date():
    name = "畸形日期 (13月)"
    print(f"\n>>> 生成: {name}")
    key = gen_key_2048()
    pub = key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Malformed Date")])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime(2020, 1, 1))
    builder = builder.not_valid_after(datetime.datetime(2050, 12, 31))
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
    
    verify_with_security(cert_path, name)

# ============================================================
# 测试 2：未知关键扩展
# ============================================================
def test_unknown_critical_ext():
    name = "未知关键扩展"
    print(f"\n>>> 生成: {name}")
    key = gen_key_2048()
    pub = key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Critical Unknown Ext")])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_UNKNOWN_CRITICAL, b'\x30\x00'), critical=True)
    
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    cert_path = os.path.join(OUTPUT_DIR, "test2_unknown_critical.crt")
    write_cert(cert_path, cert)
    
    verify_with_security(cert_path, name)

# ============================================================
# 测试 3：不可达 OCSP
# ============================================================
def test_unreachable_ocsp():
    name = "不可达 OCSP"
    print(f"\n>>> 生成: {name}")
    key = gen_key_2048()
    pub = key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Unreachable OCSP")])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
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
    
    verify_with_security(cert_path, name)

# ============================================================
# 测试 4：分水岭弱密钥
# ============================================================
def test_legacy_weak_key():
    name = "分水岭弱密钥 (512-bit RSA)"
    print(f"\n>>> 生成: {name}")
    try:
        key = gen_key_512()
    except Exception as e:
        print(f"⚠️  512-bit 密钥生成失败（可能需要降级 cryptography 库）: {e}")
        return
    
    pub = key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Legacy 512-bit")])
    
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
    
    verify_with_security(cert_path, name)

# ============================================================
# 额外测试：用 security 直接评估信任
# ============================================================
def test_trust_evaluation():
    """对所有证书做更深入的 trust evaluation"""
    print("\n\n=== 深度信任评估 (SecTrustEvaluate) ===")
    for filename in os.listdir(OUTPUT_DIR):
        if not filename.endswith(".crt"):
            continue
        cert_path = os.path.join(OUTPUT_DIR, filename)
        print(f"\n--- {filename} ---")
        try:
            # 尝试用 security dump-trust-settings 或直接 eval
            result = subprocess.run(
                ["security", "verify-cert", "-v", "-c", cert_path],
                capture_output=True, text=True, timeout=15
            )
            print(result.stdout[-300:] if len(result.stdout) > 300 else result.stdout)
            if result.stderr:
                print(result.stderr[-300:] if len(result.stderr) > 300 else result.stderr)
        except Exception as e:
            print(f"Error: {e}")

# ============================================================
# 主流程
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Apple 漏洞测试证书生成器 + Mac 本地验证")
    print("=" * 60)
    
    test_malformed_date()
    test_unknown_critical_ext()
    test_unreachable_ocsp()
    test_legacy_weak_key()
    
    print("\n\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    for name, status, _ in RESULTS:
        print(f"  {status} | {name}")
    
    # 深度评估
    test_trust_evaluation()
    
    print(f"\n✅ 所有测试完成。证书保存在: {OUTPUT_DIR}")
