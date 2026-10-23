import socket
import ssl
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

def clean_target_hostname(raw_input: str) -> tuple[str, int]:
    """Cleans URLs into a raw host and port."""
    if not raw_input.startswith("http://") and not raw_input.startswith("https://"):
        raw_input = "https://" + raw_input
    parsed = urlparse(raw_input)
    host = parsed.hostname or raw_input
    port = parsed.port if parsed.port else 443
    return host, port

def analyze_crypto_risk(cert_key_type: str, cert_key_size: int, cipher_suite: str):
    """Evaluates whether the active crypto parameters are quantum-vulnerable."""
    findings = []
    is_quantum_vulnerable = False

    # 1. Certificate Key Analysis
    if cert_key_type in ["RSA", "ECDSA", "DSA"]:
        is_quantum_vulnerable = True
        findings.append(f"Server public key uses {cert_key_type}-{cert_key_size}, vulnerable to Shor's Algorithm.")

    # 2. Cipher Suite Key Exchange Analysis
    # Classical key exchanges: ECDHE, DHE, RSA
    quantum_vulnerable_kex = ["ECDHE", "DHE", "RSA", "ECDH", "DH"]
    for kex in quantum_vulnerable_kex:
        if kex in cipher_suite:
            is_quantum_vulnerable = True
            findings.append(f"Key exchange mechanism ({kex}) is vulnerable to 'Harvest Now, Decrypt Later' (HNDL).")
            break

    # 3. Overall Migration Status
    if is_quantum_vulnerable:
        status = "CRITICAL / VULNERABLE"
        recommendation = "Migrate to Hybrid Key Exchange (X25519 + ML-KEM-768) and prepare ML-DSA certificate transition."
    else:
        status = "POST-QUANTUM RESISTANT"
        recommendation = "Endpoint already supports quantum-safe or hybrid key encapsulation."

    return {
        "status": status,
        "is_quantum_vulnerable": is_quantum_vulnerable,
        "findings": findings,
        "recommendation": recommendation
    }

def scan_endpoint(target: str):
    host, port = clean_target_hostname(target)
    print(f"\n[*] Scanning target endpoint: {host}:{port} ...")

    # Set up SSL Context
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cipher_name, ssl_proto, secret_bits = ssock.cipher()
                
                # Fetch DER-encoded binary certificate
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                # Analyze public key in certificate
                pubkey = cert.public_key()
                if isinstance(pubkey, rsa.RSAPublicKey):
                    key_type = "RSA"
                    key_size = pubkey.key_size
                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    key_type = "ECDSA"
                    key_size = pubkey.key_size
                else:
                    key_type = "Unknown / Other"
                    key_size = 0

                # Analyze Signature Algorithm
                sig_alg = cert.signature_algorithm_oid._name

                # Run Quantum Risk Assessment
                risk = analyze_crypto_risk(key_type, key_size, cipher_name)

                return {
                    "host": host,
                    "port": port,
                    "tls_version": tls_version,
                    "cipher_suite": cipher_name,
                    "secret_bits": secret_bits,
                    "cert_subject": cert.subject.rfc4514_string(),
                    "cert_key_type": key_type,
                    "cert_key_size": key_size,
                    "cert_sig_alg": sig_alg,
                    "risk_assessment": risk
                }

    except Exception as e:
        return {"error": f"Failed to connect or scan target: {str(e)}"}

if __name__ == "__main__":
    import json
    
    # You can test with any domain: google.com, cloudflare.com, or your university URL
    test_target = input("Enter domain or URL to scan (default: google.com): ").strip()
    if not test_target:
        test_target = "google.com"

    result = scan_endpoint(test_target)

    if "error" in result:
        print(f"[!] Error: {result['error']}")
    else:
        print("\n" + "=" * 70)
        print("          Q-Migrate Cryptographic Discovery Scan Report          ")
        print("=" * 70)
        print(f"Target Host       : {result['host']}:{result['port']}")
        print(f"Active Protocol   : {result['tls_version']}")
        print(f"Active Cipher     : {result['cipher_suite']} ({result['secret_bits']} bits)")
        print(f"Certificate Key   : {result['cert_key_type']}-{result['cert_key_size']}")
        print(f"Signature Alg     : {result['cert_sig_alg']}")
        print("-" * 70)
        print(f"Quantum Status    : {result['risk_assessment']['status']}")
        for f in result['risk_assessment']['findings']:
            print(f" - Finding        : {f}")
        print(f"Recommendation    : {result['risk_assessment']['recommendation']}")
        print("=" * 70)
        
        # Save output for the Decision Engine to ingest
        with open("scan_result.json", "w") as f:
            json.dump(result, f, indent=4)
        print("\n[+] Scan results saved to 'scan_result.json' for the Decision Engine.")