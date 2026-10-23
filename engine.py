import json
import os
import sys

# Official Cryptographic Architecture Profiles
CRYPTO_PROFILES = {
    "Classical-StatusQuo": {
        "name": "Classical (RSA-2048 / ECDHE-P256)",
        "quantum_security_level": 0,       # 0% Shor protection
        "total_handshake_bytes": 350,       # ~0.35 KB
        "backward_compatibility": 10,
        "hndl_risk": "CRITICAL"
    },
    "Hybrid-Transition": {
        "name": "Hybrid (X25519 + ML-KEM-768)",
        "quantum_security_level": 85,      # Quantum-safe KEX, classical PKI
        "total_handshake_bytes": 2622,     # ~2.56 KB
        "backward_compatibility": 8,
        "hndl_risk": "LOW"
    },
    "Pure-PQC": {
        "name": "Pure PQC (ML-KEM-768 + ML-DSA-65)",
        "quantum_security_level": 100,     # Full FIPS 203 + FIPS 204
        "total_handshake_bytes": 7450,     # ~7.28 KB
        "backward_compatibility": 4,
        "hndl_risk": "ZERO"
    }
}

def load_scan_result(filepath="scan_result.json"):
    if not os.path.exists(filepath):
        print(f"[!] '{filepath}' not found. Please run scanner.py first.")
        sys.exit(1)
    with open(filepath, "r") as f:
        return json.load(f)

def evaluate_migration(scan_data, max_packet_overhead_kb=3.0, data_retention_years=7):
    host = scan_data.get("host", "Unknown")
    cipher = scan_data.get("cipher_suite", "Unknown")
    is_vulnerable = scan_data.get("risk_assessment", {}).get("is_quantum_vulnerable", True)

    scores = {}

    for profile_key, profile in CRYPTO_PROFILES.items():
        size_kb = profile["total_handshake_bytes"] / 1024.0

        # --- Rule 1: Hard Bandwidth Constraint Filter ---
        # If payload strictly exceeds the user's network budget, disqualify it with a heavy penalty
        if size_kb > max_packet_overhead_kb:
            bandwidth_score = 0.0
        else:
            # Full points if well within budget, scaled down slightly as it approaches the limit
            bandwidth_score = 35.0 * (1.0 - (size_kb / (max_packet_overhead_kb * 1.8)))

        # --- Rule 2: Security & HNDL Shelf-Life Urgency ---
        # Short retention (<3 years) -> low urgency, classical is tolerable
        # Medium retention (3-12 years) -> hybrid is the recommended sweet spot
        # Long retention (>12 years) -> pure quantum safety is mandatory
        q_level = profile["quantum_security_level"] / 100.0

        if data_retention_years < 3:
            # Low HNDL urgency: security has low weight
            security_score = q_level * 15.0
            classical_bonus = 25.0 if profile_key == "Classical-StatusQuo" else 0.0
        elif data_retention_years >= 12:
            # Critical HNDL urgency: pure PQC gets massive priority
            security_score = q_level * 55.0
            classical_bonus = 0.0
        else:
            # Balanced transition window (3 to 11 years)
            security_score = q_level * 35.0
            classical_bonus = 0.0

        # --- Rule 3: Interoperability & Compatibility ---
        compat_score = (profile["backward_compatibility"] / 10.0) * 20.0

        total = round(bandwidth_score + security_score + compat_score + classical_bonus, 2)
        scores[profile_key] = max(0.0, total)

    # Winner is the highest score
    recommended_tier = max(scores, key=scores.get)
    rec_details = CRYPTO_PROFILES[recommended_tier]

    decision_summary = {
        "target": host,
        "current_cipher": cipher,
        "is_currently_vulnerable": is_vulnerable,
        "recommended_architecture": rec_details["name"],
        "recommendation_code": recommended_tier,
        "feasibility_scores": scores,
        "rationale": []
    }

    if recommended_tier == "Classical-StatusQuo":
        decision_summary["rationale"].append(
            "Bandwidth constraint violation: Target payload budget is too low for PQC/Hybrid key expansion (~2.6KB - 7.3KB required)."
        )
        decision_summary["rationale"].append(
            "Short data retention window (<3 years) permits delaying migration until network infrastructure or session resumption is optimized."
        )
    elif recommended_tier == "Pure-PQC":
        decision_summary["rationale"].append(
            f"High data shelf-life requirement ({data_retention_years} years) demands immediate, end-to-end quantum resistance against retrospective decryption."
        )
        decision_summary["rationale"].append(
            "Sufficient packet budget allocated to accommodate both lattice KEX (ML-KEM-768) and lattice signatures (ML-DSA-65)."
        )
    else:  # Hybrid-Transition
        decision_summary["rationale"].append(
            "Optimal compromise: Defends ephemeral key exchanges against HNDL while preserving legacy client interoperability."
        )
        decision_summary["rationale"].append(
            "Handshake size fits within intermediate packet budgets without causing multi-roundtrip TCP fragmentation."
        )

    return decision_summary

if __name__ == "__main__":
    scan_result = load_scan_result("scan_result.json")
    print("\n--- Testing 3 Distinct Scenarios on the updated Engine ---")

    print("\n1. Low Budget (1.0 KB, 2 Years):")
    d1 = evaluate_migration(scan_result, max_packet_overhead_kb=1.0, data_retention_years=2)
    print("Winner:", d1["recommended_architecture"], "| Scores:", d1["feasibility_scores"])

    print("\n2. Balanced (3.5 KB, 7 Years):")
    d2 = evaluate_migration(scan_result, max_packet_overhead_kb=3.5, data_retention_years=7)
    print("Winner:", d2["recommended_architecture"], "| Scores:", d2["feasibility_scores"])

    print("\n3. High Security Archive (8.5 KB, 18 Years):")
    d3 = evaluate_migration(scan_result, max_packet_overhead_kb=8.5, data_retention_years=18)
    print("Winner:", d3["recommended_architecture"], "| Scores:", d3["feasibility_scores"])