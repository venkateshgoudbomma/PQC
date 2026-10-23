import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import time

# Import existing core modules
from scanner import scan_endpoint
from engine import evaluate_migration, CRYPTO_PROFILES
from benchmark import run_classical_x25519, run_pqc_ml_kem_768, run_classical_rsa2048, run_hybrid_x25519_ml_kem

# Page Configuration
st.set_page_config(
    page_title="Q-Migrate | Post-Quantum Migration Platform",
    page_icon="🛡️",
    layout="wide"
)

# Custom Styling
st.markdown("""
    <style>
    .metric-card {
        background-color: #f8f9fa;
        padding: 18px;
        border-radius: 10px;
        border: 1px solid #dee2e6;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Q-Migrate")
st.caption("Post-Quantum Cryptography Migration Assessment & Decision Platform")
st.write("---")

# Sidebar - Target & Operational Constraints
st.sidebar.header("🎯 Target & Constraints")

target_url = st.sidebar.text_input("Target Host / Domain", value="google.com")

st.sidebar.subheader("System Constraints")
max_overhead_kb = st.sidebar.slider(
    "Max Handshake Payload Budget (KB)",
    min_value=0.5,
    max_value=10.0,
    value=3.0,
    step=0.5,
    help="Ethernet MTU standard is ~1.5KB. Values above 1.5KB require multi-packet handshakes."
)

data_retention_years = st.sidebar.slider(
    "Data Shelf-Life / Confidentiality (Years)",
    min_value=1,
    max_value=25,
    value=8,
    help="How long must recorded traffic remain confidential? >5 years triggers high 'Harvest Now, Decrypt Later' (HNDL) risk."
)

run_analysis = st.sidebar.button("🚀 Run Full Assessment", type="primary")

# Main Interface Tabs
tab1, tab2, tab3 = st.tabs([
    "🔍 1. Discovery & Vulnerability Scan",
    "⚡ 2. Cryptographic Benchmarking",
    "📋 3. Migration Decision & Roadmap"
])

# Initialize Session State
if "scan_data" not in st.session_state:
    st.session_state.scan_data = None
if "bench_data" not in st.session_state:
    st.session_state.bench_data = None
if "decision_data" not in st.session_state:
    st.session_state.decision_data = None

if run_analysis:
    with st.spinner("Executing live TLS discovery probe..."):
        st.session_state.scan_data = scan_endpoint(target_url)

    with st.spinner("Executing cryptographic execution sandbox..."):
        st.session_state.bench_data = [
            run_classical_rsa2048(),
            run_classical_x25519(),
            run_pqc_ml_kem_768(),
            run_hybrid_x25519_ml_kem()
        ]

    with st.spinner("Evaluating multi-criteria decision matrix..."):
        if "error" not in st.session_state.scan_data:
            st.session_state.decision_data = evaluate_migration(
                st.session_state.scan_data,
                max_packet_overhead_kb=max_overhead_kb,
                data_retention_years=data_retention_years
            )

# ----------------- TAB 1: SCANNER -----------------
with tab1:
    st.subheader("Live Cryptographic Discovery Engine")
    if st.session_state.scan_data:
        scan = st.session_state.scan_data
        if "error" in scan:
            st.error(scan["error"])
        else:
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Target Host", f"{scan['host']}:{scan['port']}")
            col2.metric("TLS Version", scan['tls_version'])
            col3.metric("Cipher Suite", scan['cipher_suite'].split('_')[0])
            col4.metric("Quantum Status", scan['risk_assessment']['status'], delta_color="inverse")

            st.write("### Cryptographic Bill of Materials (Discovered CBOM)")
            cbom_df = pd.DataFrame([{
                "Asset": "Session Key Exchange",
                "Algorithm": scan['cipher_suite'],
                "Quantum Vulnerable": "YES (Shor's)",
                "Risk Severity": "CRITICAL (HNDL Threat)"
            }, {
                "Asset": "Identity Certificate",
                "Algorithm": f"{scan['cert_key_type']}-{scan['cert_key_size']}",
                "Quantum Vulnerable": "YES (Shor's)",
                "Risk Severity": "HIGH (Authentication Forgery)"
            }, {
                "Asset": "Signature Algorithm",
                "Algorithm": scan['cert_sig_alg'],
                "Quantum Vulnerable": "YES (Shor's)",
                "Risk Severity": "HIGH"
            }])
            st.table(cbom_df)

            st.info(f"**Discovery Finding:** {scan['risk_assessment']['findings'][0]}")
    else:
        st.info("👈 Enter a target domain in the sidebar and click **'Run Full Assessment'** to begin.")

# ----------------- TAB 2: BENCHMARK -----------------
with tab2:
    st.subheader("Hardware Sandbox Execution Benchmark")
    if st.session_state.bench_data:
        bench_df = pd.DataFrame(st.session_state.bench_data)
        
        # Display Table
        st.dataframe(bench_df[[
            "alg", "security_level", "quantum_safe", "pubkey_bytes", "ciphertext_bytes", "keygen_ms", "exchange_ms"
        ]], use_container_width=True)

        colA, colB = st.columns(2)
        with colA:
            # Chart 1: Key & Ciphertext Payload Overhead
            bench_df["total_bytes"] = bench_df["pubkey_bytes"] + bench_df["ciphertext_bytes"]
            fig_bytes = px.bar(
                bench_df,
                x="alg",
                y="total_bytes",
                color="quantum_safe",
                title="Total Handshake Payload Overhead (Bytes)",
                labels={"total_bytes": "Bytes (Public Key + Ciphertext)", "alg": "Algorithm"},
                text_auto=True
            )
            st.plotly_chart(fig_bytes, use_container_width=True)

        with colB:
            # Chart 2: Latency Comparison
            bench_df["total_latency"] = bench_df["keygen_ms"] + bench_df["exchange_ms"]
            fig_lat = px.bar(
                bench_df,
                x="alg",
                y="total_latency",
                color="alg",
                title="Execution Latency (Milliseconds)",
                labels={"total_latency": "Time (ms)", "alg": "Algorithm"},
                text_auto=True
            )
            st.plotly_chart(fig_lat, use_container_width=True)
    else:
        st.info("Run the assessment to inspect live benchmark telemetry.")

# ----------------- TAB 3: DECISION ENGINE -----------------
with tab3:
    st.subheader("MCDA Decision Engine & Migration Roadmap")
    if st.session_state.decision_data:
        dec = st.session_state.decision_data
        
        st.success(f"### Recommended Architecture: **{dec['recommended_architecture']}**")
        
        col_s1, col_s2 = st.columns([1, 1])
        with col_s1:
            st.write("#### Feasibility Scoring Matrix (0–100)")
            score_df = pd.DataFrame(
                list(dec["feasibility_scores"].items()),
                columns=["Architecture", "Feasibility Score"]
            )
            fig_radar = px.bar(
                score_df,
                x="Architecture",
                y="Feasibility Score",
                color="Feasibility Score",
                range_y=[0, 100],
                title="Multi-Criteria Feasibility Score"
            )
            st.plotly_chart(fig_radar, use_container_width=True)

        with col_s2:
            st.write("#### Architectural Decision Rationale")
            for r in dec["rationale"]:
                st.markdown(f"- ✅ **{r}**")

            st.write("#### Actionable Transition Roadmap")
            st.markdown("""
            1. **Phase 1 (Immediate):** Deploy **X25519 + ML-KEM-768** hybrid key exchange on edge proxies to neutralize Harvest Now, Decrypt Later (HNDL) attacks without breaking legacy clients.
            2. **Phase 2 (Medium-term):** Upgrade TLS stack to OpenSSL 3.2+ or BoringSSL with draft-ietf-tls-hybrid support.
            3. **Phase 3 (Long-term):** Migrate Public Key Infrastructure (PKI) and root CAs to **ML-DSA** once root store trust anchors finalize.
            """)

        # Download Report Button
        report_data = {
            "scan": st.session_state.scan_data,
            "decision": st.session_state.decision_data
        }
        st.download_button(
            label="📥 Export Full Migration Assessment (JSON)",
            data=json.dumps(report_data, indent=4),
            file_name=f"Q-Migrate_Report_{st.session_state.scan_data.get('host', 'target')}.json",
            mime="application/json"
        )
    else:
        st.info("Run the assessment to generate the decision matrix.")