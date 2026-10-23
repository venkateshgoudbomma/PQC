🛡️ Q-Migrate

Post-Quantum Cryptography Migration Assessment & Decision Platform

📌 Overview

Q-Migrate is an automated cryptographic assessment and decision platform designed to help organizations plan their transition from quantum-vulnerable classical algorithms (RSA, ECC, Diffie-Hellman) to NIST-standardized Post-Quantum Cryptography (PQC).

With adversaries actively archiving encrypted internet traffic under Harvest Now, Decrypt Later (HNDL) paradigms, legacy cryptographic configurations require immediate review. However, blind migration to lattice-based schemes is impeded by significant payload inflation (public keys up to ~37× larger) and potential network MTU packet fragmentation.

Q-Migrate provides an end-to-end framework that:

Discovers active cryptographic suites and public keys across any live TLS endpoint.

Benchmarks real execution latency and payload sizes on host hardware.

Decides optimal target architectures (Classical Status Quo, Hybrid Transition, or Pure PQC) using Multi-Criteria Decision Analysis (MCDA).

Visualizes comparative metrics in an interactive web dashboard.

🏗️ System Architecture

                       ┌─────────────────────────┐
                       │    Target Domain/URL    │
                       └────────────┬────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │         Module 1: Discovery Engine (scanner.py)        │
       │   - Live TLS Handshake & X.509 Certificate Parser      │
       │   - Cryptographic Bill of Materials (CBOM) Generation  │
       │   - Shor's Vulnerability & HNDL Risk Assessment        │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │        Module 2: Benchmark Sandbox (benchmark.py)      │
       │   - Hardware execution: RSA-2048, X25519               │
       │   - FIPS 203 Spec Execution: ML-KEM-768 & Hybrid       │
       │   - Latency (ms) & Payload Overhead (Bytes) profiling  │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │         Module 3: Decision Engine (engine.py)          │
       │   - Constraints: MTU Budget (KB) & Retention (Years)   │
       │   - Multi-Criteria Decision Analysis (MCDA) Scoring    │
       │   - Verdict: Classical vs. Hybrid vs. Pure PQC         │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │          Module 4: Web Dashboard (app.py)              │
       │   - Real-time Plotly charts & parameter sliders        │
       │   - JSON compliance report export                      │
       └────────────────────────────────────────────────────────┘


🚀 Key Features

Live Endpoint Discovery: Connects via TLS socket to parse active cipher suites, certificate key types (RSA, ECDSA), and signature algorithms without requiring agent installation.

Hardware Benchmarking: Runs local asymmetric keypair generation, encapsulation, and exchange routines to deliver concrete computational latency and byte size metrics.

Deterministic Decision Scoring: Eliminates guesswork by evaluating migration trade-offs against practical constraints (packet size thresholds and data shelf-life sensitivity).

Interactive UI: Built with Streamlit and Plotly for intuitive data exploration and decision modeling.

CBOM & Report Export: Generates structured compliance data for security audits and architectural review boards.

💻 Installation & Quickstart

Prerequisites

Python 3.10 or higher

Git

1. Clone the Repository

git clone https://github.com/YOUR_USERNAME/PQC.git
cd PQC


2. Set Up a Virtual Environment (Recommended)

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate


3. Install Dependencies

    install requirements


( pip install cryptography streamlit pandas plotly)

4. Launch the Platform

python -m streamlit run app.py


Open your browser at http://localhost:8501

📁 Repository Structure

├── app.py                     # Streamlit web dashboard & visualization engine
├── scanner.py                 # Module 1: Live TLS socket scanner & CBOM generator
├── benchmark.py               # Module 2: Cryptographic benchmark sandbox
├── engine.py                  # Module 3: MCDA decision engine & scoring logic
├── PROJECT_DOCUMENTATION.md   # Complete technical specifications & viva defense notes
├── README.md                  # Project overview & quickstart guide
└── .gitignore                 # Cache and environment exclusion rules

📜 Migration Decision Matrix

Q-Migrate categorizes targets into three strategic recommendations based on user constraints:

Hybrid-Transition (X25519 + ML-KEM-768) [Balanced]

Default Path. Deploys dual-layer key exchange to neutralize HNDL attacks immediately while preserving backward compatibility and staying within moderate packet budgets (~2.6 KB).

Classical-StatusQuo [Bandwidth-Constrained]

Triggered when network payload limits are restricted ($\le 1.5\text{ KB}$, e.g., low-power IoT/satellite links) and data shelf-life is short ($<3$ years). Advises infrastructure optimization prior to algorithm replacement.

Pure-PQC (ML-KEM-768 + ML-DSA-65) [High-Assurance]

Triggered for long-term data retention ( e.g., healthcare, defense, financial records) with packet budgets capable of absorbing full lattice key and signature overhead .