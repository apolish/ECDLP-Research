# ECDLP Research: Research on Elliptic Curve Discrete Logarithm Problem

## 🔍 Overview

This project investigates a novel topological approach to the Elliptic Curve Discrete Logarithm Problem (ECDLP), with a focus on the `secp256k1` curve used in Bitcoin and other blockchain systems.

The core idea is based on the observation that scalar multiplication — the operation used to derive a public key from a private key — produces a deterministic sequence of elliptic curve point additions. This sequence, referred to as the **private key topology**, encodes structural information about the private key in the form of a chain of intermediate curve points. Each private key induces a unique topological fingerprint defined by four parameters `(a, b, c, d)`, which describe the positions of key operations within the addition chain.

The research explores whether this topology can be exploited to narrow down or reconstruct the private key from its public key. Specifically, the work examines:

- The statistical distribution of topological conditions across large sets of private keys (up to 1M keys)
- The feasibility of bidirectional inversion — restoring a private key given its topology and a known chain of added double-points
- The application of machine learning and deep learning to detect hidden meta-invariants embedded in the topological structure

Experiments are conducted on both a small test curve and the full-scale `secp256k1` (legacy) curve. Datasets, statistical analyses, and ML/DL notebooks are provided for reproducibility.

> **NOTICE:** This work is in active development and research. Some sections of this repository are incomplete, and documentation may be unavailable at this stage.

## 📁 Structure

```text
ECDLP-Research/
├── README.md
├── LICENSE
├── src/
|   ├── ecurve/
│   │   ├── find_curve.sage                   # Script to find test elliptic curve parameters
│   │   ├── secp256k1.py                      # Advanced script to generate pairs of keys with private key topology based on 'secp256k1'
│   │   └── secp256k1.txt                     # The result of the work 'secp256k1.py' script
|   ├── kuggle/                               # ML/DL models, datasets, experimental notebooks for Kaggle environment
|   ├── utils/
│   │   ├── generate_data.py                  # Script to generate data into local CSV file
│   │   ├── restore_private_key.py            # Script for private key restoring based on the hidden added points chain from the topology
│   │   ├── instructions.txt                  # Instructions on how to use the scripts from the 'utils' folder
│   │   └── topology_counter.py               # Script for counting unique topologies defined by parameters (a, b, c, d)
├── data/
│   ├── key_list_stats_20260131200024.txt     # A file that includes statistics for 100K keys based on legacy curve (generated on Local env)
│   ├── key_list_stats_20260131204250.txt     # A file that includes statistics for 1M keys based on test curve (generated on Local env)
│   ├── key_list_stats_20260131191955.txt     # A file that includes statistics for 100K keys based on legacy curve (generated on Kaggle env)
│   └── key_list_stats_20260131191633.txt     # A file that includes statistics for 1M keys based on test curve (generated on Kaggle env)
└── docs/
    └── ...
```

## 📘 Link

This work was inspired by the author's previous research on detecting algebraic anomalies in ECDSA transactions and modular remainders. You can read the corresponding publication through the following links:

```text
https://doi.org/10.6084/m9.figshare.29223701
https://doi.org/10.21203/rs.3.rs-6790872/v1
```

## 🔗 License

Released under MIT License (see LICENSE file).

## 🔍 Project on JIRA

Tracking and monitoring tasks related to the current project can be found here:

[![Go to JIRA](https://img.shields.io/badge/JIRA-Visit-blue)](https://cryptonsystemslab.atlassian.net/jira/core/projects/CSL/board?filter=&groupBy=status&atlOrigin=eyJpIjoiZWYwNGI4ODlhYmZjNDdkNGIwMGM3NWUwNzk0MTBjNGYiLCJwIjoiaiJ9)

### STATUS: Active
