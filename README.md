# ECDLP Research: Research on Elliptic Curve Discrete Logarithm Problem

## 🔍 Overview

This work explores the possibility of completely inverting the private key based on the public key and the available probabilistic topology of the private key, which should enable the algorithmic recovery of private keys in polynomial time.

NOTICE!
This work is in the stage of active development and research; therefore, some sections of this repository are incomplete, and documentation may be unavailable at this stage.

## 📁 Structure

```text
ECDLP-Research/
├── README.md
├── LICENSE
├── src/
|   ├── ecurve/
│   │   ├── find_curve.sage                # Script to find test elliptic curve parameters
│   │   ├── secp256k1.py                   # Advanced script to generate pairs of keys with private key topology based on 'secp256k1'
│   │   └── secp256k1.txt                  # The result of the work 'secp256k1.py' script
|   ├── models/
│   │   ├── description.txt                # ML model list description
│   │   ├── ...
│   │   └── ...
|   ├── utils/
│   │   ├── generate_data.py               # Script to generate data into local CSV file
│   │   ├── ...
│   │   └── ...
├── data/
│   ├── instructions.txt                   # The instructions on how to generate or download existing data
│   ├── key_list_data_20251002200628.csv   # CSV file with 1M keys written in topological key representation format
│   ├── key_list_stats_20251002200628.txt  # A statistics file that includes statistics on topological groups by key
│   ├── ...
│   └── ...
└── docs/
    ├── description.txt                    # Document list description
    ├── ...
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

## 🚀 Quick Start

Clone the repository and run the transaction generator:

```bash
git clone https://github.com/YOUR_USERNAME/ECDLP-Research.git
cd ECDLP-Research/
```

## 🔍 Project on JIRA

Tracking and monitoring tasks related to the current project can be found here:

[![Go to JIRA](https://img.shields.io/badge/JIRA-Visit-blue)](https://cryptonsystemslab.atlassian.net/jira/core/projects/CSL/board?filter=&groupBy=status&atlOrigin=eyJpIjoiZWYwNGI4ODlhYmZjNDdkNGIwMGM3NWUwNzk0MTBjNGYiLCJwIjoiaiJ9)
