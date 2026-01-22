# ECDLP Research: Research on Elliptic Curve Discrete Logarithm Problem

## 🔍 Overview

This work investigates the possibility of fully inverting a private key from a public key using an available probabilistic private-key topology that supports bidirectional inversion. The study uses machine learning and deep learning to discover hidden meta-invariants based on the topological structure of the private key.

NOTICE!
This work is in the stage of active development and research; therefore, some sections of this repository are incomplete, and documentation may be unavailable at this stage.

## 📁 Structure

```text
ECDLP-Research/
├── README.md
├── LICENSE
├── src/
|   ├── ecurve/
│   │   ├── find_curve.sage                  # Script to find test elliptic curve parameters
│   │   ├── secp256k1.py                     # Advanced script to generate pairs of keys with private key topology based on 'secp256k1'
│   │   └── secp256k1.txt                    # The result of the work 'secp256k1.py' script
|   ├── kuggle/                              # ML/DL models, datasets, experimental notebooks for Kaggle environment
|   ├── utils/
│   │   ├── generate_data.py                 # Script to generate data into local CSV file
│   │   ├── restore_private_key.py           # Script for private key restoring based on the hidden added points chain from the topology
│   │   ├── instructions.txt                 # Instructions on how to use the scripts from the 'utils' folder
│   │   ├── generate_private_key.py          # Script for generating private key based on multi-source entropy
│   │   ├── topology_counter.py              # Script for counting unique topologies defined by parameters (a, b, c, d)
│   │   ├── ...
│   │   └── ...
├── data/
│   ├── key_list_stats_20251215142747.txt    # A file that includes statistics for 100K keys based on legacy curve (generated on Local env)
│   ├── key_list_stats_20251215150040.txt    # A file that includes statistics for 100K keys based on legacy curve (generated on Kaggle env)
│   ├── key_list_stats_20251215153252.txt    # A file that includes statistics for 100K keys based on test curve (generated on Kaggle env)
│   ├── key_list_stats_20251215173203.txt    # A file that includes statistics for 100K keys based on test curve (generated on Local env)
│   ├── ...
│   └── ...
└── docs/
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

## 🔍 Project on JIRA

Tracking and monitoring tasks related to the current project can be found here:

[![Go to JIRA](https://img.shields.io/badge/JIRA-Visit-blue)](https://cryptonsystemslab.atlassian.net/jira/core/projects/CSL/board?filter=&groupBy=status&atlOrigin=eyJpIjoiZWYwNGI4ODlhYmZjNDdkNGIwMGM3NWUwNzk0MTBjNGYiLCJwIjoiaiJ9)

### STATUS: Active
