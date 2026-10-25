"""
config.py - Configuration settings for the Network Intrusion Detection project.

This module contains all configuration constants including MongoDB connection
settings, dataset paths, and project-wide constants used across all scripts.
"""

import os

# =============================================================================
# MongoDB Connection Settings
# =============================================================================
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_URI = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/"
MONGO_DATABASE = "network_intrusion_db"
MONGO_COLLECTION_RAW = "network_traffic"
MONGO_COLLECTION_CLEANED = "cleaned_network_traffic"

# =============================================================================
# Dataset Configuration
# =============================================================================
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")
VISUALIZATIONS_DIR = os.path.join(PROJECT_ROOT, "visualizations")

DATASET_NAME = "ciaboromani/cicids2017"
HF_DATASET_URL = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main"

# List of expected CSV files in the CIC-IDS-2017 dataset (one per capture session)
EXPECTED_CSV_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# =============================================================================
# Ingestion Settings
# =============================================================================
BATCH_SIZE = 5000  # Number of records to insert per batch

# Encoding fallback order for reading CSV files
CSV_ENCODINGS = ["utf-8", "latin-1"]

# =============================================================================
# Preprocessing Constants
# =============================================================================
# Label column name (after cleaning)
LABEL_COLUMN = "label"

# Benign traffic label
BENIGN_LABEL = "BENIGN"

# Key numeric features to normalize/standardize
NUMERIC_FEATURES_TO_NORMALIZE = [
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "flow_bytes/s",
    "flow_packets/s",
]

# Attack category mapping: maps specific attack labels to broader categories
ATTACK_CATEGORY_MAP = {
    # DoS attacks
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    # DDoS attacks
    "DDoS": "DDoS",
    # Probe / Port Scan
    "PortScan": "Probe/PortScan",
    # Brute Force attacks
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    # Web Attacks
    "Web Attack \u2013 Brute Force": "Web Attack",
    "Web Attack \u2013 XSS": "Web Attack",
    "Web Attack \u2013 Sql Injection": "Web Attack",
    "Web Attack Brute Force": "Web Attack",
    "Web Attack XSS": "Web Attack",
    "Web Attack Sql Injection": "Web Attack",
    # Botnet
    "Bot": "Botnet",
    # Infiltration
    "Infiltration": "Infiltration",
    # Heartbleed
    "Heartbleed": "DoS",
}

# =============================================================================
# Logging Configuration
# =============================================================================
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"
