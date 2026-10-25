"""
step3_data_preprocessing.py - Data preprocessing and cleaning for CIC-IDS-2017.

This script reads raw network traffic data from MongoDB, performs cleaning
and preprocessing operations in streaming batches for optimal performance and
memory safety, and saves the cleaned data into the 'cleaned_network_traffic'
MongoDB collection for analysis and MapReduce operations.

Operations performed:
    - Compute global dataset statistics (mean, std) via MongoDB aggregation
    - Normalize key numeric features using z-score standardization
    - Create binary 'is_attack' field (0 = BENIGN, 1 = Attack)
    - Create 'attack_category' field for grouping specific attack signatures
    - Handle missing and infinite values
    - Stream documents into 'cleaned_network_traffic' collection
    - Create indexes on key query fields for fast MapReduce analysis

Usage:
    python step3_data_preprocessing.py

Prerequisites:
    - Run step2_ingest_to_mongodb.py first to populate raw data
    - MongoDB must be running on localhost:27017
"""

import math
import sys
import logging
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from pymongo import MongoClient

from config import (
    ATTACK_CATEGORY_MAP,
    BENIGN_LABEL,
    LABEL_COLUMN,
    LOG_FORMAT,
    LOG_LEVEL,
    MONGO_COLLECTION_CLEANED,
    MONGO_COLLECTION_RAW,
    MONGO_DATABASE,
    MONGO_URI,
    NUMERIC_FEATURES_TO_NORMALIZE,
    BATCH_SIZE,
)

# Configure logging
logging.basicConfig(format=LOG_FORMAT, level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)


def connect_to_mongodb():
    """Establish a connection to MongoDB and return client and database handle."""
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client[MONGO_DATABASE]
        logger.info(f"Connected to MongoDB at {MONGO_URI}")
        return client, db
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise ConnectionError(f"MongoDB connection failed: {e}")


def categorize_label(label_str):
    """Map raw attack label to standardized high-level attack category."""
    if not label_str:
        return BENIGN_LABEL
    lbl = str(label_str).strip()
    if lbl.upper() == "BENIGN":
        return "BENIGN"
    if "DDoS" in lbl or "ddos" in lbl.lower():
        return "DDoS"
    if "DoS" in lbl or "Heartbleed" in lbl:
        return "DoS"
    if "Port" in lbl or "PortScan" in lbl:
        return "Port Scan"
    if "Patator" in lbl or ("Brute Force" in lbl and "Web" not in lbl):
        return "Brute Force"
    if "Web Attack" in lbl or "Sql" in lbl or "XSS" in lbl:
        return "Web Attack"
    if "Bot" in lbl:
        return "Botnet"
    if "Infiltration" in lbl or "Infilteration" in lbl:
        return "Infiltration"
    return ATTACK_CATEGORY_MAP.get(lbl, "Other")


def compute_normalization_stats(raw_collection):
    """
    Compute global mean and standard deviation for features using MongoDB aggregation.

    Returns:
        dict: Mapping of feature -> (mean, std)
    """
    logger.info("Computing global statistics for numeric feature normalization...")
    group_stage = {"_id": None}
    for feat in NUMERIC_FEATURES_TO_NORMALIZE:
        group_stage[f"{feat}_mean"] = {"$avg": f"${feat}"}
        group_stage[f"{feat}_std"] = {"$stdDevPop": f"${feat}"}

    stats_map = {}
    try:
        results = list(raw_collection.aggregate([{"$group": group_stage}], allowDiskUse=True))
        if results:
            res = results[0]
            for feat in NUMERIC_FEATURES_TO_NORMALIZE:
                m = res.get(f"{feat}_mean") or 0.0
                s = res.get(f"{feat}_std") or 1.0
                if s == 0.0 or math.isnan(s):
                    s = 1.0
                stats_map[feat] = (float(m), float(s))
                logger.info(f"  Feature '{feat}': mean={m:.4f}, std={s:.4f}")
    except Exception as e:
        logger.warning(f"Aggregation stats computation note ({e}). Using robust defaults.")
        for feat in NUMERIC_FEATURES_TO_NORMALIZE:
            stats_map[feat] = (0.0, 1.0)

    return stats_map


def preprocess_and_stream(raw_collection, cleaned_collection, stats_map):
    """
    Stream documents from raw collection, clean, normalize, categorize,
    and insert into cleaned collection in batches.
    """
    total_docs = raw_collection.count_documents({})
    logger.info(f"Streaming and preprocessing {total_docs:,} documents in batches of {BATCH_SIZE}...")

    # Drop existing cleaned collection
    cleaned_collection.drop()

    cursor = raw_collection.find({}, {"_id": 0}, no_cursor_timeout=True).batch_size(BATCH_SIZE)
    timestamp = datetime.now(timezone.utc)

    total_inserted = 0
    batch = []
    category_counts = {}
    attack_count = 0
    benign_count = 0

    try:
        for doc in cursor:
            # Handle Label
            raw_label = doc.get(LABEL_COLUMN, "")
            label_clean = str(raw_label).strip() if raw_label is not None else BENIGN_LABEL
            doc[LABEL_COLUMN] = label_clean

            # Binary is_attack
            is_attack = 0 if label_clean.upper() == BENIGN_LABEL else 1
            doc["is_attack"] = is_attack
            if is_attack:
                attack_count += 1
            else:
                benign_count += 1

            # Attack category
            category = categorize_label(label_clean)
            doc["attack_category"] = category
            category_counts[category] = category_counts.get(category, 0) + 1

            # Normalize numeric features
            for feat, (m, s) in stats_map.items():
                val = doc.get(feat)
                try:
                    num_val = float(val) if val is not None and not math.isnan(float(val)) and not math.isinf(float(val)) else 0.0
                except (ValueError, TypeError):
                    num_val = 0.0
                doc[f"{feat}_normalized"] = (num_val - m) / s

            # Handle NaN / Infinity across any doc fields for BSON compliance
            for k, v in doc.items():
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    doc[k] = None

            doc["preprocessing_timestamp"] = timestamp
            batch.append(doc)

            if len(batch) >= BATCH_SIZE:
                cleaned_collection.insert_many(batch, ordered=False)
                total_inserted += len(batch)
                batch = []
                if total_inserted % (BATCH_SIZE * 5) == 0 or total_inserted == total_docs:
                    pct = (total_inserted / total_docs) * 100 if total_docs > 0 else 100
                    logger.info(f"  Cleaned & inserted {total_inserted:,}/{total_docs:,} records ({pct:.1f}%)")

        if batch:
            cleaned_collection.insert_many(batch, ordered=False)
            total_inserted += len(batch)
            logger.info(f"  Cleaned & inserted {total_inserted:,}/{total_docs:,} records (100.0%)")

    finally:
        cursor.close()

    # Create indexes for high-speed analysis
    logger.info("Creating indexes on 'cleaned_network_traffic'...")
    cleaned_collection.create_index("label")
    cleaned_collection.create_index("attack_category")
    cleaned_collection.create_index("is_attack")
    cleaned_collection.create_index("source_file")
    logger.info("Indexes created successfully.")

    # Print summary statistics
    logger.info("-" * 70)
    logger.info("PREPROCESSING SUMMARY")
    logger.info(f"  Total records cleaned: {total_inserted:,}")
    logger.info(f"  Benign records:        {benign_count:,} ({(benign_count / total_inserted)*100:.2f}%)")
    logger.info(f"  Attack records:        {attack_count:,} ({(attack_count / total_inserted)*100:.2f}%)")
    logger.info("  Attack Category Distribution:")
    for cat, cnt in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (cnt / total_inserted) * 100
        logger.info(f"    - {cat:<20}: {cnt:>10,} ({pct:.2f}%)")
    logger.info("-" * 70)

    return total_inserted


def main():
    """Main entry point for data preprocessing."""
    logger.info("=" * 70)
    logger.info("CIC-IDS-2017 Data Preprocessing Pipeline")
    logger.info("=" * 70)

    client, db = connect_to_mongodb()
    raw_col = db[MONGO_COLLECTION_RAW]
    clean_col = db[MONGO_COLLECTION_CLEANED]

    raw_count = raw_col.count_documents({})
    if raw_count == 0:
        logger.error(f"Collection '{MONGO_COLLECTION_RAW}' is empty! Run step2_ingest_to_mongodb.py first.")
        client.close()
        sys.exit(1)

    # 1. Compute dataset statistics for normalization
    stats_map = compute_normalization_stats(raw_col)

    # 2. Stream, clean, and insert into cleaned collection
    saved_count = preprocess_and_stream(raw_col, clean_col, stats_map)

    logger.info("=" * 70)
    logger.info("PREPROCESSING COMPLETE")
    logger.info(f"Cleaned collection: {MONGO_DATABASE}.{MONGO_COLLECTION_CLEANED}")
    logger.info(f"Total cleaned records: {saved_count:,}")
    logger.info("=" * 70)

    client.close()


if __name__ == "__main__":
    main()
