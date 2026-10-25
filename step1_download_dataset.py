"""
step1_download_dataset.py - Download the CIC-IDS-2017 dataset from Kaggle.

This script uses kagglehub to download the CIC-IDS-2017 network intrusion
detection dataset. The dataset contains labeled network traffic data with
both benign and various attack types (DDoS, PortScan, Bot, etc.).

Usage:
    python step1_download_dataset.py

Prerequisites:
    - Install dependencies: pip install -r requirements.txt
    - Configure Kaggle API credentials (see https://www.kaggle.com/docs/api)
"""

import os
import sys
import logging

import kagglehub

import urllib.request
import time

from config import DATASET_NAME, DATASET_DIR, EXPECTED_CSV_FILES, HF_DATASET_URL, LOG_FORMAT, LOG_LEVEL

# Configure logging
logging.basicConfig(format=LOG_FORMAT, level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)


def download_file_with_progress(url, dest_path):
    """Download a file with real-time progress logging."""
    logger.info(f"Downloading {os.path.basename(dest_path)} from mirror...")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    with urllib.request.urlopen(req) as response, open(dest_path, "wb") as out_file:
        total_size = int(response.headers.get("Content-Length", 0))
        downloaded = 0
        chunk_size = 1024 * 1024  # 1 MB chunks
        last_log = time.time()

        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            out_file.write(chunk)
            downloaded += len(chunk)
            # Log progress every 2 seconds or when finished
            if time.time() - last_log > 2 or downloaded == total_size:
                if total_size > 0:
                    pct = (downloaded / total_size) * 100
                    mb = downloaded / (1024 * 1024)
                    tot_mb = total_size / (1024 * 1024)
                    logger.info(f"  {mb:.1f}/{tot_mb:.1f} MB ({pct:.1f}%)")
                else:
                    mb = downloaded / (1024 * 1024)
                    logger.info(f"  {mb:.1f} MB downloaded")
                last_log = time.time()


def download_from_hf_mirror():
    """Download the CIC-IDS-2017 dataset from the open Hugging Face mirror."""
    os.makedirs(DATASET_DIR, exist_ok=True)
    logger.info(f"Target dataset directory: {DATASET_DIR}")

    for idx, filename in enumerate(EXPECTED_CSV_FILES, 1):
        dest_file = os.path.join(DATASET_DIR, filename)
        if os.path.exists(dest_file) and os.path.getsize(dest_file) > 1000:
            sz_mb = os.path.getsize(dest_file) / (1024 * 1024)
            logger.info(f"[{idx}/{len(EXPECTED_CSV_FILES)}] Already exists: {filename} ({sz_mb:.1f} MB)")
            continue

        file_url = f"{HF_DATASET_URL}/{filename}"
        logger.info(f"[{idx}/{len(EXPECTED_CSV_FILES)}] Fetching {filename}...")
        try:
            download_file_with_progress(file_url, dest_file)
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")
            if os.path.exists(dest_file):
                os.remove(dest_file)
            raise

    return DATASET_DIR


def download_dataset():
    """
    Download the CIC-IDS-2017 dataset using kagglehub, with fallback to open mirror.

    Returns:
        str: The local path where the dataset was downloaded.
    """
    logger.info("=" * 70)
    logger.info("CIC-IDS-2017 Dataset Downloader")
    logger.info("=" * 70)
    logger.info(f"Primary source: Kaggle ({DATASET_NAME})")

    # Check if local dataset already exists and is complete
    if os.path.exists(DATASET_DIR):
        existing = [f for f in EXPECTED_CSV_FILES if os.path.exists(os.path.join(DATASET_DIR, f))]
        if len(existing) == len(EXPECTED_CSV_FILES):
            logger.info(f"All {len(existing)} CSV files already present in {DATASET_DIR}!")
            return DATASET_DIR

    try:
        # Attempt download using kagglehub
        logger.info("Attempting download via kagglehub...")
        dataset_path = kagglehub.dataset_download(DATASET_NAME)
        logger.info(f"Kaggle download complete! Dataset path: {dataset_path}")
        return dataset_path

    except Exception as e:
        logger.warning(f"Kaggle download did not succeed ({e}).")
        logger.info("Falling back to open mirror (Hugging Face CDN)...")
        return download_from_hf_mirror()


def list_csv_files(dataset_path):
    """
    List all CSV files found in the downloaded dataset directory.

    Args:
        dataset_path (str): Path to the downloaded dataset directory.

    Returns:
        list: List of CSV file paths found in the dataset directory.
    """
    csv_files = []

    # Walk through the dataset directory to find all CSV files
    for root, dirs, files in os.walk(dataset_path):
        for file in files:
            if file.lower().endswith(".csv"):
                full_path = os.path.join(root, file)
                csv_files.append(full_path)

    return csv_files


def main():
    """Main entry point for the dataset download script."""
    try:
        # Step 1: Download the dataset
        dataset_path = download_dataset()

        # Step 2: List available CSV files
        logger.info("-" * 70)
        logger.info("Scanning for CSV files...")
        csv_files = list_csv_files(dataset_path)

        if csv_files:
            logger.info(f"Found {len(csv_files)} CSV file(s):")
            for i, csv_file in enumerate(csv_files, 1):
                file_size = os.path.getsize(csv_file)
                size_mb = file_size / (1024 * 1024)
                logger.info(f"  {i}. {os.path.basename(csv_file)} ({size_mb:.1f} MB)")
        else:
            logger.warning("No CSV files found in the dataset directory.")
            logger.warning(f"Please check the directory: {dataset_path}")
            sys.exit(1)

        # Step 3: Print next steps
        logger.info("-" * 70)
        logger.info("NEXT STEPS:")
        logger.info(
            f"  1. Note the dataset path: {dataset_path}"
        )
        logger.info(
            "  2. Make sure MongoDB is running on localhost:27017"
        )
        logger.info(
            "  3. Run: python step2_ingest_to_mongodb.py"
        )
        logger.info("=" * 70)

        return dataset_path

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
