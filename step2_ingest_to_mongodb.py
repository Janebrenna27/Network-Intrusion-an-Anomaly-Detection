"""
step2_ingest_to_mongodb.py - Ingest CIC-IDS-2017 CSV data into MongoDB.

This script reads all CSV files from the downloaded CIC-IDS-2017 dataset,
cleans column names, handles encoding issues, and inserts records into
MongoDB in batches for optimal performance.

Usage:
    python step2_ingest_to_mongodb.py

Prerequisites:
    - Run step1_download_dataset.py first to download the dataset
    - MongoDB must be running on localhost:27017
"""

import os
import sys
import logging
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from pymongo import MongoClient

from config import (
    BATCH_SIZE,
    CSV_ENCODINGS,
    DATASET_DIR,
    EXPECTED_CSV_FILES,
    LOG_FORMAT,
    LOG_LEVEL,
    MONGO_COLLECTION_RAW,
    MONGO_DATABASE,
    MONGO_URI,
)

# Configure logging
logging.basicConfig(format=LOG_FORMAT, level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)


def connect_to_mongodb():
    """
    Establish a connection to MongoDB and return the database handle.

    Returns:
        tuple: (MongoClient, Database) - the client and database objects.

    Raises:
        ConnectionError: If unable to connect to MongoDB.
    """
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        # Verify connection by requesting server info
        client.server_info()
        db = client[MONGO_DATABASE]
        logger.info(f"Connected to MongoDB at {MONGO_URI}")
        logger.info(f"Database: {MONGO_DATABASE}")
        return client, db
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        logger.error("Make sure MongoDB is running on localhost:27017")
        raise ConnectionError(f"MongoDB connection failed: {e}")


def find_dataset_path():
    """
    Locate the downloaded CIC-IDS-2017 dataset directory.

    Searches local dataset folder and kagglehub cache locations.

    Returns:
        str: Path to the dataset directory containing CSV files.

    Raises:
        FileNotFoundError: If the dataset directory cannot be found.
    """
    # 1. First check local project dataset directory
    if os.path.exists(DATASET_DIR):
        csv_files = [f for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]
        if csv_files:
            return DATASET_DIR

    # 2. Check current directory dataset subfolder
    local_sub = os.path.join(os.path.dirname(__file__), "dataset")
    if os.path.exists(local_sub):
        csv_files = [f for f in os.listdir(local_sub) if f.endswith(".csv")]
        if csv_files:
            return local_sub

    # 3. Check common kagglehub cache paths
    possible_paths = [
        os.path.join(os.path.expanduser("~"), ".cache", "kagglehub", "datasets",
                     "ciaboromani", "cicids2017", "versions"),
    ]

    for base_path in possible_paths:
        if os.path.exists(base_path):
            versions = sorted(os.listdir(base_path))
            if versions:
                dataset_path = os.path.join(base_path, versions[-1])
                csv_found = any(f.endswith(".csv") for f in os.listdir(dataset_path))
                if csv_found:
                    return dataset_path
                for subdir in os.listdir(dataset_path):
                    sub_path = os.path.join(dataset_path, subdir)
                    if os.path.isdir(sub_path):
                        csv_found = any(f.endswith(".csv") for f in os.listdir(sub_path))
                        if csv_found:
                            return sub_path

    # If non-interactive, fail immediately
    if not sys.stdin or not sys.stdin.isatty():
        raise FileNotFoundError(f"Dataset path not found. Please run step1_download_dataset.py first.")

    # If interactive, prompt user
    logger.warning("Could not automatically locate the dataset.")
    logger.info("Please enter the path to the dataset directory containing CSV files:")
    user_path = input("Dataset path: ").strip()
    if os.path.exists(user_path):
        return user_path
    raise FileNotFoundError(f"Dataset path not found: {user_path}")


def clean_column_names(df):
    """
    Clean DataFrame column names: strip whitespace, replace spaces
    with underscores, and convert to lowercase.

    Args:
        df (pd.DataFrame): DataFrame with original column names.

    Returns:
        pd.DataFrame: DataFrame with cleaned column names.
    """
    df.columns = (
        df.columns.str.strip()
        .str.replace(" ", "_", regex=False)
        .str.lower()
    )
    return df


def read_csv_with_fallback(filepath):
    """
    Read a CSV file with encoding fallback (try utf-8, then latin-1).

    Args:
        filepath (str): Path to the CSV file.

    Returns:
        pd.DataFrame: The loaded DataFrame.

    Raises:
        Exception: If the file cannot be read with any encoding.
    """
    for encoding in CSV_ENCODINGS:
        try:
            df = pd.read_csv(filepath, encoding=encoding, low_memory=False)
            logger.info(f"  Successfully read with encoding: {encoding}")
            return df
        except UnicodeDecodeError:
            logger.warning(f"  Failed with encoding: {encoding}, trying next...")
            continue
    raise Exception(f"Could not read file {filepath} with any supported encoding.")


def clean_dataframe_values(df):
    """
    Clean DataFrame values: replace NaN and inf values with None
    for MongoDB compatibility.

    Args:
        df (pd.DataFrame): DataFrame to clean.

    Returns:
        pd.DataFrame: Cleaned DataFrame.
    """
    # Replace infinity values with NaN first, then convert NaN to None
    df = df.replace([np.inf, -np.inf], np.nan)
    # Convert to object dtype where there are NaN values to allow None
    df = df.where(df.notna(), other=None)
    return df


def ingest_csv_file(collection, filepath, source_filename):
    """
    Ingest a single CSV file into MongoDB using chunked batch insertion.

    Args:
        collection: MongoDB collection object.
        filepath (str): Full path to the CSV file.
        source_filename (str): Name of the source file (for metadata).

    Returns:
        int: Number of records inserted from this file.
    """
    logger.info(f"Processing: {source_filename}")

    # Read the CSV file with encoding fallback
    df = read_csv_with_fallback(filepath)
    total_rows = len(df)
    logger.info(f"  Rows loaded: {total_rows:,}")
    logger.info(f"  Columns: {len(df.columns)}")

    # Clean column names
    df = clean_column_names(df)

    # Clean data values (NaN, inf -> None)
    df = clean_dataframe_values(df)

    # Add metadata columns directly to DataFrame
    ingestion_timestamp = datetime.now(timezone.utc)
    df["source_file"] = source_filename
    df["ingestion_timestamp"] = ingestion_timestamp

    # Insert in batches for optimal performance and memory safety
    total_inserted = 0
    for i in range(0, total_rows, BATCH_SIZE):
        batch_df = df.iloc[i : i + BATCH_SIZE]
        batch_records = batch_df.to_dict(orient="records")
        try:
            collection.insert_many(batch_records, ordered=False)
            total_inserted += len(batch_records)
            progress = (total_inserted / total_rows) * 100
            if total_inserted % (BATCH_SIZE * 5) == 0 or total_inserted == total_rows:
                logger.info(
                    f"  Inserted {total_inserted:,}/{total_rows:,} "
                    f"records ({progress:.1f}%)"
                )
        except Exception as e:
            logger.error(f"  Error inserting batch at index {i}: {e}")
            raise

    logger.info(f"  Completed: {total_inserted:,} records inserted from {source_filename}")
    return total_inserted


def main():
    """Main entry point for the data ingestion script."""
    logger.info("=" * 70)
    logger.info("CIC-IDS-2017 Data Ingestion to MongoDB")
    logger.info("=" * 70)

    # Step 1: Connect to MongoDB
    try:
        client, db = connect_to_mongodb()
    except ConnectionError:
        sys.exit(1)

    collection = db[MONGO_COLLECTION_RAW]

    # Step 2: Check if collection already has data
    existing_count = collection.count_documents({})
    if existing_count > 0:
        logger.warning(f"Collection '{MONGO_COLLECTION_RAW}' already has {existing_count:,} documents.")
        # If running via script / non-interactive, drop collection for fresh, clean run
        if "--drop" in sys.argv or "--clean" in sys.argv or not sys.stdin or not sys.stdin.isatty():
            collection.drop()
            logger.info("Existing collection dropped for a clean re-ingestion.")
        else:
            user_input = input("Do you want to drop the existing collection and re-ingest? (y/n): ").strip().lower()
            if user_input == "y":
                collection.drop()
                logger.info("Existing collection dropped.")
            else:
                logger.info("Keeping existing data. New records will be appended.")

    # Step 3: Find the dataset
    try:
        dataset_path = find_dataset_path()
        logger.info(f"Dataset directory: {dataset_path}")
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)

    # Step 4: List and process CSV files
    csv_files = []
    for root, dirs, files in os.walk(dataset_path):
        for f in files:
            if f.endswith(".csv"):
                csv_files.append(os.path.join(root, f))

    if not csv_files:
        logger.error("No CSV files found in the dataset directory.")
        sys.exit(1)

    logger.info(f"Found {len(csv_files)} CSV file(s) to process:")
    for f in csv_files:
        logger.info(f"  - {os.path.basename(f)}")

    # Step 5: Ingest each CSV file
    logger.info("-" * 70)
    total_records = 0
    files_processed = 0
    start_time = datetime.now()

    for csv_file in csv_files:
        filename = os.path.basename(csv_file)
        try:
            count = ingest_csv_file(collection, csv_file, filename)
            total_records += count
            files_processed += 1
        except Exception as e:
            logger.error(f"Failed to ingest {filename}: {e}")
            logger.error("Continuing with next file...")
            continue

    # Step 6: Print summary
    elapsed_time = datetime.now() - start_time
    logger.info("=" * 70)
    logger.info("INGESTION SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Files processed:  {files_processed}/{len(csv_files)}")
    logger.info(f"Total records:    {total_records:,}")
    logger.info(f"Time elapsed:     {elapsed_time}")
    logger.info(f"Collection:       {MONGO_DATABASE}.{MONGO_COLLECTION_RAW}")

    # Verify final count in MongoDB
    final_count = collection.count_documents({})
    logger.info(f"MongoDB count:    {final_count:,}")

    # Create indexes for fast aggregation and querying
    logger.info("Creating indexes on 'label' and 'source_file'...")
    collection.create_index("label")
    collection.create_index("source_file")
    logger.info("Indexes created successfully.")

    # Print label distribution
    logger.info("-" * 70)
    logger.info("Label distribution (sample):")
    pipeline = [
        {"$group": {"_id": "$label", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    for doc in collection.aggregate(pipeline):
        logger.info(f"  {doc['_id']}: {doc['count']:,}")

    logger.info("-" * 70)
    logger.info("NEXT STEPS:")
    logger.info("  1. Run: python step3_data_preprocessing.py")
    logger.info("=" * 70)

    # Close MongoDB connection
    client.close()
    logger.info("MongoDB connection closed.")


if __name__ == "__main__":
    main()
