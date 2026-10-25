"""
Step 4: MapReduce Analysis for Network Intrusion Detection
==========================================================
This script implements 6 MapReduce operations on the CIC-IDS-2017 dataset
stored in MongoDB. Each operation defines formal Map, Reduce, and Finalize
JavaScript functions demonstrating the MapReduce paradigm, with an optimized
Aggregation Pipeline execution engine that scales efficiently across large-scale
datasets beyond MongoDB's 16MB intermediate BSON memory limit.

Database: network_intrusion_db
Collection: cleaned_network_traffic

Output collections:
    - mr_attack_distribution
    - mr_avg_flow_duration
    - mr_traffic_volume_by_day
    - mr_flag_analysis
    - mr_packet_size_stats
    - mr_flow_rate_analysis

Usage:
    python step4_mapreduce_analysis.py              # Fast pipeline (recommended)
    python step4_mapreduce_analysis.py --mapreduce  # Attempt legacy JS mapReduce

Author: Jane Brenna Christy
"""

import sys
import logging
from datetime import datetime
from bson.code import Code
from pymongo import MongoClient
from pymongo.errors import OperationFailure, ConnectionFailure

from config import MONGO_COLLECTION_CLEANED, MONGO_DATABASE, MONGO_URI

# Configure UTF-8 encoding for Windows terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Flag to determine whether to run legacy mapReduce command or fast aggregation pipeline
RUN_LEGACY_MAPREDUCE = "--mapreduce" in sys.argv

# ---------------------------------------------------------------------------
# MongoDB connection parameters
# ---------------------------------------------------------------------------
DATABASE_NAME = MONGO_DATABASE
COLLECTION_NAME = MONGO_COLLECTION_CLEANED


def get_db():
    """Return a handle to the MongoDB database."""
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    logger.info("Connected to MongoDB successfully.")
    return client[DATABASE_NAME]


# ===================================================================
# Helper: pretty-print MapReduce / aggregation results
# ===================================================================
def print_results(title: str, results: list, max_rows: int = 30):
    """Print a formatted table of results to the console."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)
    for i, doc in enumerate(results[:max_rows]):
        _id = str(doc.get("_id", "N/A")).replace("\ufffd", "-").replace("\u2013", "-")
        value = doc.get("value", doc)
        try:
            print(f"  {_id:<35} -> {value}")
        except Exception:
            safe_val = str(value).encode("ascii", "replace").decode("ascii")
            print(f"  {_id:<35} -> {safe_val}")
    if len(results) > max_rows:
        print(f"  ... and {len(results) - max_rows} more rows")
    print("=" * 70 + "\n")


# ===================================================================
# MapReduce 1 – Attack Type Distribution
# ===================================================================
def mr_attack_distribution(db):
    """
    Count occurrences of each traffic type (BENIGN, DDoS, PortScan, etc.).

    Map:  emit(this.label, 1)
    Reduce: sum the counts
    Output collection: mr_attack_distribution
    """
    title = "MapReduce 1: Attack Type Distribution"
    out_col = "mr_attack_distribution"
    logger.info("Running %s ...", title)

    # --- MapReduce JavaScript Functions ---
    mapper = Code("""
        function() {
            emit(this.label, 1);
        }
    """)
    reducer = Code("""
        function(key, values) {
            return Array.sum(values);
        }
    """)

    if RUN_LEGACY_MAPREDUCE:
        try:
            db.command(
                "mapReduce",
                COLLECTION_NAME,
                map=mapper,
                reduce=reducer,
                out=out_col,
            )
            logger.info("MapReduce command succeeded for '%s'.", title)
            docs = list(db[out_col].find().sort("value", -1))
            print_results(title, docs)
            return docs
        except Exception as exc:
            logger.warning("mapReduce command note (%s). Using aggregation pipeline.", exc)

    # --- Pipeline execution ---
    pipeline = [
        {"$group": {"_id": "$label", "value": {"$sum": 1}}},
        {"$sort": {"value": -1}},
    ]
    docs = list(db[COLLECTION_NAME].aggregate(pipeline, allowDiskUse=True))

    out = db[out_col]
    out.drop()
    if docs:
        out.insert_many(docs)
    logger.info("Completed analysis for '%s'.", title)
    print_results(title, docs)
    return docs


# ===================================================================
# MapReduce 2 – Average Flow Duration by Attack Category
# ===================================================================
def mr_avg_flow_duration(db):
    """
    Find which attack categories have the longest average flow durations.

    Map:  emit(attack_category, {sum: flow_duration, count: 1})
    Reduce: accumulate sums and counts
    Finalize: compute average = sum / count
    Output collection: mr_avg_flow_duration
    """
    title = "MapReduce 2: Average Flow Duration by Attack Category"
    out_col = "mr_avg_flow_duration"
    logger.info("Running %s ...", title)

    # --- MapReduce JavaScript Functions ---
    mapper = Code("""
        function() {
            emit(this.attack_category, {sum: this.flow_duration, count: 1});
        }
    """)
    reducer = Code("""
        function(key, values) {
            var result = {sum: 0, count: 0};
            values.forEach(function(v) {
                result.sum += v.sum;
                result.count += v.count;
            });
            return result;
        }
    """)
    finalizer = Code("""
        function(key, reducedVal) {
            reducedVal.avg = reducedVal.sum / reducedVal.count;
            return reducedVal;
        }
    """)

    if RUN_LEGACY_MAPREDUCE:
        try:
            db.command(
                "mapReduce",
                COLLECTION_NAME,
                map=mapper,
                reduce=reducer,
                finalize=finalizer,
                out=out_col,
            )
            logger.info("MapReduce command succeeded for '%s'.", title)
            docs = list(db[out_col].find().sort("value.avg", -1))
            print_results(title, docs)
            return docs
        except Exception as exc:
            logger.warning("mapReduce command note (%s). Using aggregation pipeline.", exc)

    # --- Pipeline execution ---
    pipeline = [
        {
            "$group": {
                "_id": "$attack_category",
                "sum": {"$sum": "$flow_duration"},
                "count": {"$sum": 1},
                "avg": {"$avg": "$flow_duration"},
            }
        },
        {"$project": {"_id": 1, "value": {"sum": "$sum", "count": "$count", "avg": "$avg"}}},
        {"$sort": {"value.avg": -1}},
    ]
    docs = list(db[COLLECTION_NAME].aggregate(pipeline, allowDiskUse=True))

    out = db[out_col]
    out.drop()
    if docs:
        out.insert_many(docs)
    logger.info("Completed analysis for '%s'.", title)
    print_results(title, docs)
    return docs


# ===================================================================
# MapReduce 3 – Network Traffic Volume by Source File (Day of Week)
# ===================================================================
def mr_traffic_volume_by_day(db):
    """
    Analyze traffic volume patterns across different capture days.

    Map:  emit(source_file, {total_bytes: fwd+bwd packet lengths, count: 1})
    Reduce: sum total_bytes and count
    Output collection: mr_traffic_volume_by_day
    """
    title = "MapReduce 3: Network Traffic Volume by Source File (Day)"
    out_col = "mr_traffic_volume_by_day"
    logger.info("Running %s ...", title)

    # --- MapReduce JavaScript Functions ---
    mapper = Code("""
        function() {
            var totalBytes = (this.total_length_of_fwd_packets || 0)
                           + (this.total_length_of_bwd_packets || 0);
            emit(this.source_file, {total_bytes: totalBytes, count: 1});
        }
    """)
    reducer = Code("""
        function(key, values) {
            var result = {total_bytes: 0, count: 0};
            values.forEach(function(v) {
                result.total_bytes += v.total_bytes;
                result.count += v.count;
            });
            return result;
        }
    """)

    if RUN_LEGACY_MAPREDUCE:
        try:
            db.command(
                "mapReduce",
                COLLECTION_NAME,
                map=mapper,
                reduce=reducer,
                out=out_col,
            )
            logger.info("MapReduce command succeeded for '%s'.", title)
            docs = list(db[out_col].find().sort("value.total_bytes", -1))
            print_results(title, docs)
            return docs
        except Exception as exc:
            logger.warning("mapReduce command note (%s). Using aggregation pipeline.", exc)

    # --- Pipeline execution ---
    pipeline = [
        {
            "$group": {
                "_id": "$source_file",
                "total_bytes": {
                    "$sum": {
                        "$add": [
                            {"$ifNull": ["$total_length_of_fwd_packets", 0]},
                            {"$ifNull": ["$total_length_of_bwd_packets", 0]},
                        ]
                    }
                },
                "count": {"$sum": 1},
            }
        },
        {"$project": {"_id": 1, "value": {"total_bytes": "$total_bytes", "count": "$count"}}},
        {"$sort": {"value.total_bytes": -1}},
    ]
    docs = list(db[COLLECTION_NAME].aggregate(pipeline, allowDiskUse=True))

    out = db[out_col]
    out.drop()
    if docs:
        out.insert_many(docs)
    logger.info("Completed analysis for '%s'.", title)
    print_results(title, docs)
    return docs


# ===================================================================
# MapReduce 4 – Flag Analysis per Attack Type
# ===================================================================
def mr_flag_analysis(db):
    """
    Understand which TCP flags are characteristic of each attack type.

    Map:  emit(label, {syn, fin, rst, psh, ack counts + total: 1})
    Reduce: sum all fields
    Finalize: compute averages (divide by total)
    Output collection: mr_flag_analysis
    """
    title = "MapReduce 4: Flag Analysis per Attack Type"
    out_col = "mr_flag_analysis"
    logger.info("Running %s ...", title)

    # --- MapReduce JavaScript Functions ---
    mapper = Code("""
        function() {
            emit(this.label, {
                syn_count:  this.syn_flag_count  || 0,
                fin_count:  this.fin_flag_count  || 0,
                rst_count:  this.rst_flag_count  || 0,
                psh_count:  this.psh_flag_count  || 0,
                ack_count:  this.ack_flag_count  || 0,
                total: 1
            });
        }
    """)
    reducer = Code("""
        function(key, values) {
            var r = {syn_count:0, fin_count:0, rst_count:0, psh_count:0, ack_count:0, total:0};
            values.forEach(function(v) {
                r.syn_count += v.syn_count;
                r.fin_count += v.fin_count;
                r.rst_count += v.rst_count;
                r.psh_count += v.psh_count;
                r.ack_count += v.ack_count;
                r.total     += v.total;
            });
            return r;
        }
    """)
    finalizer = Code("""
        function(key, r) {
            r.avg_syn = r.syn_count / r.total;
            r.avg_fin = r.fin_count / r.total;
            r.avg_rst = r.rst_count / r.total;
            r.avg_psh = r.psh_count / r.total;
            r.avg_ack = r.ack_count / r.total;
            return r;
        }
    """)

    if RUN_LEGACY_MAPREDUCE:
        try:
            db.command(
                "mapReduce",
                COLLECTION_NAME,
                map=mapper,
                reduce=reducer,
                finalize=finalizer,
                out=out_col,
            )
            logger.info("MapReduce command succeeded for '%s'.", title)
            docs = list(db[out_col].find().sort("_id", 1))
            print_results(title, docs)
            return docs
        except Exception as exc:
            logger.warning("mapReduce command note (%s). Using aggregation pipeline.", exc)

    # --- Pipeline execution ---
    pipeline = [
        {
            "$group": {
                "_id": "$label",
                "syn_count": {"$sum": {"$ifNull": ["$syn_flag_count", 0]}},
                "fin_count": {"$sum": {"$ifNull": ["$fin_flag_count", 0]}},
                "rst_count": {"$sum": {"$ifNull": ["$rst_flag_count", 0]}},
                "psh_count": {"$sum": {"$ifNull": ["$psh_flag_count", 0]}},
                "ack_count": {"$sum": {"$ifNull": ["$ack_flag_count", 0]}},
                "total": {"$sum": 1},
            }
        },
        {
            "$project": {
                "_id": 1,
                "value": {
                    "syn_count": "$syn_count",
                    "fin_count": "$fin_count",
                    "rst_count": "$rst_count",
                    "psh_count": "$psh_count",
                    "ack_count": "$ack_count",
                    "total": "$total",
                    "avg_syn": {"$divide": ["$syn_count", "$total"]},
                    "avg_fin": {"$divide": ["$fin_count", "$total"]},
                    "avg_rst": {"$divide": ["$rst_count", "$total"]},
                    "avg_psh": {"$divide": ["$psh_count", "$total"]},
                    "avg_ack": {"$divide": ["$ack_count", "$total"]},
                },
            }
        },
        {"$sort": {"_id": 1}},
    ]
    docs = list(db[COLLECTION_NAME].aggregate(pipeline, allowDiskUse=True))

    out = db[out_col]
    out.drop()
    if docs:
        out.insert_many(docs)
    logger.info("Completed analysis for '%s'.", title)
    print_results(title, docs)
    return docs


# ===================================================================
# MapReduce 5 – Packet Size Statistics by Attack Category
# ===================================================================
def mr_packet_size_stats(db):
    """
    Characterize packet size patterns for anomaly detection.

    Map:  emit(attack_category, {min_pkt, max_pkt, avg_pkt_sum, count})
    Reduce: track min of mins, max of maxes, sum avg_pkt_sum & count
    Finalize: compute overall_avg_packet_size
    Output collection: mr_packet_size_stats
    """
    title = "MapReduce 5: Packet Size Statistics by Attack Category"
    out_col = "mr_packet_size_stats"
    logger.info("Running %s ...", title)

    # --- MapReduce JavaScript Functions ---
    mapper = Code("""
        function() {
            emit(this.attack_category, {
                min_pkt:     this.min_packet_length   || 0,
                max_pkt:     this.max_packet_length   || 0,
                avg_pkt_sum: this.average_packet_size  || 0,
                count: 1
            });
        }
    """)
    reducer = Code("""
        function(key, values) {
            var r = {min_pkt: Infinity, max_pkt: -Infinity, avg_pkt_sum: 0, count: 0};
            values.forEach(function(v) {
                if (v.min_pkt < r.min_pkt) r.min_pkt = v.min_pkt;
                if (v.max_pkt > r.max_pkt) r.max_pkt = v.max_pkt;
                r.avg_pkt_sum += v.avg_pkt_sum;
                r.count       += v.count;
            });
            return r;
        }
    """)
    finalizer = Code("""
        function(key, r) {
            r.overall_avg_packet_size = r.avg_pkt_sum / r.count;
            return r;
        }
    """)

    if RUN_LEGACY_MAPREDUCE:
        try:
            db.command(
                "mapReduce",
                COLLECTION_NAME,
                map=mapper,
                reduce=reducer,
                finalize=finalizer,
                out=out_col,
            )
            logger.info("MapReduce command succeeded for '%s'.", title)
            docs = list(db[out_col].find().sort("_id", 1))
            print_results(title, docs)
            return docs
        except Exception as exc:
            logger.warning("mapReduce command note (%s). Using aggregation pipeline.", exc)

    # --- Pipeline execution ---
    pipeline = [
        {
            "$group": {
                "_id": "$attack_category",
                "min_pkt": {"$min": {"$ifNull": ["$min_packet_length", 0]}},
                "max_pkt": {"$max": {"$ifNull": ["$max_packet_length", 0]}},
                "avg_pkt_sum": {"$sum": {"$ifNull": ["$average_packet_size", 0]}},
                "count": {"$sum": 1},
            }
        },
        {
            "$project": {
                "_id": 1,
                "value": {
                    "min_pkt": "$min_pkt",
                    "max_pkt": "$max_pkt",
                    "avg_pkt_sum": "$avg_pkt_sum",
                    "count": "$count",
                    "overall_avg_packet_size": {"$divide": ["$avg_pkt_sum", "$count"]},
                },
            }
        },
        {"$sort": {"_id": 1}},
    ]
    docs = list(db[COLLECTION_NAME].aggregate(pipeline, allowDiskUse=True))

    out = db[out_col]
    out.drop()
    if docs:
        out.insert_many(docs)
    logger.info("Completed analysis for '%s'.", title)
    print_results(title, docs)
    return docs


# ===================================================================
# MapReduce 6 – Flow Rate Analysis (Bytes/s & Packets/s) by Attack Type
# ===================================================================
def mr_flow_rate_analysis(db):
    """
    Identify high-volume / high-rate attack patterns.

    Map:  emit(attack_category, {bytes_per_sec_sum, packets_per_sec_sum, count})
    Reduce: sum all
    Finalize: compute averages
    Output collection: mr_flow_rate_analysis
    """
    title = "MapReduce 6: Flow Rate Analysis by Attack Type"
    out_col = "mr_flow_rate_analysis"
    logger.info("Running %s ...", title)

    # --- MapReduce JavaScript Functions ---
    mapper = Code("""
        function() {
            var bps = this["flow_bytes/s"] || 0;
            var pps = this["flow_packets/s"] || 0;
            if (!isFinite(bps)) bps = 0;
            if (!isFinite(pps)) pps = 0;
            emit(this.attack_category, {
                bytes_per_sec_sum:   bps,
                packets_per_sec_sum: pps,
                count: 1
            });
        }
    """)
    reducer = Code("""
        function(key, values) {
            var r = {bytes_per_sec_sum: 0, packets_per_sec_sum: 0, count: 0};
            values.forEach(function(v) {
                r.bytes_per_sec_sum   += v.bytes_per_sec_sum;
                r.packets_per_sec_sum += v.packets_per_sec_sum;
                r.count               += v.count;
            });
            return r;
        }
    """)
    finalizer = Code("""
        function(key, r) {
            r.avg_bytes_per_sec   = r.bytes_per_sec_sum   / r.count;
            r.avg_packets_per_sec = r.packets_per_sec_sum / r.count;
            return r;
        }
    """)

    if RUN_LEGACY_MAPREDUCE:
        try:
            db.command(
                "mapReduce",
                COLLECTION_NAME,
                map=mapper,
                reduce=reducer,
                finalize=finalizer,
                out=out_col,
            )
            logger.info("MapReduce command succeeded for '%s'.", title)
            docs = list(db[out_col].find().sort("_id", 1))
            print_results(title, docs)
            return docs
        except Exception as exc:
            logger.warning("mapReduce command note (%s). Using aggregation pipeline.", exc)

    # --- Pipeline execution ---
    pipeline = [
        {
            "$group": {
                "_id": "$attack_category",
                "bytes_per_sec_sum": {
                    "$sum": {"$ifNull": ["$flow_bytes/s", 0]}
                },
                "packets_per_sec_sum": {
                    "$sum": {"$ifNull": ["$flow_packets/s", 0]}
                },
                "count": {"$sum": 1},
            }
        },
        {
            "$project": {
                "_id": 1,
                "value": {
                    "bytes_per_sec_sum": "$bytes_per_sec_sum",
                    "packets_per_sec_sum": "$packets_per_sec_sum",
                    "count": "$count",
                    "avg_bytes_per_sec": {"$divide": ["$bytes_per_sec_sum", "$count"]},
                    "avg_packets_per_sec": {"$divide": ["$packets_per_sec_sum", "$count"]},
                },
            }
        },
        {"$sort": {"_id": 1}},
    ]
    docs = list(db[COLLECTION_NAME].aggregate(pipeline, allowDiskUse=True))

    out = db[out_col]
    out.drop()
    if docs:
        out.insert_many(docs)
    logger.info("Completed analysis for '%s'.", title)
    print_results(title, docs)
    return docs


# ===================================================================
# Main execution
# ===================================================================
def main():
    """Run all six MapReduce analyses sequentially."""
    start = datetime.now()
    logger.info("=" * 60)
    logger.info("Starting MapReduce Analysis Pipeline")
    logger.info("=" * 60)

    client = None
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        db = client[DATABASE_NAME]
        logger.info("Connected to MongoDB successfully.")
    except ConnectionFailure as exc:
        logger.error("Could not connect to MongoDB: %s", exc)
        return 1

    # Verify the source collection exists and has data
    doc_count = db[COLLECTION_NAME].estimated_document_count()
    logger.info("Collection '%s' contains ~%d documents.", COLLECTION_NAME, doc_count)
    if doc_count == 0:
        logger.error("Source collection is empty. Run the data ingestion steps first.")
        client.close()
        return 1

    # Execute each MapReduce operation
    mr_attack_distribution(db)
    mr_avg_flow_duration(db)
    mr_traffic_volume_by_day(db)
    mr_flag_analysis(db)
    mr_packet_size_stats(db)
    mr_flow_rate_analysis(db)

    elapsed = datetime.now() - start
    logger.info("All MapReduce operations completed in %s.", elapsed)
    print(f"\n✅ All 6 MapReduce analyses finished successfully in {elapsed}.")
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
