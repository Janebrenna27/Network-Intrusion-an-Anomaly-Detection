"""
Step 5: Visualization for Network Intrusion Detection Analysis
===============================================================
This script creates comprehensive visualizations from the MapReduce
results (or raw data) stored in MongoDB for the CIC-IDS-2017 dataset.

All charts are saved to:
    c:\\Users\\Jane Brenna Christy\\OneDrive\\Desktop\\Big_Data_IA3\\visualizations\\

Database: network_intrusion_db
Source collection: cleaned_network_traffic
MapReduce output collections:
    - mr_attack_distribution
    - mr_avg_flow_duration
    - mr_traffic_volume_by_day
    - mr_flag_analysis
    - mr_packet_size_stats
    - mr_flow_rate_analysis

Author: Jane Brenna Christy
"""

import os
import sys
import logging
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend; switch to "TkAgg" for plt.show()
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
import pandas as pd
import numpy as np
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from config import MONGO_COLLECTION_CLEANED, MONGO_DATABASE, MONGO_URI, VISUALIZATIONS_DIR

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths and MongoDB settings
# ---------------------------------------------------------------------------
VIS_DIR = VISUALIZATIONS_DIR
DATABASE_NAME = MONGO_DATABASE
RAW_COLLECTION = MONGO_COLLECTION_CLEANED

# Ensure the output directory exists
os.makedirs(VIS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
PALETTE = sns.color_palette("Set2", 15)
ATTACK_PALETTE = sns.color_palette("husl", 15)
sns.set_theme(style="whitegrid", font_scale=1.1)


def get_db():
    """Return a handle to the MongoDB database."""
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    logger.info("Connected to MongoDB successfully.")
    return client[DATABASE_NAME]


def collection_exists(db, name: str) -> bool:
    """Check whether a collection exists and has documents."""
    return name in db.list_collection_names() and db[name].estimated_document_count() > 0


def save_figure(fig, filename: str):
    """Save a matplotlib figure to the visualizations directory."""
    path = os.path.join(VIS_DIR, filename)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    logger.info("Saved visualization: %s", path)


# ===================================================================
# 1. Attack Type Distribution – Bar Chart (Top 15)
# ===================================================================
def viz_attack_type_distribution(db):
    """Bar chart showing count of each attack type (top 15)."""
    logger.info("Creating Visualization 1: Attack Type Distribution ...")

    if collection_exists(db, "mr_attack_distribution"):
        docs = list(db["mr_attack_distribution"].find().sort("value", -1))
        labels = [d["_id"] for d in docs]
        counts = [d["value"] for d in docs]
    else:
        logger.info("MR collection not found – querying raw data.")
        pipeline = [
            {"$group": {"_id": "$label", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
        labels = [d["_id"] for d in docs]
        counts = [d["count"] for d in docs]

    # Keep top 15
    labels = labels[:15]
    counts = counts[:15]

    fig, ax = plt.subplots(figsize=(14, 7))
    bars = ax.bar(range(len(labels)), counts, color=ATTACK_PALETTE[: len(labels)], edgecolor="black", linewidth=0.5)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=10)
    ax.set_ylabel("Number of Flows", fontsize=12)
    ax.set_title("Attack Type Distribution (Top 15)", fontsize=14, fontweight="bold")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    # Add count labels on top of bars
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{count:,.0f}", ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    save_figure(fig, "01_attack_type_distribution.png")
    # plt.show()


# ===================================================================
# 2. Benign vs Attack Traffic – Pie Chart
# ===================================================================
def viz_benign_vs_attack(db):
    """Pie chart showing proportion of benign vs attack traffic."""
    logger.info("Creating Visualization 2: Benign vs Attack Traffic ...")

    pipeline = [
        {"$group": {"_id": "$is_attack", "count": {"$sum": 1}}},
    ]
    docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))

    label_map = {True: "Attack", False: "Benign", 1: "Attack", 0: "Benign",
                 "true": "Attack", "false": "Benign", "True": "Attack", "False": "Benign"}
    pie_labels = []
    pie_counts = []
    for d in docs:
        pie_labels.append(label_map.get(d["_id"], str(d["_id"])))
        pie_counts.append(d["count"])

    colors = ["#e74c3c", "#2ecc71"] if pie_labels and pie_labels[0] == "Attack" else ["#2ecc71", "#e74c3c"]

    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        pie_counts,
        labels=pie_labels,
        autopct="%1.1f%%",
        startangle=140,
        colors=colors,
        textprops={"fontsize": 13},
        wedgeprops={"edgecolor": "white", "linewidth": 2},
    )
    for t in autotexts:
        t.set_fontweight("bold")
    ax.set_title("Benign vs Attack Traffic", fontsize=14, fontweight="bold")

    fig.tight_layout()
    save_figure(fig, "02_benign_vs_attack.png")
    # plt.show()


# ===================================================================
# 3. Average Flow Duration by Attack Category – Horizontal Bar
# ===================================================================
def viz_avg_flow_duration(db):
    """Horizontal bar chart of average flow duration by attack category."""
    logger.info("Creating Visualization 3: Average Flow Duration by Attack Category ...")

    if collection_exists(db, "mr_avg_flow_duration"):
        docs = list(db["mr_avg_flow_duration"].find().sort("value.avg", -1))
        categories = [d["_id"] for d in docs]
        avgs = [d["value"]["avg"] for d in docs]
    else:
        logger.info("MR collection not found – querying raw data.")
        pipeline = [
            {"$group": {"_id": "$attack_category", "avg": {"$avg": "$flow_duration"}}},
            {"$sort": {"avg": -1}},
        ]
        docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
        categories = [d["_id"] for d in docs]
        avgs = [d["avg"] for d in docs]

    fig, ax = plt.subplots(figsize=(12, 6))
    y_pos = range(len(categories))
    ax.barh(y_pos, avgs, color=sns.color_palette("coolwarm", len(categories)), edgecolor="black", linewidth=0.5)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(categories, fontsize=11)
    ax.set_xlabel("Average Flow Duration (μs)", fontsize=12)
    ax.set_title("Average Flow Duration by Attack Category", fontsize=14, fontweight="bold")
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    ax.invert_yaxis()

    fig.tight_layout()
    save_figure(fig, "03_avg_flow_duration.png")
    # plt.show()


# ===================================================================
# 4. TCP Flag Patterns Heatmap
# ===================================================================
def viz_flag_heatmap(db):
    """Heatmap showing average TCP flag counts per attack type."""
    logger.info("Creating Visualization 4: TCP Flag Patterns Heatmap ...")

    flag_cols = ["avg_syn", "avg_fin", "avg_rst", "avg_psh", "avg_ack"]
    display_cols = ["SYN", "FIN", "RST", "PSH", "ACK"]

    if collection_exists(db, "mr_flag_analysis"):
        docs = list(db["mr_flag_analysis"].find().sort("_id", 1))
        rows = []
        for d in docs:
            v = d["value"]
            rows.append({
                "Attack Type": d["_id"],
                "SYN": v.get("avg_syn", 0),
                "FIN": v.get("avg_fin", 0),
                "RST": v.get("avg_rst", 0),
                "PSH": v.get("avg_psh", 0),
                "ACK": v.get("avg_ack", 0),
            })
    else:
        logger.info("MR collection not found – querying raw data.")
        pipeline = [
            {
                "$group": {
                    "_id": "$label",
                    "SYN": {"$avg": {"$ifNull": ["$syn_flag_count", 0]}},
                    "FIN": {"$avg": {"$ifNull": ["$fin_flag_count", 0]}},
                    "RST": {"$avg": {"$ifNull": ["$rst_flag_count", 0]}},
                    "PSH": {"$avg": {"$ifNull": ["$psh_flag_count", 0]}},
                    "ACK": {"$avg": {"$ifNull": ["$ack_flag_count", 0]}},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
        rows = []
        for d in docs:
            rows.append({
                "Attack Type": d["_id"],
                "SYN": d.get("SYN", 0),
                "FIN": d.get("FIN", 0),
                "RST": d.get("RST", 0),
                "PSH": d.get("PSH", 0),
                "ACK": d.get("ACK", 0),
            })

    df = pd.DataFrame(rows).set_index("Attack Type")

    fig, ax = plt.subplots(figsize=(10, max(6, len(df) * 0.5)))
    sns.heatmap(df, annot=True, fmt=".2f", cmap="YlOrRd", linewidths=0.5,
                linecolor="gray", ax=ax, cbar_kws={"label": "Average Flag Count"})
    ax.set_title("TCP Flag Patterns by Attack Type", fontsize=14, fontweight="bold")
    ax.set_ylabel("")

    fig.tight_layout()
    save_figure(fig, "04_flag_patterns_heatmap.png")
    # plt.show()


# ===================================================================
# 5. Packet Size Distribution by Category – Grouped Bar Chart
# ===================================================================
def viz_packet_size_distribution(db):
    """Grouped bar chart of min, max, and average packet sizes by category."""
    logger.info("Creating Visualization 5: Packet Size Distribution by Category ...")

    if collection_exists(db, "mr_packet_size_stats"):
        docs = list(db["mr_packet_size_stats"].find().sort("_id", 1))
        categories = [d["_id"] for d in docs]
        min_pkts = [d["value"].get("min_pkt", 0) for d in docs]
        max_pkts = [d["value"].get("max_pkt", 0) for d in docs]
        avg_pkts = [d["value"].get("overall_avg_packet_size", 0) for d in docs]
    else:
        logger.info("MR collection not found – querying raw data.")
        pipeline = [
            {
                "$group": {
                    "_id": "$attack_category",
                    "min_pkt": {"$min": "$min_packet_length"},
                    "max_pkt": {"$max": "$max_packet_length"},
                    "avg_pkt": {"$avg": "$average_packet_size"},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
        categories = [d["_id"] for d in docs]
        min_pkts = [d.get("min_pkt", 0) for d in docs]
        max_pkts = [d.get("max_pkt", 0) for d in docs]
        avg_pkts = [d.get("avg_pkt", 0) for d in docs]

    x = np.arange(len(categories))
    width = 0.25

    fig, ax = plt.subplots(figsize=(14, 7))
    ax.bar(x - width, min_pkts, width, label="Min Packet Length", color="#3498db", edgecolor="black", linewidth=0.5)
    ax.bar(x, avg_pkts, width, label="Avg Packet Size", color="#2ecc71", edgecolor="black", linewidth=0.5)
    ax.bar(x + width, max_pkts, width, label="Max Packet Length", color="#e74c3c", edgecolor="black", linewidth=0.5)

    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=45, ha="right", fontsize=10)
    ax.set_ylabel("Packet Size (bytes)", fontsize=12)
    ax.set_title("Packet Size Distribution by Attack Category", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))

    fig.tight_layout()
    save_figure(fig, "05_packet_size_distribution.png")
    # plt.show()


# ===================================================================
# 6. Network Traffic Volume by Day – Bar Chart
# ===================================================================
def viz_traffic_volume_by_day(db):
    """Bar chart of total traffic volume (bytes) by source file / capture day."""
    logger.info("Creating Visualization 6: Network Traffic Volume by Day ...")

    if collection_exists(db, "mr_traffic_volume_by_day"):
        docs = list(db["mr_traffic_volume_by_day"].find().sort("value.total_bytes", -1))
        days = [d["_id"] for d in docs]
        volumes = [d["value"]["total_bytes"] for d in docs]
    else:
        logger.info("MR collection not found – querying raw data.")
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
                }
            },
            {"$sort": {"total_bytes": -1}},
        ]
        docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
        days = [d["_id"] for d in docs]
        volumes = [d["total_bytes"] for d in docs]

    # Shorten long file names for display
    short_labels = [os.path.splitext(os.path.basename(str(d)))[0] if d else "Unknown" for d in days]

    fig, ax = plt.subplots(figsize=(14, 7))
    bars = ax.bar(range(len(short_labels)), volumes, color=sns.color_palette("viridis", len(short_labels)),
                  edgecolor="black", linewidth=0.5)
    ax.set_xticks(range(len(short_labels)))
    ax.set_xticklabels(short_labels, rotation=45, ha="right", fontsize=9)
    ax.set_ylabel("Total Bytes (Fwd + Bwd)", fontsize=12)
    ax.set_title("Network Traffic Volume by Capture Day / Source File", fontsize=14, fontweight="bold")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))

    for bar, vol in zip(bars, volumes):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{vol / 1e9:.2f} GB" if vol > 1e9 else f"{vol / 1e6:.1f} MB",
                ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    save_figure(fig, "06_traffic_volume_by_day.png")
    # plt.show()


# ===================================================================
# 7. Flow Rate Comparison – Grouped Bar Chart
# ===================================================================
def viz_flow_rate_comparison(db):
    """Grouped bar chart of avg bytes/s and packets/s by attack category."""
    logger.info("Creating Visualization 7: Flow Rate Comparison ...")

    if collection_exists(db, "mr_flow_rate_analysis"):
        docs = list(db["mr_flow_rate_analysis"].find().sort("_id", 1))
        categories = [d["_id"] for d in docs]
        avg_bps = [d["value"].get("avg_bytes_per_sec", 0) for d in docs]
        avg_pps = [d["value"].get("avg_packets_per_sec", 0) for d in docs]
    else:
        logger.info("MR collection not found – querying raw data.")
        pipeline = [
            {
                "$group": {
                    "_id": "$attack_category",
                    "avg_bps": {"$avg": {"$ifNull": ["$flow_bytes/s", 0]}},
                    "avg_pps": {"$avg": {"$ifNull": ["$flow_packets/s", 0]}},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
        categories = [d["_id"] for d in docs]
        avg_bps = [d.get("avg_bps", 0) for d in docs]
        avg_pps = [d.get("avg_pps", 0) for d in docs]

    x = np.arange(len(categories))
    width = 0.35

    fig, ax1 = plt.subplots(figsize=(14, 7))
    ax2 = ax1.twinx()

    bar1 = ax1.bar(x - width / 2, avg_bps, width, label="Avg Bytes/s", color="#2980b9",
                   edgecolor="black", linewidth=0.5, alpha=0.85)
    bar2 = ax2.bar(x + width / 2, avg_pps, width, label="Avg Packets/s", color="#e67e22",
                   edgecolor="black", linewidth=0.5, alpha=0.85)

    ax1.set_xticks(x)
    ax1.set_xticklabels(categories, rotation=45, ha="right", fontsize=10)
    ax1.set_ylabel("Avg Bytes/s", fontsize=12, color="#2980b9")
    ax2.set_ylabel("Avg Packets/s", fontsize=12, color="#e67e22")
    ax1.set_title("Flow Rate Comparison by Attack Category", fontsize=14, fontweight="bold")

    # Combined legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right", fontsize=11)

    fig.tight_layout()
    save_figure(fig, "07_flow_rate_comparison.png")
    # plt.show()


# ===================================================================
# 8. Top 10 Attack Types by Average Packet Size – Bar Chart
# ===================================================================
def viz_top10_avg_packet_size(db):
    """Bar chart of top 10 attack types by average packet size."""
    logger.info("Creating Visualization 8: Top 10 Attack Types by Avg Packet Size ...")

    pipeline = [
        {"$match": {"label": {"$ne": "BENIGN"}}},
        {
            "$group": {
                "_id": "$label",
                "avg_packet_size": {"$avg": {"$ifNull": ["$average_packet_size", 0]}},
            }
        },
        {"$sort": {"avg_packet_size": -1}},
        {"$limit": 10},
    ]
    docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
    labels = [d["_id"] for d in docs]
    sizes = [d["avg_packet_size"] for d in docs]

    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.bar(range(len(labels)), sizes, color=sns.color_palette("magma", len(labels)),
                  edgecolor="black", linewidth=0.5)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=10)
    ax.set_ylabel("Average Packet Size (bytes)", fontsize=12)
    ax.set_title("Top 10 Attack Types by Average Packet Size", fontsize=14, fontweight="bold")

    for bar, s in zip(bars, sizes):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{s:,.1f}", ha="center", va="bottom", fontsize=9)

    fig.tight_layout()
    save_figure(fig, "08_top10_avg_packet_size.png")
    # plt.show()


# ===================================================================
# 9. Correlation: Flow Duration vs Packet Count (Attack vs Benign)
# ===================================================================
def viz_scatter_duration_vs_packets(db):
    """Scatter plot of flow duration vs total packet count, colored by label."""
    logger.info("Creating Visualization 9: Flow Duration vs Packet Count Scatter ...")

    # Sample ~5000 documents (2500 benign + 2500 attack) for performance
    sample_benign = list(db[RAW_COLLECTION].aggregate([
        {"$match": {"is_attack": False}},
        {"$sample": {"size": 2500}},
        {"$project": {"flow_duration": 1, "total_fwd_packets": 1, "total_backward_packets": 1, "is_attack": 1}},
    ], allowDiskUse=True))

    sample_attack = list(db[RAW_COLLECTION].aggregate([
        {"$match": {"is_attack": True}},
        {"$sample": {"size": 2500}},
        {"$project": {"flow_duration": 1, "total_fwd_packets": 1, "total_backward_packets": 1, "is_attack": 1}},
    ], allowDiskUse=True))

    # If boolean match fails, try integer / string variants
    if not sample_benign and not sample_attack:
        logger.info("Retrying with alternate is_attack values ...")
        sample_benign = list(db[RAW_COLLECTION].aggregate([
            {"$match": {"is_attack": 0}},
            {"$sample": {"size": 2500}},
            {"$project": {"flow_duration": 1, "total_fwd_packets": 1, "total_backward_packets": 1, "is_attack": 1}},
        ], allowDiskUse=True))
        sample_attack = list(db[RAW_COLLECTION].aggregate([
            {"$match": {"is_attack": 1}},
            {"$sample": {"size": 2500}},
            {"$project": {"flow_duration": 1, "total_fwd_packets": 1, "total_backward_packets": 1, "is_attack": 1}},
        ], allowDiskUse=True))

    all_docs = sample_benign + sample_attack
    if not all_docs:
        logger.warning("No data found for scatter plot. Skipping.")
        return

    df = pd.DataFrame(all_docs)
    df["total_packets"] = df["total_fwd_packets"].fillna(0) + df["total_backward_packets"].fillna(0)
    df["category"] = df["is_attack"].map({True: "Attack", False: "Benign", 1: "Attack", 0: "Benign"})

    fig, ax = plt.subplots(figsize=(12, 8))
    for cat, color in [("Benign", "#2ecc71"), ("Attack", "#e74c3c")]:
        subset = df[df["category"] == cat]
        ax.scatter(subset["flow_duration"], subset["total_packets"],
                   c=color, label=cat, alpha=0.4, s=15, edgecolors="none")

    ax.set_xlabel("Flow Duration (μs)", fontsize=12)
    ax.set_ylabel("Total Packets (Fwd + Bwd)", fontsize=12)
    ax.set_title("Flow Duration vs Total Packets (Benign vs Attack)", fontsize=14, fontweight="bold")
    ax.legend(fontsize=12)
    ax.set_xscale("symlog")
    ax.set_yscale("symlog")

    fig.tight_layout()
    save_figure(fig, "09_scatter_duration_vs_packets.png")
    # plt.show()


# ===================================================================
# 10. Attack Category Distribution – Donut Chart
# ===================================================================
def viz_attack_category_donut(db):
    """Donut chart of attack category distribution (excluding BENIGN)."""
    logger.info("Creating Visualization 10: Attack Category Distribution (Donut) ...")

    pipeline = [
        {"$match": {"label": {"$ne": "BENIGN"}}},
        {"$group": {"_id": "$attack_category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
    if not docs:
        logger.warning("No attack data found for donut chart. Skipping.")
        return

    categories = [d["_id"] for d in docs]
    counts = [d["count"] for d in docs]
    colors = sns.color_palette("Set2", len(categories))

    fig, ax = plt.subplots(figsize=(9, 9))
    wedges, texts, autotexts = ax.pie(
        counts,
        labels=categories,
        autopct="%1.1f%%",
        startangle=90,
        colors=colors,
        pctdistance=0.80,
        textprops={"fontsize": 11},
        wedgeprops={"width": 0.45, "edgecolor": "white", "linewidth": 2},
    )
    for t in autotexts:
        t.set_fontweight("bold")
        t.set_fontsize(9)

    # Centre text
    ax.text(0, 0, "Attack\nCategories", ha="center", va="center", fontsize=14, fontweight="bold", color="#333")
    ax.set_title("Attack Category Distribution", fontsize=14, fontweight="bold", pad=20)

    fig.tight_layout()
    save_figure(fig, "10_attack_category_donut.png")
    # plt.show()


# ===================================================================
# 11. Top Destination Ports – Bar Chart
# ===================================================================
def viz_top_destination_ports(db):
    """Bar chart of top 10 most targeted destination ports."""
    logger.info("Creating Visualization 11: Top Destination Ports ...")

    port_names = {
        80: "HTTP (80)",
        443: "HTTPS (443)",
        22: "SSH (22)",
        21: "FTP (21)",
        53: "DNS (53)",
        8080: "HTTP-Alt (8080)",
        25: "SMTP (25)",
        110: "POP3 (110)",
        143: "IMAP (143)",
        3389: "RDP (3389)",
    }

    pipeline = [
        {"$group": {"_id": "$destination_port", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
    if not docs:
        return

    ports = [port_names.get(int(d["_id"]), f"Port {d['_id']}") for d in docs]
    counts = [d["count"] for d in docs]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(ports, counts, color=sns.color_palette("crest", len(ports)), edgecolor="black", linewidth=0.5)
    ax.set_xticklabels(ports, rotation=35, ha="right", fontsize=10)
    ax.set_ylabel("Number of Flows", fontsize=12)
    ax.set_title("Top 10 Most Targeted Destination Ports", fontsize=14, fontweight="bold")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))

    for bar, c in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{c:,.0f}", ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    save_figure(fig, "08_top_destination_ports.png")
    save_figure(fig, "11_top_destination_ports.png")


# ===================================================================
# 12. Feature Correlation Heatmap
# ===================================================================
def viz_feature_correlation_heatmap(db):
    """Heatmap showing correlation between key network flow features."""
    logger.info("Creating Visualization 12: Feature Correlation Heatmap ...")

    features = [
        "flow_duration",
        "total_fwd_packets",
        "total_backward_packets",
        "average_packet_size",
        "flow_bytes/s",
        "flow_packets/s",
        "syn_flag_count",
        "ack_flag_count",
    ]

    pipeline = [
        {"$sample": {"size": 10000}},
        {"$project": {f: 1 for f in features}},
    ]
    docs = list(db[RAW_COLLECTION].aggregate(pipeline, allowDiskUse=True))
    if not docs:
        return

    df = pd.DataFrame(docs)
    for f in features:
        if f in df.columns:
            df[f] = pd.to_numeric(df[f], errors="coerce").fillna(0)

    valid_feats = [f for f in features if f in df.columns]
    corr = df[valid_feats].corr()

    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(corr, annot=True, fmt=".2f", cmap="coolwarm", vmin=-1, vmax=1,
                linewidths=0.5, linecolor="gray", ax=ax)
    ax.set_title("Key Feature Correlation Matrix", fontsize=14, fontweight="bold")
    fig.tight_layout()
    save_figure(fig, "09_feature_correlation_heatmap.png")
    save_figure(fig, "12_feature_correlation_heatmap.png")


# ===================================================================
# Main execution
# ===================================================================
def main():
    """Generate all visualizations."""
    start = datetime.now()
    logger.info("=" * 60)
    logger.info("Starting Visualization Pipeline")
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

    if not collection_exists(db, RAW_COLLECTION):
        logger.error("Source collection '%s' is empty. Run the preprocessing step first.", RAW_COLLECTION)
        client.close()
        return 1

    # List of visualization functions
    viz_functions = [
        viz_attack_type_distribution,
        viz_benign_vs_attack,
        viz_avg_flow_duration,
        viz_flag_heatmap,
        viz_packet_size_distribution,
        viz_traffic_volume_by_day,
        viz_flow_rate_comparison,
        viz_top10_avg_packet_size,
        viz_scatter_duration_vs_packets,
        viz_attack_category_donut,
        viz_top_destination_ports,
        viz_feature_correlation_heatmap,
    ]

    success_count = 0
    for func in viz_functions:
        try:
            func(db)
            success_count += 1
        except Exception as exc:
            logger.error("Failed to create visualization '%s': %s", func.__name__, exc, exc_info=True)

    elapsed = datetime.now() - start
    logger.info("Visualization pipeline completed in %s (%d/%d succeeded).", elapsed, success_count, len(viz_functions))
    print(f"\n✅ {success_count}/{len(viz_functions)} visualizations saved to: {VIS_DIR}")
    print(f"   Completed in {elapsed}.")
    client.close()
    return 0 if success_count == len(viz_functions) else 1


if __name__ == "__main__":
    raise SystemExit(main())
