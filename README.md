# Big Data Network Intrusion and Anomaly Detection

## Project Overview

This project analyzes network traffic data using Big Data tools to detect intrusion patterns and anomalies. By leveraging MongoDB's NoSQL capabilities and the MapReduce paradigm, we process and analyze approximately **2.8 million network traffic records** from the CIC-IDS-2017 dataset to identify malicious traffic patterns, attack signatures, and anomalous behaviors.

- **Dataset:** [CIC-IDS-2017 from Kaggle](https://www.kaggle.com/datasets/ciaboromani/cicids2017)
- **Tools:** Python, MongoDB, MapReduce, Pandas, Matplotlib, Seaborn
- **Features:** The dataset contains 79 features including flow statistics, packet metrics, TCP flags, and attack labels

---

## Dataset Description

| Attribute | Details |
|-----------|---------|
| **Source** | Canadian Institute for Cybersecurity (CIC), University of New Brunswick |
| **Records** | ~2.8 million network traffic records |
| **Files** | 8 CSV files (one per capture session) |
| **Features** | 79 network flow features |
| **Data Type** | Semi-structured log data from network packet captures |

### Traffic Labels

The dataset contains labeled network traffic categorized as:

- **BENIGN** — Normal, legitimate network traffic
- **DoS/DDoS Attacks** — Slowloris, Slowhttptest, Hulk, GoldenEye
- **Port Scan** — Network reconnaissance activity
- **Brute Force** — FTP-Patator, SSH-Patator
- **Web Attack** — XSS, SQL Injection, Brute Force
- **Botnet** — Bot-controlled traffic
- **Infiltration** — Stealthy intrusion attempts

---

## Prerequisites

- **Python** 3.8+
- **MongoDB** 4.4+ (Community Edition)
- **Kaggle account** (for dataset download)
- **pip** packages (see `requirements.txt`)

---

## Installation & Setup

### 1. Install MongoDB Community Edition

Download and install MongoDB Community Server from:
https://www.mongodb.com/try/download/community

### 2. Start MongoDB Service

```bash
# Windows (run as Administrator)
net start MongoDB

# Or start via MongoDB Compass / Services
```

### 3. Clone / Download This Project

```bash
git clone <repository-url>
cd Big_Data_IA3
```

### 4. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 5. Set Up Kaggle API Credentials

1. Go to [Kaggle Account Settings](https://www.kaggle.com/settings/account)
2. Click **"Create New Token"** to download `kaggle.json`
3. Place `kaggle.json` in:
   - **Windows:** `C:\Users\<YourUsername>\.kaggle\kaggle.json`
   - **Linux/Mac:** `~/.kaggle/kaggle.json`

---

## Project Structure

```
Big_Data_IA3/
├── README.md                          # Project documentation
├── requirements.txt                   # Python dependencies
├── config.py                         # Configuration settings
├── step1_download_dataset.py         # Download CIC-IDS-2017 from Kaggle
├── step2_ingest_to_mongodb.py        # Load CSV data into MongoDB
├── step3_data_preprocessing.py       # Clean and preprocess data
├── step4_mapreduce_analysis.py       # Run MapReduce operations
├── step5_visualization.py            # Generate charts and plots
├── step6_run_all.py                  # Master script to run all steps
├── dashboard.py                      # Interactive Streamlit dashboard
├── visualizations/                   # Output charts
│   ├── 01_attack_type_distribution.png
│   ├── 02_benign_vs_attack_pie.png
│   ├── 03_avg_flow_duration_by_category.png
│   ├── 04_traffic_volume_by_day.png
│   ├── 05_tcp_flags_heatmap.png
│   ├── 06_packet_size_by_category.png
│   ├── 07_flow_rate_by_attack.png
│   ├── 08_top_destination_ports.png
│   ├── 09_feature_correlation_heatmap.png
│   └── 10_attack_category_donut.png
└── report/
    └── Big_Data_IA3_Report.md        # Formal project report
```

---

## How to Run

### Run All Steps Sequentially

```bash
python step6_run_all.py
```

The master script stops dependent steps when an earlier step fails and exits
with a non-zero status, so automation can reliably detect an incomplete run.

### Or Run Individual Steps

```bash
# Step 1: Download the CIC-IDS-2017 dataset from Kaggle
python step1_download_dataset.py

# Step 2: Ingest CSV files into MongoDB
python step2_ingest_to_mongodb.py

# Step 3: Clean and preprocess the data
python step3_data_preprocessing.py

# Step 4: Run MapReduce analysis operations
python step4_mapreduce_analysis.py

# Step 5: Generate visualizations
python step5_visualization.py
```

### Run the Interactive Dashboard

After MongoDB contains the cleaned collection, start the dashboard with:

```bash
python -m streamlit run dashboard.py
```

Open the local URL shown by Streamlit, usually `http://localhost:8501`.
The dashboard provides traffic KPIs, category and label filters, interactive
Plotly charts, TCP flag analysis, traffic-volume analysis, and a sampled flow
explorer. Use the **Clear cached data** button after rerunning preprocessing
or MapReduce analysis.

---

## MapReduce Operations

This project implements **6 MapReduce operations** to analyze network traffic patterns:

| # | Operation | Description |
|---|-----------|-------------|
| 1 | **Attack Type Distribution** | Counts the number of records per attack label to understand the distribution of benign vs. malicious traffic |
| 2 | **Average Flow Duration by Attack Category** | Computes the mean flow duration for each attack category to identify temporal patterns |
| 3 | **Network Traffic Volume by Day** | Aggregates network traffic volume (total bytes) across different days of the capture period |
| 4 | **TCP Flag Analysis per Attack Type** | Analyzes the distribution of TCP flags (SYN, ACK, FIN, RST, PSH, URG) across attack types |
| 5 | **Packet Size Statistics by Attack Category** | Calculates min, max, mean, and standard deviation of packet sizes per attack category |
| 6 | **Flow Rate Analysis by Attack Type** | Computes average flow bytes/second and flow packets/second for each attack type |

---

## Key Findings

> **Note:** This section will be populated with actual results after running the analysis pipeline.

- **Network Traffic Analysis:** Distribution patterns between benign and malicious traffic
- **Attack Pattern Characteristics:** Temporal and volumetric signatures of different attack types
- **Anomaly Detection Observations:** Statistical outliers and unusual patterns in network flow data

---

## Authors

- Jane Brenna Christy

---

## License

This project is licensed under the MIT License.
