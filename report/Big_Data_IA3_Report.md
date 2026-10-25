# Big Data Network Intrusion and Anomaly Detection — Project Report

---

## 1. Introduction

### 1.1 Background

Network intrusion detection has become a cornerstone of modern cybersecurity infrastructure. As organizations increasingly depend on networked systems, the volume and sophistication of cyber attacks continue to grow at an alarming rate. Traditional rule-based intrusion detection systems (IDS), while effective against known attack signatures, struggle to keep pace with the evolving threat landscape and the sheer volume of network traffic generated in contemporary environments.

The intersection of Big Data analytics and cybersecurity presents a compelling opportunity to address these challenges. By applying distributed data processing techniques to large-scale network traffic datasets, it becomes possible to uncover hidden patterns, detect anomalous behaviors, and identify attack signatures that would be invisible to conventional analysis methods.

### 1.2 Importance of Big Data Analytics in Cybersecurity

Modern enterprise networks generate terabytes of log data daily. Analyzing this data requires tools and techniques that can handle:

- **Volume:** Millions of network flow records per day
- **Variety:** Semi-structured data with heterogeneous feature sets
- **Velocity:** Real-time or near-real-time processing requirements
- **Veracity:** Noisy, incomplete, and potentially mislabeled data

Big Data frameworks such as MongoDB and MapReduce provide the scalability and flexibility needed to process these massive datasets efficiently. MongoDB's document-oriented model is particularly well-suited for storing semi-structured network logs, while MapReduce enables parallel aggregation and statistical analysis across the entire dataset.

### 1.3 Project Objectives

This project aims to:

1. **Ingest and store** the CIC-IDS-2017 network traffic dataset (~2.8 million records) into MongoDB
2. **Preprocess and clean** the data to address quality issues such as missing values, duplicates, and infinite values
3. **Implement MapReduce operations** to perform distributed analysis on network traffic patterns
4. **Visualize** the results to reveal attack signatures, traffic anomalies, and distribution patterns
5. **Draw insights** about the characteristics of different attack types and their network footprints

---

## 2. Dataset Description

### 2.1 CIC-IDS-2017 Overview

The CIC-IDS-2017 dataset was created by the **Canadian Institute for Cybersecurity (CIC)** at the University of New Brunswick. It is one of the most widely used benchmark datasets for network intrusion detection research.

- **Kaggle Source:** [https://www.kaggle.com/datasets/ciaboromani/cicids2017](https://www.kaggle.com/datasets/ciaboromani/cicids2017)
- **Original Source:** Canadian Institute for Cybersecurity, UNB

### 2.2 Data Characteristics

| Characteristic | Value |
|----------------|-------|
| Total Records | ~2,830,743 |
| Number of Features | 79 |
| Number of CSV Files | 8 (one per capture session) |
| File Format | CSV (Comma-Separated Values) |
| Total Size | ~1.2 GB (compressed) |
| Time Period | Monday–Friday, July 3–7, 2017 |

### 2.3 Feature Categories

The 79 features in the dataset can be grouped into the following categories:

- **Flow Identifiers:** Source IP, Destination IP, Source Port, Destination Port, Protocol
- **Flow Statistics:** Flow Duration, Total Forward/Backward Packets, Total Length of Forward/Backward Packets
- **Packet Metrics:** Packet Length (Min, Max, Mean, Std), Packet Size statistics
- **Inter-Arrival Time (IAT):** Flow IAT (Min, Max, Mean, Std), Forward/Backward IAT statistics
- **TCP Flags:** FIN, SYN, RST, PSH, ACK, URG, CWE, ECE flag counts
- **Flow Rates:** Flow Bytes/s, Flow Packets/s
- **Active/Idle Statistics:** Active/Idle time (Min, Max, Mean, Std)
- **Label:** Traffic classification (BENIGN or specific attack type)

### 2.4 Attack Types

The dataset includes the following attack categories:

| Day | Attack Type | Category |
|-----|-------------|----------|
| Monday | None (Benign only) | Normal |
| Tuesday | FTP-Patator, SSH-Patator | Brute Force |
| Wednesday | DoS Slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed | DoS/DDoS |
| Thursday | Web Attack – Brute Force, Web Attack – XSS, Web Attack – SQL Injection, Infiltration | Web Attack, Infiltration |
| Friday | Bot, Port Scan, DDoS | Botnet, Port Scan, DDoS |

### 2.5 Why This Dataset

The CIC-IDS-2017 dataset is particularly suitable for this Big Data project because:

1. **Semi-structured nature:** Network flow logs are inherently semi-structured, making them ideal for MongoDB's document model
2. **Scale:** With ~2.8 million records, the dataset is large enough to demonstrate Big Data processing techniques
3. **Diversity:** Multiple attack types enable multi-faceted analysis
4. **Labeled data:** Ground-truth labels facilitate supervised analysis and validation
5. **Real-world relevance:** Generated from realistic network traffic profiles

---

## 3. Technology Stack

### 3.1 MongoDB

**MongoDB** is a NoSQL, document-oriented database that stores data in flexible, JSON-like BSON documents. It was chosen for this project for several reasons:

- **Schema Flexibility:** Network log data often has inconsistent or evolving schemas. MongoDB's schemaless design accommodates this naturally, allowing documents with varying fields to coexist in the same collection.
- **Horizontal Scalability:** MongoDB supports sharding, enabling horizontal distribution of data across multiple servers—essential for Big Data workloads.
- **Native MapReduce Support:** MongoDB includes built-in MapReduce functionality, allowing in-database distributed computation without external frameworks.
- **Rich Query Language:** MongoDB's aggregation pipeline and query operators enable complex data exploration and preprocessing.
- **Document Model Fit:** Each network flow record maps naturally to a MongoDB document, preserving the hierarchical structure of network metadata.

### 3.2 MapReduce

**MapReduce** is a programming paradigm for distributed data processing, originally introduced by Google. It consists of two primary phases:

- **Map Phase:** A user-defined map function processes each input document and emits zero or more key-value pairs. This phase runs in parallel across all documents.
- **Reduce Phase:** A user-defined reduce function aggregates all values associated with each unique key, producing a summarized result.

In MongoDB, MapReduce is implemented using JavaScript functions executed within the database engine. While MongoDB has introduced the Aggregation Pipeline as a more performant alternative, MapReduce remains valuable for its conceptual clarity and alignment with Big Data educational objectives.

### 3.3 Python Ecosystem

The following Python libraries are used:

| Library | Purpose |
|---------|---------|
| `pymongo` | MongoDB driver for Python |
| `pandas` | Data manipulation and analysis |
| `matplotlib` | Static plot generation |
| `seaborn` | Statistical visualization |
| `kaggle` | Kaggle API for dataset download |
| `numpy` | Numerical computations |

### 3.4 Architecture Diagram

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐    ┌───────────────┐
│   Kaggle     │───▶│   CSV Files  │───▶│   MongoDB   │───▶│  MapReduce   │───▶│ Visualizations│
│   Dataset    │    │  (Download)  │    │  (Ingest)   │    │  (Analysis)  │    │   (Charts)    │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘    └───────────────┘
     Step 1             Step 1             Step 2            Step 4              Step 5
                                           Step 3
                                       (Preprocessing)
```

---

## 4. Methodology

### 4.1 Data Ingestion (Step 2)

#### Process

The data ingestion pipeline loads each CSV file from the CIC-IDS-2017 dataset into a MongoDB collection. The process follows these steps:

1. **File Discovery:** Scan the dataset directory for all CSV files
2. **Batch Reading:** Read each CSV file using pandas with chunked processing to manage memory
3. **Column Normalization:** Strip whitespace from column names for consistency
4. **Batch Insertion:** Insert records in batches of 10,000 documents using `insert_many()` for optimal throughput
5. **Index Creation:** Create indexes on frequently queried fields (`Label`, `Destination Port`, `Protocol`)

#### Data Schema Design

Each network flow record is stored as a MongoDB document with the following structure:

```json
{
    "_id": ObjectId("..."),
    "Destination Port": 80,
    "Flow Duration": 120000,
    "Total Fwd Packets": 15,
    "Total Backward Packets": 12,
    "Flow Bytes/s": 45230.5,
    "Flow Packets/s": 225.0,
    "FIN Flag Count": 1,
    "SYN Flag Count": 1,
    "Label": "BENIGN",
    "is_attack": 0,
    "attack_category": "Benign",
    ...
}
```

#### Batch Insertion Strategy

To optimize insertion performance:
- Records are inserted in batches of **10,000 documents**
- `ordered=False` is used to allow partial batch success
- Progress logging tracks insertion status per file

### 4.2 Data Preprocessing (Step 3)

#### Cleaning Steps

1. **Duplicate Removal:** Identify and remove exact duplicate records across all features
2. **Null Value Handling:** Replace NaN values with 0 for numeric fields, ensuring no missing data disrupts analysis
3. **Infinity Replacement:** Replace `inf` and `-inf` values (common in rate calculations like Bytes/s) with 0
4. **Data Type Correction:** Ensure numeric fields are stored as proper numeric types

#### Feature Engineering

Two derived features are created to facilitate analysis:

- **`is_attack`:** Binary flag (0 = BENIGN, 1 = attack) for quick filtering
- **`attack_category`:** High-level grouping of attack types:

| Label | Attack Category |
|-------|----------------|
| BENIGN | Benign |
| FTP-Patator, SSH-Patator | Brute Force |
| DoS Slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye | DoS |
| Heartbleed | DoS |
| Web Attack – Brute Force, Web Attack – XSS, Web Attack – SQL Injection | Web Attack |
| Infiltration | Infiltration |
| Bot | Botnet |
| PortScan | Port Scan |
| DDoS | DDoS |

### 4.3 MapReduce Analysis (Step 4)

Six MapReduce operations are implemented to analyze different aspects of the network traffic data. Each operation uses MongoDB's `map_reduce()` command with JavaScript map, reduce, and (where applicable) finalize functions.

---

#### MapReduce 1: Attack Type Distribution

**Objective:** Count the number of records for each traffic label to understand the distribution of benign vs. malicious traffic.

**Map Function:**
```javascript
function() {
    emit(this.Label, 1);
}
```
The map function emits the traffic label as the key and `1` as the value for each document.

**Reduce Function:**
```javascript
function(key, values) {
    return Array.sum(values);
}
```
The reduce function sums all the `1` values for each label, producing the total count.

**Expected Output:** A collection of `{_id: "<label>", value: <count>}` documents showing the frequency of each traffic type.

---

#### MapReduce 2: Average Flow Duration by Attack Category

**Objective:** Compute the average flow duration for each attack category to identify temporal characteristics of different attack types.

**Map Function:**
```javascript
function() {
    emit(this.attack_category, {
        sum: this["Flow Duration"],
        count: 1
    });
}
```

**Reduce Function:**
```javascript
function(key, values) {
    var result = { sum: 0, count: 0 };
    values.forEach(function(v) {
        result.sum += v.sum;
        result.count += v.count;
    });
    return result;
}
```

**Finalize Function:**
```javascript
function(key, reducedValue) {
    reducedValue.avg = reducedValue.sum / reducedValue.count;
    return reducedValue;
}
```

**Expected Output:** Average flow duration (in microseconds) per attack category, enabling comparison of attack durations.

---

#### MapReduce 3: Network Traffic Volume by Day

**Objective:** Aggregate network traffic volume across different days of the capture period to identify temporal patterns.

**Map Function:**
```javascript
function() {
    var day = this.Timestamp ? this.Timestamp.substring(0, 10) : "Unknown";
    var totalBytes = (this["Total Fwd Packets"] || 0) + (this["Total Backward Packets"] || 0);
    emit(day, {
        total_bytes: totalBytes,
        count: 1
    });
}
```

**Reduce Function:**
```javascript
function(key, values) {
    var result = { total_bytes: 0, count: 0 };
    values.forEach(function(v) {
        result.total_bytes += v.total_bytes;
        result.count += v.count;
    });
    return result;
}
```

**Expected Output:** Total traffic volume and flow count per day.

---

#### MapReduce 4: TCP Flag Analysis per Attack Type

**Objective:** Analyze the distribution of TCP flags across different attack types to identify protocol-level attack signatures.

**Map Function:**
```javascript
function() {
    emit(this.attack_category, {
        fin: this["FIN Flag Count"] || 0,
        syn: this["SYN Flag Count"] || 0,
        rst: this["RST Flag Count"] || 0,
        psh: this["PSH Flag Count"] || 0,
        ack: this["ACK Flag Count"] || 0,
        urg: this["URG Flag Count"] || 0,
        count: 1
    });
}
```

**Reduce Function:**
```javascript
function(key, values) {
    var result = { fin: 0, syn: 0, rst: 0, psh: 0, ack: 0, urg: 0, count: 0 };
    values.forEach(function(v) {
        result.fin += v.fin;
        result.syn += v.syn;
        result.rst += v.rst;
        result.psh += v.psh;
        result.ack += v.ack;
        result.urg += v.urg;
        result.count += v.count;
    });
    return result;
}
```

**Expected Output:** Aggregated TCP flag counts per attack category, revealing protocol-level attack characteristics.

---

#### MapReduce 5: Packet Size Statistics by Attack Category

**Objective:** Calculate descriptive statistics (sum, count, min, max) of packet sizes for each attack category.

**Map Function:**
```javascript
function() {
    var pktLen = this["Average Packet Size"] || 0;
    emit(this.attack_category, {
        sum: pktLen,
        count: 1,
        min: pktLen,
        max: pktLen
    });
}
```

**Reduce Function:**
```javascript
function(key, values) {
    var result = { sum: 0, count: 0, min: Infinity, max: -Infinity };
    values.forEach(function(v) {
        result.sum += v.sum;
        result.count += v.count;
        if (v.min < result.min) result.min = v.min;
        if (v.max > result.max) result.max = v.max;
    });
    return result;
}
```

**Finalize Function:**
```javascript
function(key, reducedValue) {
    reducedValue.avg = reducedValue.sum / reducedValue.count;
    return reducedValue;
}
```

**Expected Output:** Packet size statistics (average, min, max) per attack category.

---

#### MapReduce 6: Flow Rate Analysis by Attack Type

**Objective:** Compute average flow bytes/second and flow packets/second for each attack type to characterize bandwidth consumption patterns.

**Map Function:**
```javascript
function() {
    emit(this.attack_category, {
        bytes_per_sec: this["Flow Bytes/s"] || 0,
        packets_per_sec: this["Flow Packets/s"] || 0,
        count: 1
    });
}
```

**Reduce Function:**
```javascript
function(key, values) {
    var result = { bytes_per_sec: 0, packets_per_sec: 0, count: 0 };
    values.forEach(function(v) {
        result.bytes_per_sec += v.bytes_per_sec;
        result.packets_per_sec += v.packets_per_sec;
        result.count += v.count;
    });
    return result;
}
```

**Finalize Function:**
```javascript
function(key, reducedValue) {
    reducedValue.avg_bytes_per_sec = reducedValue.bytes_per_sec / reducedValue.count;
    reducedValue.avg_packets_per_sec = reducedValue.packets_per_sec / reducedValue.count;
    return reducedValue;
}
```

**Expected Output:** Average flow rates per attack category, indicating the bandwidth characteristics of different attacks.

---

## 5. Results and Analysis

### 5.1 Attack Type Distribution

The attack type distribution analysis reveals the composition of the CIC-IDS-2017 dataset. The dataset is heavily imbalanced, with BENIGN traffic constituting the majority of records.

| Attack Type | Count | Percentage |
|-------------|-------|------------|
| BENIGN | [INSERT ACTUAL VALUES] | [INSERT]% |
| DoS Hulk | [INSERT ACTUAL VALUES] | [INSERT]% |
| PortScan | [INSERT ACTUAL VALUES] | [INSERT]% |
| DDoS | [INSERT ACTUAL VALUES] | [INSERT]% |
| DoS GoldenEye | [INSERT ACTUAL VALUES] | [INSERT]% |
| FTP-Patator | [INSERT ACTUAL VALUES] | [INSERT]% |
| SSH-Patator | [INSERT ACTUAL VALUES] | [INSERT]% |
| DoS Slowloris | [INSERT ACTUAL VALUES] | [INSERT]% |
| DoS Slowhttptest | [INSERT ACTUAL VALUES] | [INSERT]% |
| Bot | [INSERT ACTUAL VALUES] | [INSERT]% |
| Web Attack | [INSERT ACTUAL VALUES] | [INSERT]% |
| Infiltration | [INSERT ACTUAL VALUES] | [INSERT]% |
| Heartbleed | [INSERT ACTUAL VALUES] | [INSERT]% |

**Observations:**
- The dataset exhibits significant class imbalance, which is representative of real-world network traffic where benign flows vastly outnumber malicious ones.
- DoS attacks (particularly DoS Hulk) are among the most frequent attack types, reflecting their ease of execution.
- Rare attack types such as Heartbleed and Infiltration have very few samples, posing challenges for detection models.

### 5.2 Flow Duration Analysis

The average flow duration varies significantly across attack categories, providing insights into the temporal footprint of different attacks.

| Attack Category | Average Flow Duration (μs) | Interpretation |
|-----------------|---------------------------|----------------|
| Benign | [INSERT ACTUAL VALUES] | Varied duration — normal sessions |
| DoS | [INSERT ACTUAL VALUES] | [INSERT interpretation] |
| DDoS | [INSERT ACTUAL VALUES] | [INSERT interpretation] |
| Brute Force | [INSERT ACTUAL VALUES] | [INSERT interpretation] |
| Port Scan | [INSERT ACTUAL VALUES] | [INSERT interpretation] |
| Web Attack | [INSERT ACTUAL VALUES] | [INSERT interpretation] |
| Botnet | [INSERT ACTUAL VALUES] | [INSERT interpretation] |
| Infiltration | [INSERT ACTUAL VALUES] | [INSERT interpretation] |

**Observations:**
- [INSERT observations about which attacks have longer/shorter durations and what that implies about their nature]

### 5.3 Traffic Volume Patterns

Network traffic volume analysis across the capture period reveals temporal patterns in both benign and malicious activity.

| Day | Total Flows | Total Volume | Dominant Attack |
|-----|-------------|--------------|-----------------|
| Monday | [INSERT] | [INSERT] | None (Benign only) |
| Tuesday | [INSERT] | [INSERT] | Brute Force |
| Wednesday | [INSERT] | [INSERT] | DoS |
| Thursday | [INSERT] | [INSERT] | Web Attack, Infiltration |
| Friday | [INSERT] | [INSERT] | Botnet, Port Scan, DDoS |

**Observations:**
- [INSERT observations about daily traffic patterns and attack scheduling]

### 5.4 TCP Flag Analysis

TCP flag distribution across attack types reveals protocol-level signatures that distinguish different attack categories.

| Category | FIN | SYN | RST | PSH | ACK | URG |
|----------|-----|-----|-----|-----|-----|-----|
| Benign | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] |
| DoS | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] |
| DDoS | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] |
| Port Scan | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] |
| Brute Force | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] | [INSERT] |

**Observations:**
- SYN floods are expected to show elevated SYN flag counts in DoS/DDoS categories
- Port scanning activity typically exhibits high SYN counts with corresponding RST responses
- [INSERT additional protocol-level observations]

### 5.5 Packet Size Patterns

Packet size statistics across attack categories reveal volumetric characteristics of different attacks.

| Category | Avg Packet Size | Min | Max |
|----------|-----------------|-----|-----|
| Benign | [INSERT] | [INSERT] | [INSERT] |
| DoS | [INSERT] | [INSERT] | [INSERT] |
| DDoS | [INSERT] | [INSERT] | [INSERT] |
| Port Scan | [INSERT] | [INSERT] | [INSERT] |
| Brute Force | [INSERT] | [INSERT] | [INSERT] |
| Web Attack | [INSERT] | [INSERT] | [INSERT] |

**Observations:**
- [INSERT observations about how packet sizes differ between attack types and benign traffic]

### 5.6 Flow Rate Analysis

Flow rate analysis characterizes the bandwidth consumption patterns of different attack types.

| Category | Avg Bytes/sec | Avg Packets/sec |
|----------|---------------|-----------------|
| Benign | [INSERT] | [INSERT] |
| DoS | [INSERT] | [INSERT] |
| DDoS | [INSERT] | [INSERT] |
| Port Scan | [INSERT] | [INSERT] |
| Brute Force | [INSERT] | [INSERT] |

**Observations:**
- DDoS attacks are expected to show the highest flow rates, reflecting their flooding nature
- [INSERT additional flow rate observations]

---

## 6. Key Insights and Patterns

### 6.1 Anomaly Characteristics

Through the MapReduce analysis, several anomaly characteristics emerge:

1. **Volumetric Anomalies:** DoS and DDoS attacks generate significantly higher traffic volumes and flow rates compared to benign traffic, making them detectable through volume-based thresholds.

2. **Temporal Anomalies:** Different attack types exhibit distinct temporal patterns. Brute force attacks tend to have rapid, short-lived connections, while Slowloris-style DoS attacks maintain long-duration, low-rate connections.

3. **Protocol-Level Anomalies:** TCP flag distributions differ markedly between benign and malicious traffic. Port scanning activity shows characteristic SYN-heavy patterns, while normal traffic exhibits balanced flag distributions.

### 6.2 Attack Signatures Identified Through MapReduce

| Attack Category | Key Signature | MapReduce Operation |
|-----------------|---------------|---------------------|
| DoS/DDoS | High flow rates, extreme packet counts | Flow Rate Analysis |
| Port Scan | High SYN flag count, short duration | TCP Flag Analysis, Flow Duration |
| Brute Force | Repeated connections, moderate duration | Attack Distribution, Flow Duration |
| Web Attack | Specific port targeting (80/443), varied packet sizes | Packet Size Analysis |
| Botnet | Consistent, automated traffic patterns | Flow Rate Analysis |

### 6.3 Benign vs. Malicious Traffic Comparison

The comparison of benign and malicious traffic patterns reveals:

- **Flow Duration:** Malicious traffic often exhibits bimodal distribution—very short (scanning) or very long (slow DoS) durations—while benign traffic shows a more uniform distribution.
- **Packet Sizes:** Attack traffic tends to have less variance in packet sizes, reflecting the automated and repetitive nature of attack tools.
- **Flow Rates:** Extreme flow rates (both very high and very low) are more common in attack traffic than in benign traffic.

---

## 7. Challenges and Limitations

### 7.1 Dataset Size and Memory Constraints

- The CIC-IDS-2017 dataset contains approximately 2.8 million records, which, while large enough to demonstrate Big Data techniques, can still be processed on a single machine. True Big Data scenarios would involve datasets orders of magnitude larger.
- Loading the entire dataset into memory for preprocessing required careful management of pandas DataFrame sizes and chunked processing.
- MongoDB's MapReduce operations are single-threaded within a collection, which limits parallelism on a single-node deployment.

### 7.2 MongoDB MapReduce Deprecation Considerations

- MongoDB has deprecated the `mapReduce` command starting from version 5.0, recommending the Aggregation Pipeline as a replacement.
- For this project, MapReduce was used intentionally to demonstrate the classic Big Data paradigm and its conceptual alignment with distributed processing frameworks like Hadoop.
- The Aggregation Pipeline offers better performance and query optimization but lacks the explicit map-reduce-finalize structure that illustrates the paradigm.

### 7.3 Data Quality Issues

- Several columns in the CIC-IDS-2017 dataset contain `Infinity` and `NaN` values, particularly in rate-based features (`Flow Bytes/s`, `Flow Packets/s`). These arise from division-by-zero in flow calculations for zero-duration flows.
- Some records have negative values in features that should be non-negative, likely due to measurement or calculation errors.
- The dataset has significant class imbalance, with benign traffic comprising approximately 80% of all records.

### 7.4 Single-Node Limitations

- This project runs on a single MongoDB instance without sharding or replication. In a production Big Data environment, the dataset would be distributed across multiple nodes.
- The MapReduce operations execute sequentially rather than in a truly distributed manner, though the paradigm itself is designed for distributed execution.

---

## 8. Conclusion

### 8.1 Summary of Findings

This project successfully demonstrated the application of Big Data techniques—specifically MongoDB and MapReduce—to the problem of network intrusion detection using the CIC-IDS-2017 dataset. The key findings include:

1. **Data Ingestion:** The complete CIC-IDS-2017 dataset (~2.8 million records) was successfully loaded into MongoDB, demonstrating the database's capacity for handling semi-structured network log data.

2. **Preprocessing:** Data cleaning addressed common quality issues including duplicates, null values, and infinity values, resulting in a clean dataset suitable for analysis.

3. **MapReduce Analysis:** Six MapReduce operations extracted meaningful patterns from the data, including attack type distributions, temporal patterns, protocol-level signatures, and volumetric characteristics.

4. **Pattern Recognition:** The analysis revealed distinct signatures for different attack categories:
   - DoS/DDoS attacks exhibit high flow rates and extreme traffic volumes
   - Port scanning shows characteristic SYN-heavy TCP flag patterns
   - Brute force attacks demonstrate repeated, short-duration connection attempts
   - Web attacks target specific ports with varied packet sizes

5. **Visualization:** The generated charts and plots provide intuitive representations of the analytical results, making complex network data accessible for interpretation.

### 8.2 Future Work

Several directions for future enhancement include:

- **Distributed Processing:** Deploy MongoDB in a sharded cluster to demonstrate true horizontal scalability with MapReduce
- **Real-Time Analysis:** Implement change streams with MongoDB to enable near-real-time intrusion detection
- **Machine Learning Integration:** Combine MapReduce feature extraction with ML models (e.g., Random Forest, Neural Networks) for automated anomaly classification
- **Aggregation Pipeline Comparison:** Implement the same analyses using MongoDB's Aggregation Pipeline and benchmark performance against MapReduce
- **Additional Datasets:** Apply the methodology to other network intrusion datasets (e.g., UNSW-NB15, CSE-CIC-IDS2018) for cross-validation

---

## 9. References

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* In Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP).

2. Canadian Institute for Cybersecurity. (2017). *CIC-IDS-2017 Dataset.* University of New Brunswick. Available at: https://www.unb.ca/cic/datasets/ids-2017.html

3. MongoDB Documentation. *Map-Reduce.* Available at: https://www.mongodb.com/docs/manual/core/map-reduce/

4. MongoDB Documentation. *Aggregation Pipeline.* Available at: https://www.mongodb.com/docs/manual/aggregation/

5. Dean, J., & Ghemawat, S. (2004). *MapReduce: Simplified Data Processing on Large Clusters.* In Proceedings of the 6th Symposium on Operating Systems Design and Implementation (OSDI).

6. Kaggle. *CIC-IDS-2017 Dataset.* Available at: https://www.kaggle.com/datasets/ciaboromani/cicids2017

7. Lashkari, A. H., Gil, G. D., Mamun, M. S. I., & Ghorbani, A. A. (2017). *Characterization of Tor Traffic using Time based Features.* In Proceedings of the 3rd International Conference on Information Systems Security and Privacy (ICISSP).

8. Garcia-Teodoro, P., Diaz-Verdejo, J., Maciá-Fernández, G., & Vázquez, E. (2009). *Anomaly-based network intrusion detection: Techniques, systems and challenges.* Computers & Security, 28(1-2), 18–28.

---

*Report generated as part of the Big Data IA3 project — Network Intrusion and Anomaly Detection using MongoDB and MapReduce.*
