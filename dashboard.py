"""Interactive Streamlit dashboard for the network intrusion analysis project."""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from config import MONGO_COLLECTION_CLEANED, MONGO_DATABASE, MONGO_URI


st.set_page_config(
    page_title="Network Intrusion Dashboard",
    page_icon="🛡️",
    layout="wide",
)

COLORS = {
    "navy": "#101828",
    "blue": "#2563EB",
    "cyan": "#06B6D4",
    "purple": "#7C3AED",
    "green": "#10B981",
    "orange": "#F59E0B",
    "red": "#EF4444",
    "muted": "#667085",
}
PLOTLY_TEMPLATE = "plotly_white"

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'DM Sans', sans-serif;
    }
    .stApp {
        background: linear-gradient(135deg, #f8fbff 0%, #f5f3ff 48%, #fffaf5 100%);
    }
    [data-testid="stHeader"] {
        background: rgba(248, 251, 255, 0.82);
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #101828 0%, #172554 100%);
    }
    [data-testid="stSidebar"] * {
        color: #eef4ff;
    }
    [data-testid="stSidebar"] .stMultiSelect div[data-baseweb="select"] > div,
    [data-testid="stSidebar"] .stSlider {
        background-color: rgba(255, 255, 255, 0.08);
        border-radius: 12px;
    }
    .hero {
        background: linear-gradient(115deg, #101828 0%, #1d4ed8 55%, #7c3aed 100%);
        border-radius: 24px;
        padding: 30px 34px 28px;
        margin: 8px 0 24px;
        color: white;
        box-shadow: 0 18px 40px rgba(37, 99, 235, 0.22);
    }
    .hero h1 {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 2.7rem;
        margin: 0 0 8px;
        letter-spacing: -0.04em;
    }
    .hero p {
        color: #dbeafe;
        font-size: 1.15rem;
        margin: 0;
    }
    .eyebrow {
        color: #67e8f9;
        font-size: 0.9rem;
        font-weight: 700;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        margin-bottom: 10px;
    }
    .kpi {
        background: rgba(255, 255, 255, 0.86);
        border: 1px solid rgba(148, 163, 184, 0.20);
        border-top: 4px solid var(--accent);
        border-radius: 18px;
        padding: 17px 19px;
        min-height: 112px;
        box-shadow: 0 8px 24px rgba(16, 24, 40, 0.07);
    }
    .kpi-label {
        color: #667085;
        font-size: 0.95rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }
    .kpi-value {
        color: #101828;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 2rem;
        font-weight: 700;
        margin-top: 7px;
    }
    .kpi-note {
        color: #667085;
        font-size: 0.9rem;
        margin-top: 3px;
    }
    .section-title {
        color: #101828;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 1.45rem;
        font-weight: 700;
        margin: 10px 0 2px;
    }
    div[data-testid="stTabs"] button {
        font-size: 1.05rem;
        font-weight: 600;
    }
    [data-testid="stSidebar"] h2 {
        font-size: 1.45rem;
    }
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
        font-size: 1rem;
    }
    [data-testid="stMarkdownContainer"] p,
    [data-testid="stCaptionContainer"] p {
        font-size: 1rem;
    }
    [data-testid="stMetricLabel"] {
        font-size: 1rem;
    }
    [data-testid="stDataFrame"] {
        font-size: 0.95rem;
    }
    div[data-testid="stDataFrame"] {
        border-radius: 14px;
        overflow: hidden;
        border: 1px solid #e4e7ec;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def styled_chart(figure: go.Figure) -> go.Figure:
    """Apply the dashboard's shared Plotly styling."""
    figure.update_layout(
        template=PLOTLY_TEMPLATE,
        font={"family": "DM Sans, sans-serif", "size": 15, "color": COLORS["navy"]},
        title={"font": {"size": 20, "family": "Space Grotesk, sans-serif"}},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.72)",
        margin={"l": 24, "r": 24, "t": 48, "b": 24},
        legend={"bgcolor": "rgba(255,255,255,0.7)", "borderwidth": 0},
        hoverlabel={"bgcolor": COLORS["navy"], "font_color": "white"},
    )
    figure.update_xaxes(tickfont={"size": 13}, title_font={"size": 15})
    figure.update_yaxes(tickfont={"size": 13}, title_font={"size": 15})
    return figure


def section_heading(text: str, subtitle: str | None = None) -> None:
    st.markdown(f'<div class="section-title">{text}</div>', unsafe_allow_html=True)
    if subtitle:
        st.caption(subtitle)


@st.cache_resource
def get_database() -> tuple[MongoClient, Any]:
    """Connect to MongoDB once per Streamlit process."""
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    return client, client[MONGO_DATABASE]


def collection_has_data(db: Any, name: str) -> bool:
    return name in db.list_collection_names() and db[name].estimated_document_count() > 0


@st.cache_data(ttl=300)
def load_summary() -> dict[str, int]:
    _, db = get_database()
    collection = db[MONGO_COLLECTION_CLEANED]
    counts = list(collection.aggregate([
        {
            "$group": {
                "_id": None,
                "total": {"$sum": 1},
                "attacks": {"$sum": {"$cond": [{"$eq": ["$is_attack", 1]}, 1, 0]}},
            }
        }
    ]))
    if not counts:
        return {"total": 0, "attacks": 0, "benign": 0}
    total = int(counts[0]["total"])
    attacks = int(counts[0]["attacks"])
    return {"total": total, "attacks": attacks, "benign": total - attacks}


@st.cache_data(ttl=300)
def load_attack_distribution(categories: tuple[str, ...]) -> pd.DataFrame:
    _, db = get_database()
    match = {"attack_category": {"$in": list(categories)}} if categories else {}
    rows = list(db[MONGO_COLLECTION_CLEANED].aggregate([
        {"$match": match},
        {"$group": {"_id": "$label", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ], allowDiskUse=True))
    return pd.DataFrame(
        [{"label": row["_id"], "count": row["count"]} for row in rows]
    )


@st.cache_data(ttl=300)
def load_category_distribution() -> pd.DataFrame:
    _, db = get_database()
    rows = list(db[MONGO_COLLECTION_CLEANED].aggregate([
        {"$group": {"_id": "$attack_category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ], allowDiskUse=True))
    return pd.DataFrame(
        [{"category": row["_id"], "count": row["count"]} for row in rows]
    )


@st.cache_data(ttl=300)
def load_mapreduce(collection_name: str, sort_field: str | None = None) -> list[dict[str, Any]]:
    _, db = get_database()
    cursor = db[collection_name].find({}, {"_id": 1, "value": 1})
    if sort_field:
        cursor = cursor.sort(sort_field, -1)
    return list(cursor)


@st.cache_data(ttl=300)
def load_sample(categories: tuple[str, ...], sample_size: int) -> pd.DataFrame:
    _, db = get_database()
    match = {"attack_category": {"$in": list(categories)}} if categories else {}
    rows = list(db[MONGO_COLLECTION_CLEANED].aggregate([
        {"$match": match},
        {"$sample": {"size": sample_size}},
        {
            "$project": {
                "_id": 0,
                "label": 1,
                "attack_category": 1,
                "flow_duration": 1,
                "total_fwd_packets": 1,
                "total_backward_packets": 1,
                "destination_port": 1,
                "source_file": 1,
            }
        },
    ], allowDiskUse=True))
    return pd.DataFrame(rows)


def render_dashboard() -> None:
    st.markdown(
        """
        <div class="hero">
            <div class="eyebrow">CIC-IDS-2017 • Security Intelligence</div>
            <h1>Network Intrusion &amp; Anomaly Detection</h1>
            <p>Explore attack signatures, traffic behavior, and flow-level anomalies through an interactive security command center.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    with st.sidebar:
        st.markdown("## 🛡️ Security command center")
        st.caption("Live view powered by MongoDB and MapReduce")
        st.divider()

    try:
        _, db = get_database()
        if not collection_has_data(db, MONGO_COLLECTION_CLEANED):
            st.error("The cleaned MongoDB collection is empty. Run steps 2 and 3 first.")
            st.stop()
        summary = load_summary()
        categories_df = load_category_distribution()
    except PyMongoError as exc:
        st.error(f"Unable to connect to MongoDB at {MONGO_URI}: {exc}")
        st.stop()

    categories = categories_df["category"].dropna().astype(str).tolist()
    selected_categories = st.sidebar.multiselect(
        "Attack categories",
        options=categories,
        default=categories,
        help="Filters the attack distribution and sampled flow explorer.",
    )
    sample_size = st.sidebar.slider("Explorer sample size", 500, 10000, 2000, 500)
    if st.sidebar.button("Clear cached data"):
        st.cache_data.clear()
        st.rerun()

    benign_pct = summary["benign"] / summary["total"] * 100 if summary["total"] else 0
    attack_pct = summary["attacks"] / summary["total"] * 100 if summary["total"] else 0
    cards = st.columns(4)
    kpis = [
        ("Total flows", f"{summary['total']:,}", "All observed network flows", COLORS["blue"]),
        ("Attack flows", f"{summary['attacks']:,}", f"{attack_pct:.1f}% of all flows", COLORS["red"]),
        ("Benign flows", f"{summary['benign']:,}", f"{benign_pct:.1f}% of all flows", COLORS["green"]),
        ("Categories", str(len(categories)), "Detected traffic groups", COLORS["purple"]),
    ]
    for card, (label, value, note, accent) in zip(cards, kpis):
        with card:
            st.markdown(
                f'<div class="kpi" style="--accent:{accent}">'
                f'<div class="kpi-label">{label}</div>'
                f'<div class="kpi-value">{value}</div>'
                f'<div class="kpi-note">{note}</div></div>',
                unsafe_allow_html=True,
            )

    overview, attacks, behavior, explorer = st.tabs(
        ["🌐 Overview", "🚨 Attack analysis", "📡 Network behavior", "🔎 Data explorer"]
    )

    with overview:
        left, right = st.columns(2)
        with left:
            section_heading("Traffic composition", "A high-level view of benign and malicious flows")
            pie = pd.DataFrame({"traffic": ["Benign", "Attack"], "count": [summary["benign"], summary["attacks"]]})
            figure = px.pie(pie, names="traffic", values="count", hole=0.58, color="traffic",
                            color_discrete_map={"Benign": COLORS["green"], "Attack": COLORS["red"]})
            figure.update_traces(textposition="inside", textinfo="percent+label", marker={"line": {"color": "white", "width": 3}})
            st.plotly_chart(styled_chart(figure),
                            use_container_width=True)
        with right:
            section_heading("Attack categories", "Distribution across the eight capture groups")
            figure = px.bar(categories_df, x="category", y="count", color="category",
                            text_auto=".2s", color_discrete_sequence=px.colors.qualitative.Bold)
            figure.update_layout(showlegend=False, xaxis_title=None, yaxis_title="Flow count")
            st.plotly_chart(styled_chart(figure), use_container_width=True)

    with attacks:
        distribution = load_attack_distribution(tuple(selected_categories))
        section_heading("Attack label distribution", "Select categories in the sidebar to focus the investigation")
        figure = px.bar(distribution.head(20), x="count", y="label", orientation="h",
                        color="count", text_auto=".2s", color_continuous_scale="Turbo")
        figure.update_layout(yaxis={"categoryorder": "total ascending"}, xaxis_title="Flow count", yaxis_title=None)
        st.plotly_chart(styled_chart(figure), use_container_width=True)
        st.dataframe(distribution, use_container_width=True, hide_index=True)

    with behavior:
        duration_docs = load_mapreduce("mr_avg_flow_duration", "value.avg")
        duration = pd.DataFrame([
            {"category": doc["_id"], "average_duration": doc["value"].get("avg", 0)}
            for doc in duration_docs
        ])
        traffic_docs = load_mapreduce("mr_traffic_volume_by_day", "value.total_bytes")
        traffic = pd.DataFrame([
            {"source_file": doc["_id"], "total_bytes": doc["value"].get("total_bytes", 0)}
            for doc in traffic_docs
        ])
        left, right = st.columns(2)
        with left:
            section_heading("Average flow duration", "Longer durations can reveal sustained or abnormal sessions")
            figure = px.bar(duration, x="category", y="average_duration", color="category",
                            color_discrete_sequence=px.colors.qualitative.Vivid)
            figure.update_layout(showlegend=False, xaxis_title=None, yaxis_title="Average duration (μs)")
            st.plotly_chart(styled_chart(figure), use_container_width=True)
        with right:
            section_heading("Traffic volume by capture file", "Total forward and backward bytes by capture session")
            figure = px.bar(traffic, x="source_file", y="total_bytes", color="total_bytes",
                            color_continuous_scale="Tealgrn")
            figure.update_layout(xaxis_title=None, yaxis_title="Total bytes")
            st.plotly_chart(styled_chart(figure), use_container_width=True)

        flags_docs = load_mapreduce("mr_flag_analysis")
        flag_rows = []
        for doc in flags_docs:
            value = doc.get("value", {})
            for flag in ("syn", "fin", "rst", "psh", "ack"):
                flag_rows.append({"label": doc["_id"], "flag": flag.upper(), "average": value.get(f"avg_{flag}", 0)})
        section_heading("Average TCP flag counts", "Flag intensity by traffic label")
        figure = px.density_heatmap(pd.DataFrame(flag_rows), x="flag", y="label", z="average",
                                    color_continuous_scale="Plasma", text_auto=".2f")
        st.plotly_chart(styled_chart(figure),
                        use_container_width=True)

    with explorer:
        sample = load_sample(tuple(selected_categories), sample_size)
        if sample.empty:
            st.info("No sampled records match the selected categories.")
        else:
            sample["packet_count"] = (
                pd.to_numeric(sample["total_fwd_packets"], errors="coerce").fillna(0)
                + pd.to_numeric(sample["total_backward_packets"], errors="coerce").fillna(0)
            )
            section_heading("Flow duration vs packet count", "Hover over any point to inspect the underlying flow")
            chart = px.scatter(sample, x="flow_duration", y="packet_count", color="attack_category",
                               hover_data=["label", "destination_port", "source_file"],
                               log_x=True, opacity=0.72, color_discrete_sequence=px.colors.qualitative.Safe,
                               size_max=12)
            chart.update_layout(xaxis_title="Flow duration (μs, log scale)", yaxis_title="Forward + backward packets")
            st.plotly_chart(styled_chart(chart), use_container_width=True)
            st.dataframe(sample, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    render_dashboard()
