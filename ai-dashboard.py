import streamlit as st
import boto3
import pandas as pd
import re
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, time
from openai import OpenAI
import os
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import tempfile
from reportlab.lib.utils import ImageReader
from PIL import Image
# ─────────────────────────────────────────────────────────────
# ✅ Session State Initialization
# ─────────────────────────────────────────────────────────────
for key, default in {
    "ai_ready": False,
    "ai_result": None,
    "current_gauge_index": 0,
    "gauge_figures": {},
    "anomaly_data": [],
    "logs_loaded": False,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ─────────────────────────────────────────────────────────────
# ✅ Threat Patterns & Severity
# ─────────────────────────────────────────────────────────────
SECURITY_PATTERNS = {
    "Brute Force Attack": r"(brute[- ]?force|failed login|attempts=\d+)",
    "DDoS Attack": r"(DDoS|pps=\d+)",
    "Malware Upload Attempt": r"(malware|\.exe|\.scr|upload)",
    "Phishing Attempt": r"(phishing|http://.*login|fake-login|reset-password)",
    "Unauthorized Access": r"(unauthorized|denied|forbidden|401|403|access.*denied)",
    "Privilege Escalation": r"(sudo su|chmod 777|cat /etc/shadow|sudo -i)",
    "Sensitive File Access": r"(/etc/passwd|/secret\.env|shadow|admin-panel|keys)",
    "Suspicious Outbound Traffic": r"(exfiltration|bytes_sent=\d+)",
    "Port Scan": r"(port scan|nmap|ports=\[)",
    "File Tampering": r"(/boot/grub\.cfg|file overwrite)",
    "Rogue Command Execution": r"(rm -rf|wget http|curl|patch /etc)",
}

SEVERITY_MAP = {
    "Privilege Escalation": "Critical", "DDoS Attack": "Critical",
    "Sensitive File Access": "High", "Malware Upload Attempt": "High",
    "Rogue Command Execution": "High",
    "Unauthorized Access": "Medium", "Brute Force Attack": "Medium",
    "File Tampering": "Medium", "Phishing Attempt": "Medium",
    "Suspicious Outbound Traffic": "Low", "Port Scan": "Low",
}

SEVERITY_COLOR = {
    "Critical": (255, 0, 0),
    "High": (255, 140, 0),
    "Medium": (255, 215, 0),
    "Low": (34, 139, 34),
}

# ─────────────────────────────────────────────────────────────
# ✅ AWS + OpenAI Clients
# ─────────────────────────────────────────────────────────────
REGION = "ap-south-1"
LOG_GROUP_NAME = "my-anomaly-log"
S3_BUCKET_NAME = "my-threat-analysis-project"
S3_LOG_PREFIX = "logs/"
cloudwatch = boto3.client("logs", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY_2"))

# ─────────────────────────────────────────────────────────────
# ✅ Utility Functions
# ─────────────────────────────────────────────────────────────
def read_cloudwatch_logs(group, start, end):
    start_ms = int(start.timestamp() * 1000)
    end_ms = int(end.timestamp() * 1000)
    events = []

    streams = cloudwatch.describe_log_streams(
        logGroupName=group, orderBy="LastEventTime", descending=True, limit=5
    )

    for stream in streams["logStreams"]:
        logs = cloudwatch.get_log_events(
            logGroupName=group,
            logStreamName=stream["logStreamName"],
            startTime=start_ms, endTime=end_ms, limit=1000
        )
        events.extend([e["message"] for e in logs["events"]])
    return events
def get_ai_suggestions(anomalies):
    if not anomalies:
        return ["✅ No anomalies to analyze."]

    # Extract unique threat types
    unique_types = sorted({a[0] for a in anomalies})
    threat_list_text = ", ".join(unique_types)

    prompt = f"""
You are a cybersecurity analyst for AWS cloud environment.

Detected security threat categories:
{threat_list_text}

For each threat above:
- Explain why it's dangerous
- Provide AWS-specific remediations
- Mention related AWS services (IAM, GuardDuty, WAF, CloudTrail, Security Hub, Shield, VPC, KMS etc.)
- Provide MITRE ATT&CK technique mapping where relevant
- Provide short SOC playbook response steps
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-nano",
            messages=[
                {"role": "system", "content": "You are a senior cloud security architect."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=2500,
        )

        output = response.choices[0].message.content
        return output.splitlines()

    except Exception as e:
        print(str(e))
        return [f"❌ OpenAI API Error: {str(e)}"]

def read_s3_logs(bucket, prefix):
    logs = []
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    for obj in resp.get("Contents", [])[:5]:
        content = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode()
        logs.extend(content.strip().split("\n"))
    return logs

def categorize_log_event(log_line):
    for category, pattern in SECURITY_PATTERNS.items():
        if re.search(pattern, log_line, re.IGNORECASE):
            return category
    return "Normal"

def detect_anomalies(logs):
    return [(cat, line) for line in logs if (cat := categorize_log_event(line)) != "Normal"]

def create_gauge_figure(anomaly_type, count, max_val, severity):
    return go.Figure(
        go.Indicator(
            mode="gauge+number", value=count,
            title={"text": f"{anomaly_type}<br><span style='font-size:0.8em;color:gray'>Severity: {severity}</span>"},
            gauge={
                "axis": {"range": [0, max_val]},
                "bar": {"color": {"Critical":"red","High":"orange","Medium":"yellow","Low":"green"}[severity]},
            }
        )
    ).update_layout(height=400)


def generate_pdf_report(anomalies):
    df = pd.DataFrame(anomalies, columns=["Type", "Log"])
    grouped = df.groupby("Type")["Log"].apply(list).reset_index()

    # ----------- Generate Charts as Images  ----------
    pie_img = None
    timeline_img = None

    if not grouped.empty:
            # PIE CHART
        pie_img = None
        timeline_img = None
        pie_data = df["Type"].value_counts().reset_index()
        pie_data.columns = ["Threat", "Count"]

        pie_colors = ["#D7263D", "#F46036", "#2E294E", "#1B998B", "#C5D86D", "#F6AE2D",
                      "#33658A", "#6F2DBD", "#FF6B6B", "#4CAF50"]  # enough distinct colors

        fig_pie = px.pie(
            pie_data,
            values="Count",
            names="Threat",
            title="Threat Distribution",
            color="Threat",
            color_discrete_sequence=pie_colors[:len(pie_data)]
        )

        fig_pie.update_layout(
            paper_bgcolor="white",
            plot_bgcolor="white"
        )

        pie_buffer = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        fig_pie.write_image(pie_buffer.name, format="png", scale=2)
        pie_img = pie_buffer.name

        # TIME SERIES — colored lines
        df["Timestamp"] = df["Log"].str.extract(r"(\d{4}-\d{2}-\d{2}T[\d:]+Z)")
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        df = df.dropna(subset=["Timestamp"])

        ts = df.groupby(
            [pd.Grouper(key="Timestamp", freq="1Min"), "Type"]
        ).size().reset_index(name="Count")

        fig_ts = px.line(
            ts,
            x="Timestamp",
            y="Count",
            color="Type",
            title="Threat Events Over Time",
            color_discrete_sequence=pie_colors,
            markers=True
        )

        fig_ts.update_layout(
            paper_bgcolor="white",
            plot_bgcolor="white",
            font=dict(size=10, color="black")
        )

        ts_buffer = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        fig_ts.write_image(ts_buffer.name, format="png", scale=2)
        timeline_img = ts_buffer.name


    # ----------- PDF Generation ------------
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, height - 40, "AWS Security Anomaly Report")

    y = height - 80
    c.setFont("Helvetica", 12)
    c.drawString(30, y, "Overview Charts")
    y -= 20

    # Draw Pie Chart
    if pie_img:
        c.drawImage(ImageReader(pie_img), 60, y - 250, width=450, height=250)
        y -= 270

    # Draw Time Series Chart
    if timeline_img:
        c.drawImage(ImageReader(timeline_img), 60, y - 250, width=450, height=250)
        y -= 270

    # Section Title
    c.showPage()
    c.setFont("Helvetica-Bold", 14)
    c.drawString(30, height - 50, "Threat Details & Logs")
    y = height - 80

    if grouped.empty:
        c.drawString(40, y, "✅ No anomalies detected.")
        c.save()
        buf.seek(0)
        return buf

    for idx, row in grouped.iterrows():
        atype = row["Type"]
        logs = row["Log"]
        count = len(logs)
        sev = SEVERITY_MAP.get(atype, "Low")
        r, g, b = SEVERITY_COLOR[sev]

        # Threat Header
        c.setFont("Helvetica-Bold", 11)
        c.drawString(30, y, f"{idx+1}. {atype}   | Severity: {sev} | Count: {count}")
        y -= 14

        # Severity visual bar
        c.setFillColorRGB(r/255, g/255, b/255)
        c.rect(30, y, 520, 6, fill=1, stroke=0)
        c.setFillColorRGB(0, 0, 0)
        y -= 14

        # Logs
        c.setFont("Helvetica", 9)
        for log in logs:
            for line in log.split("\n"):
                if y < 40:
                    c.showPage()
                    y = height - 40
                    c.setFont("Helvetica", 9)
                c.drawString(30, y, f"- {line[:120]}")
                y -= 12

        y -= 10
        if y < 60:
            c.showPage()
            y = height - 40

    c.save()
    buf.seek(0)
    return buf


# ─────────────────────────────────────────────────────────────
# ✅ UI
# ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="Security Anomaly Cockpit", layout="wide")
st.title("🔐 Security Anomaly Cockpit")

# Date picker
default_end = datetime.utcnow()
default_start = default_end - timedelta(hours=1)
icon = Image.open("images/download.png")
col1, col2, col3 = st.sidebar.columns([1,2,1])
col2.image(icon, width=120)
#st.sidebar.image(icon,width=70)
#st.sidebar.title("🔐 Security Hub")
start_dt = st.sidebar.date_input("Start Date", default_start.date())
start_tm = st.sidebar.time_input("Start Time", default_start.time())
end_dt = st.sidebar.date_input("End Date", default_end.date())
end_tm = st.sidebar.time_input("End Time", default_end.time())
start = datetime.combine(start_dt, start_tm)
end = datetime.combine(end_dt, end_tm)

if st.sidebar.button("📥 Fetch Logs & Analyze"):
    st.info(f"Fetching logs from {start_dt} to {end_dt}...")
    logs = read_cloudwatch_logs(LOG_GROUP_NAME, start, end) + read_s3_logs(S3_BUCKET_NAME, S3_LOG_PREFIX)
    anomalies = detect_anomalies(logs)

    df = pd.DataFrame(anomalies, columns=["Type", "Log"])
    counts = df["Type"].value_counts().reset_index()
    counts.columns = ["Anomaly", "Count"]

    st.session_state.anomaly_data = counts.to_dict("records")
    st.session_state.current_gauge_index = 0
    st.session_state.logs_loaded = True

    max_val = counts["Count"].max() if len(counts) else 1
    st.session_state.gauge_figures = {
        r["Anomaly"]: create_gauge_figure(r["Anomaly"], r["Count"], max_val, SEVERITY_MAP[r["Anomaly"]])
        for r in st.session_state.anomaly_data
    }

# ─────────────────────────────────────────────────────────────
# ✅ Tabs Rendering (ALWAYS)
# ─────────────────────────────────────────────────────────────
tab_time, tab_logs, tab_anom, tab_charts, tab_ai, tab_pdf = st.tabs(
    ["⏱️ TimeLine","📄 Logs","🚨 Anomalies","📊 Charts","🤖 AI Suggestions","📄 Export Report"]
)
def main():
    # Charts Tab (Gauge Carousel)
    logs = read_cloudwatch_logs(LOG_GROUP_NAME, start, end) + read_s3_logs(S3_BUCKET_NAME, S3_LOG_PREFIX)
    anomalies = detect_anomalies(logs)
    df = pd.DataFrame(anomalies, columns=["Type", "Log Entry"])
    anomaly_counts = df['Type'].value_counts().reset_index()
    anomaly_counts.columns = ['Anomaly Type', 'Count']
     
    with tab_time:
        if st.session_state.logs_loaded:
            st.subheader("⏱️ Anomaly Timeline")
            if anomalies:
                df = pd.DataFrame(anomalies, columns=["Type", "Log Entry"])

                # Extract timestamp from logs (CloudWatch ISO timestamps)
                df["Timestamp"] = df["Log Entry"].str.extract(r"(\d{4}-\d{2}-\d{2}T[\d:]+Z)")

                # Convert to datetime
                df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors='coerce')

                # Drop rows without valid timestamps
                df = df.dropna(subset=["Timestamp"])

                # Sort by time
                df = df.sort_values("Timestamp")

                st.write("### 📈 Threats Identified Over Time")

                fig = px.scatter(
                    df,
                    x="Timestamp",
                    y="Type",
                    color="Type",
                    size_max=10,
                    title="Anomalies by Time",
                    labels={"Type": "Threat Type", "Timestamp": "Time"},
                )

                fig.update_traces(marker=dict(size=12))
                st.plotly_chart(fig, use_container_width=True)

                # Line count trend chart
                st.write("### 📊 Threat Frequency Trend")

                time_series = df.groupby([pd.Grouper(key="Timestamp", freq="1Min"), "Type"]).size().reset_index(name="Count")

                fig2 = px.line(
                    time_series,
                    x="Timestamp",
                    y="Count",
                    color="Type",
                    title="Threat Trend Over Time",
                    markers=True
                )
                st.plotly_chart(fig2, use_container_width=True)

            else:
                st.info("No anomalies with timestamps found.")
    # Logs tab
    with tab_logs:
        if st.session_state.logs_loaded:
            cw_logs = read_cloudwatch_logs(LOG_GROUP_NAME, start, end)
            s3_logs = read_s3_logs(S3_BUCKET_NAME, S3_LOG_PREFIX)
            all_logs = cw_logs + s3_logs
            st.subheader("📜 CloudWatch Logs")
            st.code("\n".join(cw_logs[:20]))
            st.subheader("📜 S3 Logs")
            st.code("\n".join(s3_logs[:20]))

    # Anomaly tab
    with tab_anom:
        if st.session_state.logs_loaded:
           st.subheader("☢️ Anomalies and log details")
           st.write(pd.DataFrame(detect_anomalies(read_cloudwatch_logs(LOG_GROUP_NAME, start, end) + read_s3_logs(S3_BUCKET_NAME, S3_LOG_PREFIX)), columns=["Type","Log"]))
           st.subheader("🕵️‍♂️ Anomalies occurences")
           st.dataframe(pd.DataFrame(st.session_state.anomaly_data), use_container_width=True)                
    with tab_charts:
        st.subheader("📊 Threats")

        if not st.session_state.logs_loaded:
            st.info("Click **Fetch Logs & Analyze** to begin.")
        else:
            data = st.session_state.anomaly_data
            idx = st.session_state.current_gauge_index

            col1, col2, col3 = st.columns([1,2,1])
            with col1:
                st.button("⬅️", on_click=lambda: st.session_state.update(
                    current_gauge_index=max(0, idx-1)))

            with col3:
                st.button("➡️", on_click=lambda: st.session_state.update(
                    current_gauge_index=min(len(data)-1, idx+1)))

            anomaly = data[idx]["Anomaly"]
            st.plotly_chart(st.session_state.gauge_figures[anomaly], use_container_width=True)
            st.caption(f"{idx+1}/{len(data)} — {anomaly}")
        # ✅ Pie chart still used for distribution
        st.write("### 📎 Threat Distribution Overview")
        pie_chart = px.pie(anomaly_counts, values='Count', names='Anomaly Type')
        st.plotly_chart(pie_chart, use_container_width=True)
    # PDF tab
    with tab_pdf:
        if st.session_state.logs_loaded:
            buf = generate_pdf_report(detect_anomalies(
                read_cloudwatch_logs(LOG_GROUP_NAME, start, end) + read_s3_logs(S3_BUCKET_NAME, S3_LOG_PREFIX)
            ))
            st.download_button("📄 Download Report", data=buf, file_name="anomaly_report.pdf", mime="application/pdf")

    # AI tab
    with tab_ai:
        if st.session_state.logs_loaded:
            st.subheader("🧠✨ AI recommendations !!")
            if anomalies:
                    with st.spinner("Analyzing anomalies using AI..."):
                        ai_suggestions = get_ai_suggestions(anomalies)
                        st.session_state.ai_ready = True

                    for s in ai_suggestions:
                        st.markdown(f"{s}")

            else:
                st.info("No anomalies to analyze.")

if __name__ == "__main__":
    main()