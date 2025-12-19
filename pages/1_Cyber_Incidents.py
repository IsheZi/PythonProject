import streamlit as st
import plotly.express as px
import pandas as pd
import os
from google import genai
from app.data.db import connect_database
from app.data.incidents import get_all_incidents, insert_incident
from data_charts import DataCharts

# Guard
if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.error("You must be logged in to view this page")
    if st.button("Go to login"):
        st.switch_page("Home.py")
    st.stop()

st.title("Cyber Incidents Dashboard")
st.success(f"Welcome, {st.session_state.username}!")

# Initialize user/score table
if "user_scores" not in st.session_state:
    st.session_state.user_scores = pd.DataFrame(columns=["User", "Score"])

# Greeting input
name = st.text_input("Enter a name")
if st.button("Submit"):
    if name:
        if name in st.session_state.user_scores["User"].values:
            st.session_state.user_scores.loc[
                st.session_state.user_scores["User"] == name, "Score"
            ] += 1
        else:
            new_row = pd.DataFrame({"User": [name], "Score": [1]})
            st.session_state.user_scores = pd.concat(
                [st.session_state.user_scores, new_row], ignore_index=True
            )
        st.success(f"Hello {name}")

st.subheader("User Scores")
st.dataframe(st.session_state.user_scores, width="stretch")

# Load incidents
conn = connect_database("DATA/intelligence_platform.db")
df = pd.DataFrame(get_all_incidents(conn))

st.subheader("All Cyber Incidents")
st.dataframe(df, width="stretch")

# --- KPI calculations with dynamic deltas ---
current_total = len(df)
current_open = len(df[df["status"] == "Open"])
current_resolved = len(df[df["status"] == "Resolved"])

prev_total = st.session_state.get("prev_total", 0)
prev_open = st.session_state.get("prev_open", 0)
prev_resolved = st.session_state.get("prev_resolved", 0)

delta_total = current_total - prev_total
delta_open = current_open - prev_open
delta_resolved = current_resolved - prev_resolved

st.session_state.prev_total = current_total
st.session_state.prev_open = current_open
st.session_state.prev_resolved = current_resolved

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Incidents", current_total, delta=delta_total)
with col2:
    st.metric("Open Incidents", current_open, delta=delta_open)
with col3:
    st.metric("Resolved Incidents", current_resolved, delta=delta_resolved)

# Interactive chart
if not df.empty:
    fig = px.bar(df, x="incident_type", color="severity", title="Incidents by Type and Severity")
    st.plotly_chart(fig, width="stretch")

# Static chart generation
dc = DataCharts()
if not df.empty:
    dc.set_df(df)
    dc.generate_charts(output_dir="charts", show=False)

# Display static charts
for chart_file, caption in [
    ("hist_severity.png", "Histogram of Incident Severity"),
    ("pie_status.png", "Incident Status Distribution"),
    ("bar_dataset_name.png", "Datasets by Name"),
    ("scatter_matrix.png", "Scatter Matrix of Numeric Columns"),
]:
    chart_path = os.path.join("charts", chart_file)
    if os.path.exists(chart_path):
        st.image(chart_path, caption=caption)
    else:
        st.info(f"{caption} not available yet — seed data first or add records.")

# --- Gemini Analyzer (Incident-Specific) ---
st.subheader("Gemini Analyzer (Incident-Specific)")

client = genai.Client(api_key=st.secrets["API_KEY"])

if not df.empty:
    incident_options = [
        f"{row['id']}: {row['incident_type']} - {row['severity']}"
        for _, row in df.iterrows()
    ]

    selected_idx = st.selectbox(
        "Select incident to analyze:",
        range(len(df)),
        format_func=lambda i: incident_options[i]
    )

    incident = df.iloc[selected_idx]

    st.write("**Incident Details**")
    st.write(f"Type: {incident['incident_type']}")
    st.write(f"Severity: {incident['severity']}")
    st.write(f"Description: {incident['description']}")
    st.write(f"Status: {incident['status']}")

    incident_question = st.text_input("Ask Gemini about this incident")
    if st.button("Analyze Incident"):
        context = f"Incident Type: {incident['incident_type']}\n" \
                  f"Severity: {incident['severity']}\n" \
                  f"Description: {incident['description']}\n" \
                  f"Status: {incident['status']}\n"

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"Based on the following incident, answer the question:\n{context}\nQuestion: {incident_question}"
        )
        st.write("**Gemini Analyzer Response:**")
        st.write(response.text)

# Add new incident
st.subheader("Add New Incident")
with st.form("new_incident"):
    date = st.date_input("Date (YYYY-MM-DD)")
    incident_type = st.selectbox("Incident Type", ["Phishing", "Malware", "Unauthorized Access", "DDoS", "Misconfiguration"])
    severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
    status = st.selectbox("Status", ["Open", "In Progress", "Resolved"])
    description = st.text_input("Description")
    submitted = st.form_submit_button("Add Incident")
    if submitted:
        insert_incident(conn, incident_type, severity, status, description, "system", str(date))
        st.success("Incident added successfully!")
        st.rerun()

# Logout
st.divider()
if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.switch_page("Home.py")