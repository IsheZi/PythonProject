import streamlit as st
import plotly.express as px
import pandas as pd
import os
from app.data.db import connect_database
from app.data.tickets import get_all_tickets, insert_ticket
from data_charts import DataCharts

# Guard
if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.error("You must be logged in to view this page")
    if st.button("Go to login"):
        st.switch_page("Home.py")
    st.stop()

st.title("IT Tickets Dashboard")
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

# Load tickets
conn = connect_database("DATA/intelligence_platform.db")
df = pd.DataFrame(get_all_tickets(conn))

st.subheader("All IT Tickets")
st.dataframe(df, width="stretch")

# KPIs with delta arrows (sample deltas shown)
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Tickets", len(df), delta="+1")
with col2:
    st.metric("Open Tickets", len(df[df["status"] == "Open"]), delta="-2")
with col3:
    st.metric("Resolved Tickets", len(df[df["status"] == "Resolved"]), delta="+3")

# Interactive chart
if not df.empty:
    fig = px.pie(df, names="status", title="Ticket Status Distribution")
    st.plotly_chart(fig, width="stretch")

# Static chart generation
dc = DataCharts()
if not df.empty:
    dc.set_df(df)
    dc.generate_charts(output_dir="charts", show=False)

chart_path = "charts/pie_status.png"
if os.path.exists(chart_path):
    st.image(chart_path, caption="Ticket Status Distribution (Static)")
else:
    st.info("No static chart available yet — seed data first or add records.")

# Add new ticket
st.subheader("Add New Ticket")
with st.form("new_ticket"):
    subject = st.text_input("Ticket Title")
    priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"])
    status = st.selectbox("Status", ["Open", "In Progress", "Resolved", "Waiting for User"])
    description = st.text_input("Description")
    submitted = st.form_submit_button("Add Ticket")
    if submitted:
        insert_ticket(conn, subject, priority, status, description, "system")
        st.success("Ticket added successfully!")
        st.rerun()

# Logout
st.divider()
if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.switch_page("Home.py")