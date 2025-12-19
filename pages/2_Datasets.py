import streamlit as st
import plotly.express as px
import pandas as pd
import os
from app.data.db import connect_database
from app.data.datasets import get_all_datasets, insert_dataset
from data_charts import DataCharts

# Guard
if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.error("You must be logged in to view this page")
    if st.button("Go to login"):
        st.switch_page("Home.py")
    st.stop()

st.title("Datasets Dashboard")
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

# Load datasets
conn = connect_database("DATA/intelligence_platform.db")
df = pd.DataFrame(get_all_datasets(conn))

st.subheader("All Datasets")
st.dataframe(df, width="stretch")

# KPIs
col1, col2 = st.columns(2)
with col1:
    st.metric("Total Datasets", len(df))
with col2:
    st.metric("Largest Dataset Size", df["file_size_mb"].max() if not df.empty else 0)

# Interactive chart
if not df.empty:
    fig = px.bar(df, x="dataset_name", y="file_size_mb", title="Dataset Sizes (MB)")
    st.plotly_chart(fig, width="stretch")

# Static chart generation
dc = DataCharts()
if not df.empty:
    dc.set_df(df)
    dc.generate_charts(output_dir="charts", show=False)

chart_path = "charts/bar_dataset_name.png"
if os.path.exists(chart_path):
    st.image(chart_path, caption="Dataset Counts by Name")
else:
    st.info("No static chart available yet — seed data first or add records.")

# Add new dataset
st.subheader("Add New Dataset")
with st.form("new_dataset"):
    name_ds = st.text_input("Dataset Name")
    source = st.text_input("Source")
    category = st.text_input("Category")
    size = st.number_input("Size (MB)", min_value=0)
    submitted = st.form_submit_button("Add Dataset")
    if submitted:
        insert_dataset(conn, name_ds, source, category, size)
        st.success("Dataset added successfully!")
        st.rerun()

# Logout
st.divider()
if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.switch_page("Home.py")