# CW2_1510 
# Multi-Domain Intelligence Platform

## Overview
The Multi-Domain Intelligence Platform is a modular Streamlit application designed to unify secure data management, visualization, and monitoring across multiple domains.  
It supports **three domains**:
- **Cybersecurity Incidents**: Track phishing, malware, and unauthorized access events.
- **Data Science**: Analyze datasets such as customer churn and fraud detection.
- **IT Operations**: Monitor IT tickets and operational logs for workflow efficiency.

The platform was implemented at **Tier 2**, combining secure authentication, CRUD functionality, interactive dashboards, and KPI tracking.

---

## Features
- 🔐 **Secure Authentication**  
  - Password hashing with SHA‑256  
  - Session management for user login/logout  

- 🗄️ **Database Design**  
  - SQLite database with normalized schema  
  - Tables for `users` and `incidents`  
  - CRUD operations for incident lifecycle management  
  - Seeding scripts for reproducibility  

- 🖥️ **System Architecture (MVC Inspired)**  
  - **Model**: Database queries and schema (`db.py`, `incidents.py`)  
  - **View**: Streamlit dashboards and charts  
  - **Controller**: Business logic, session state, and data flow  

- 📊 **Interactive Visualizations**  
  - Bar chart: incidents by type and severity  
  - Histogram: severity distribution  
  - Pie chart: status breakdown  
  - Scatter matrix: numeric relationships  

- 📝 **Incident Analyzer**  
  - Dropdown selection of incidents (`ID: Type – Severity`)  
  - Detailed view of attributes (type, severity, description, status)  
  - Add new incidents via form submission  

---

## Installation

Clone the repository:
```bash
git clone [your-repo-link]
cd multi-domain-intelligence-platform