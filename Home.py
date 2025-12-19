import streamlit as st
from app.services.user_service import login_user, register_user
from app.data.users import get_user_role
from app.data.db_helpers import connect_database, ensure_tables, seed_admin

st.set_page_config(page_title="Intelligence Platform", layout="wide")
st.title("Intelligence Platform Login")

#Ensures DB and tables exist before anything else
conn = connect_database()
ensure_tables(conn)
seed_admin(conn)  # optional: guarantees a default admin account

#Initialize session state.
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = ""

# Tabs for login and registration.
tab_login, tab_register = st.tabs(["Login", "Register"])

# LOGIN TAB
with tab_login:
    st.subheader("Login")
    login_username = st.text_input("Username", key="login_username")
    login_password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        success, msg = login_user(login_username, login_password)
        if success:
            st.session_state.logged_in = True
            st.session_state.username = login_username
            st.session_state.role = get_user_role(login_username)  # fetch role from DB

            st.success(f"Login successful! Role: {st.session_state.role}")

            #Redirect the user to correct dashboard.
            if st.session_state.role == "analyst":
                st.switch_page("pages/1_Cyber_Incidents.py")
            elif st.session_state.role == "admin":
                st.switch_page("pages/2_Datasets.py")
            elif st.session_state.role == "it_support":
                st.switch_page("pages/3_IT_Tickets.py")
            else:
                st.error("Unknown role. Please contact admin.")
        else:
            st.error(msg)

# REGISTER TAB
with tab_register:
    st.subheader("Register")
    new_username = st.text_input("Choose a username", key="register_username")
    new_password = st.text_input("Choose a password", type="password", key="register_password")
    confirm_password = st.text_input("Confirm password", type="password", key="register_confirm")

    if st.button("Create account"):
        if not new_username or not new_password:
            st.warning("Please fill in all fields.")
        elif new_password != confirm_password:
            st.error("Passwords do not match.")
        else:
            # Default role assigned on registration (can be changed later by admin)
            success, msg = register_user(new_username, new_password, "analyst")
            if success:
                st.success("Account created! Go to Login tab to sign in.")
            else:
                st.error(msg)