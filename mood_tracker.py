import streamlit as st
import requests
import json
from fpdf import FPDF
from io import BytesIO
import os
import re
import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime
import pandas as pd
import plotly.graph_objects as go
import hashlib


st.set_page_config(page_title="Manasāroha: Your Mental Wellness Companion", page_icon="🧘", layout="centered")

# Load secrets
API_KEY = st.secrets["openrouter_api_key"]["openrouter_api_key"]
SHEET_KEY = st.secrets["sheet_id"]["sheet_id"]

def extract_mood_score(mood_result):
    mood_map = {
        "happy": 5,
        "joy": 5,
        "content": 4,
        "neutral": 3,
        "anxious": 2,
        "sad": 1,
        "depressed": 1
    }
    for mood, score in mood_map.items():
        if mood in mood_result.lower():
            return score
    return 3


@st.cache_resource
def connect_to_gsheet():
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds_info = json.loads(st.secrets["gcp"]["gcp_credentials"])
    creds = Credentials.from_service_account_info(creds_info, scopes=scope)
    client = gspread.authorize(creds)
    return client

def get_main_sheet():
    client = connect_to_gsheet()
    return client.open_by_key(SHEET_KEY).sheet1

def get_user_sheet():
    client = connect_to_gsheet()
    spreadsheet = client.open_by_key(SHEET_KEY)
    try:
        sheet = spreadsheet.worksheet("Users")
    except:
        sheet = spreadsheet.add_worksheet(title="Users", rows="100", cols="6")
        sheet.append_row(["Email", "Name", "Password", "LastActivityDate", "Streak", "XP"])

    header = sheet.row_values(1)
    required_columns = ["LastActivityDate", "Streak", "XP"]
    for col in required_columns:
        if col not in header:
            col_index = header.index('Password') + required_columns.index(col) + 2
            if col_index > sheet.col_count:
                sheet.add_cols(col_index - sheet.col_count)
            sheet.update_cell(1, col_index, col)
            header = sheet.row_values(1)

    return sheet

# (The rest of the code remains unchanged)


def save_mood_to_sheet(name, age, user_type, mood_text, mood_result, recommendation):
    sheet = get_main_sheet()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mood_score = extract_mood_score(mood_result)
    row = [timestamp, name, age, user_type, mood_text, mood_result, recommendation, mood_score]
    sheet.append_row(row)

def update_xp_and_streak(email):
    sheet = get_user_sheet()
    users = sheet.get_all_records()
    today = datetime.now().strftime("%Y-%m-%d")

    for idx, user in enumerate(users, start=2):
        if user["Email"] == email:
            last_date = user.get("LastActivityDate", "")
            streak = int(user.get("Streak", 0))
            xp = int(user.get("XP", 0))

            if last_date != today:
                if last_date == (datetime.now() - pd.Timedelta(days=1)).strftime("%Y-%m-%d"):
                    streak += 1
                else:
                    streak = 1
                xp += 10
                sheet.update(f"D{idx}:F{idx}", [[today, streak, xp]])
            break

def update_xp_and_streak(email):
    sheet = get_user_sheet()
    users = sheet.get_all_records()
    today = datetime.now().strftime("%Y-%m-%d")

    for idx, user in enumerate(users, start=2):
        if user["Email"] == email:
            last_date = user.get("LastActivityDate", "")
            streak = int(user.get("Streak") or 0)
            xp = int(user.get("XP") or 0)

            if last_date != today:
                if last_date == (datetime.now() - pd.Timedelta(days=1)).strftime("%Y-%m-%d"):
                    streak += 1
                else:
                    streak = 1
                xp += 10
                sheet.update(f"D{idx}:F{idx}", [[today, streak, xp]])
            break


def load_mood_data():
    sheet = get_main_sheet()
    data = sheet.get_all_records()
    return pd.DataFrame(data)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password, hashed):
    return hash_password(password) == hashed

def signup(email, name, password):
    user_sheet = get_user_sheet()
    users = user_sheet.get_all_records()
    if any(user["Email"] == email for user in users):
        return "User already exists!"
    hashed_pw = hash_password(password)
    user_sheet.append_row([email, name, hashed_pw])
    return "Account created successfully!"

def login(email, password):
    user_sheet = get_user_sheet()
    users = user_sheet.get_all_records()
    for user in users:
        if user["Email"] == email and check_password(password, user["Password"]):
            return user["Name"]
    return None



def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

@st.cache_resource
def get_mood_analysis(user_input):
    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
            },
            data=json.dumps({
                "model": "deepseek/deepseek-r1:free",
                "messages": [
                    {"role": "system", "content": "You are an AI assistant that detects user mood based on text input and provides recommendations."},
                    {"role": "user", "content": user_input}
                ]
            })
        )
        response_json = response.json()
        return response_json["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"API Error: {str(e)}"

@st.cache_resource
def get_mood_recommendation(user_input):
    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
            },
            data=json.dumps({
                "model": "deepseek/deepseek-r1:free",
                "messages": [
                    {"role": "system", "content": "You are a movie recommendation system. Based only on the user's mood, recommend one movie, one song, and one book."},
                    {"role": "user", "content": user_input}
                ]
            })
        )
        response_json = response.json()
        return response_json["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"API Error: {str(e)}"

def strip_unsupported_chars(text):
    return re.sub(r'[^\x00-\x7F]+', '', text)

class UnicodePDF(FPDF):
    def __init__(self):
        super().__init__()
        font_dir = os.path.join("dejavu-fonts-ttf-2.37", "ttf")
        self.add_font("DejaVu", "", os.path.join(font_dir, "DejaVuSans.ttf"), uni=True)
        self.add_font("DejaVu", "B", os.path.join(font_dir, "DejaVuSans-Bold.ttf"), uni=True)

    def header(self):
        self.set_font("DejaVu", "B", 16)
        self.cell(0, 10, "Manasāroha Mood Report", ln=True, align='C')
        self.ln(10)

def generate_pdf_report(name, age, user_type, mood, recommendation):
    mood = strip_unsupported_chars(mood)
    recommendation = strip_unsupported_chars(recommendation)
    pdf = UnicodePDF()
    pdf.add_page()

    pdf.set_font("DejaVu", "", 12)
    pdf.cell(0, 10, f"Name: {name}", ln=True)
    pdf.cell(0, 10, f"Age: {age}", ln=True)
    pdf.cell(0, 10, f"User Type: {user_type}", ln=True)

    pdf.ln(5)
    pdf.set_font("DejaVu", "B", 13)
    pdf.cell(0, 10, "Detected Mood:", ln=True)
    pdf.set_font("DejaVu", "", 12)
    pdf.multi_cell(0, 10, mood)

    pdf.ln(5)
    pdf.set_font("DejaVu", "B", 13)
    pdf.cell(0, 10, "Recommendations:", ln=True)
    pdf.set_font("DejaVu", "", 12)
    pdf.multi_cell(0, 10, recommendation)

    buffer = BytesIO()
    pdf_output = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_output)
    buffer.seek(0)
    return buffer


st.markdown("""
    <style>
        * { font-family: 'Times New Roman', Times, serif; }
        body { background-color: #f7f9fc; }
        h1 { color: #2c3e50; font-size: 36px; font-weight: bold; text-align: center; }
        .subtitle { color: #34495e; font-size: 18px; text-align: center; margin-bottom: 30px; }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            border-radius: 8px;
            padding: 10px 20px;
            font-size: 18px;
        }
    </style>
""", unsafe_allow_html=True)


st.sidebar.title("Authentication")
auth_mode = st.sidebar.radio("Login or Sign Up", ["Login", "Sign Up"])
email_input = st.sidebar.text_input("Email")
password_input = st.sidebar.text_input("Password", type="password")

if st.session_state.get("authenticated"):
    if st.sidebar.button("Log Out"):
        st.session_state.clear()
        st.rerun()
else:
    if auth_mode == "Sign Up":
        name_input = st.sidebar.text_input("Your Name")
        if st.sidebar.button("Create Account"):
            if email_input and password_input and name_input:
                msg = signup(email_input, name_input, password_input)
                st.sidebar.success(msg if "success" in msg.lower() else "")
                st.sidebar.error(msg if "exists" in msg.lower() else "")
            else:
                st.sidebar.warning("Fill all fields to sign up.")
    else:
        if st.sidebar.button("Log In"):
            user_name = login(email_input, password_input)
            if user_name:
                st.session_state["user_name"] = user_name
                st.session_state["authenticated"] = True
                st.sidebar.success(f"Welcome back, {user_name}!")
            else:
                st.sidebar.error("Invalid email or password.")


if st.session_state.get("authenticated"):
    st.markdown("""<h1>🌿 Manasāroha: Your Mental Wellness Companion</h1>
    <p class='subtitle'>Guiding you towards inner peace, clarity, and emotional balance through ancient wisdom and modern mindfulness techniques.</p>""", unsafe_allow_html=True)

    user_name = st.session_state["user_name"]

    
    st.markdown("### 🎮 Your Gamification Dashboard")

    user_sheet = get_user_sheet()
    users = user_sheet.get_all_records()
    user_data = next((u for u in users if u["Email"] == email_input), {})

    if user_data:
        streak = int(user_data.get("Streak") or 0)
        xp = int(user_data.get("XP") or 0)

        if streak >= 10:
            badge = "🥇 Gold Streaker"
        elif streak >= 5:
            badge = "🥈 Silver Streaker"
        elif streak >= 2:
            badge = "🥉 Bronze Streaker"
        else:
            badge = "✨ New Explorer"

        xp_progress = min(xp % 100, 100)
        xp_level = xp // 100 + 1

        st.markdown(f"""
            **👋 Hello, `{user_name}`**

            - 🔥 Current Streak: `{streak}` days  
            - 🧠 XP Score: `{xp}` (Level {xp_level})  
            - 🎖️ Badge: `{badge}`  
        """)

        st.progress(xp_progress / 100)
        st.info("Keep logging your mood daily to level up and unlock better badges!")

    user_age = st.number_input("What's your age?", min_value=0, max_value=120, step=1)
    user_type = st.radio("Are you a student or a working professional?", options=["Student", "Working Professional"])

    if user_name and user_age and user_type:
        st.markdown(f"Hello, {user_name}! Let's explore your mental wellness journey. 🌿")

        st.subheader("💭 How are you feeling today?")
        user_input = st.text_area("Type your emotions here...", placeholder="I feel...", height=120)

        if st.button("✨ Analyze Mood"):
            if user_input:
                with st.spinner("Analyzing your mood..."):
                    mood_result = get_mood_analysis(user_input)
                    rec_result = get_mood_recommendation(user_input)

                if "API Error" in mood_result or "API Error" in rec_result:
                    st.error("There was an error processing your request. Please try again later.")
                else:
                    st.success(f"🌼 **Detected Mood**: {mood_result.capitalize()}")
                    st.balloons()
                    st.markdown(f"📚 **Mindful Recommendations:**\n\n{rec_result}")

                    save_mood_to_sheet(user_name, user_age, user_type, user_input, mood_result, rec_result)
                    update_xp_and_streak(email_input)

                    pdf_buffer = generate_pdf_report(user_name, user_age, user_type, mood_result, rec_result)
                    st.download_button(
                        label="📄 Download Report as PDF",
                        data=pdf_buffer,
                        file_name="manasaroha_report.pdf",
                        mime="application/pdf"
                    )
            else:
                st.warning("Please enter some text to analyze your mood.")

    st.markdown("---")
    st.subheader("🗕 Mood History & Emotional Trends")

    if st.button("📊 Show My Mood Charts"):
        try:
            df = load_mood_data()
            if df.empty:
                st.info("No mood entries found yet.")
            else:
                df["Timestamp"] = pd.to_datetime(df["Timestamp"])
                df = df.sort_values(by="Timestamp")

                st.markdown("### 📈 Mood Trend Over Time")
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df["Timestamp"],
                    y=df["MoodScore"],
                    mode="lines+markers",
                    name="Mood Score",
                    line=dict(color="#6c63ff", width=2),
                    marker=dict(size=8)
                ))
                fig.update_layout(
                    xaxis_title="Date",
                    yaxis_title="Mood Score (1=Sad ➝ 5=Happy)",
                    yaxis=dict(range=[0.5, 5.5]),
                    height=400,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig)
        except Exception as e:
            st.error(f"Error loading mood data: {e}")
else:
    st.warning("Please log in to access the app.")
