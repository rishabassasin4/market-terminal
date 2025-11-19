import streamlit as st
import pandas as pd
import pandas_datareader.data as web
import yfinance as yf
import requests
import datetime as dt
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
import warnings
import json
import os
import hashlib
import secrets
import re

# Safe Import for Web Search
try:
    from duckduckgo_search import DDGS
    SEARCH_AVAILABLE = True
except ImportError:
    SEARCH_AVAILABLE = False

# Suppress warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

# ==========================================
# 1. PAGE CONFIGURATION & CSS
# ==========================================
st.set_page_config(
    page_title="Market Terminal Pro",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* CARD STYLING */
    div[data-testid="stMetric"] {
        background-color: #262730;
        border: 1px solid #444;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 0px 4px 6px rgba(0,0,0,0.3);
        min-height: 100px;
    }
    div[data-testid="stMetric"] label { color: #b0b0b0; font-size: 0.85rem; }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] { color: #ffffff; font-size: 1.6rem; font-weight: 600; }
    
    /* TAB STYLING */
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        background-color: #1E1E1E;
        border-radius: 5px 5px 0px 0px;
        gap: 2px;
        padding: 10px 20px;
        font-weight: bold;
    }
    .stTabs [aria-selected="true"] { background-color: #4CAF50; color: white; }
    
    /* CHART CONTAINER */
    .js-plotly-plot { border-radius: 10px; border: 1px solid #333; }

    /* AUTH CONTAINER */
    .auth-container {
        padding: 2rem;
        border-radius: 10px;
        background-color: #262730;
        border: 1px solid #444;
    }
</style>
""", unsafe_allow_html=True)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

# ==========================================
# 2. SECURE AUTHENTICATION SYSTEM
# ==========================================

USER_DB_FILE = "users.json"

def make_hash(password):
    """Creates a secure SHA-256 hash with a random salt"""
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"

def check_hash(stored_hash, password):
    """Verifies a password against the stored secure hash"""
    try:
        salt, h = stored_hash.split('$')
        verify = hashlib.sha256((salt + password).encode()).hexdigest()
        return h == verify
    except ValueError:
        return False # Malformed hash

def validate_input(username, password):
    """
    Security Check: Prevents Injection Attacks & Enforces Complexity
    - Username: Alphanumeric + Underscore only (No SQL/HTML chars)
    - Password: Min 8 chars
    """
    # Regex: Only letters, numbers, and underscores allowed. 3-20 chars.
    # This strictly blocks SQL injection characters like ' " ; --
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        return False, "Username must be 3-20 characters (Letters, Numbers, _ only)."
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
        
    return True, ""

def load_users():
    """Loads users from JSON file or creates default secure admin"""
    if not os.path.exists(USER_DB_FILE):
        # Create default admin with HASHED password
        default_db = {"admin": make_hash("password123")}
        with open(USER_DB_FILE, "w") as f:
            json.dump(default_db, f)
        return default_db
    
    try:
        with open(USER_DB_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_user(username, password):
    """Saves a new user with HASHED password"""
    users = load_users()
    users[username] = make_hash(password) # Never store plain text
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f)

def login_system():
    """Handles Login and Registration UI"""
    
    if "password_correct" not in st.session_state:
        st.session_state["password_correct"] = False

    if st.session_state["password_correct"]:
        return True

    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### 🔒 Secure Terminal Access")
        
        tab_login, tab_reg = st.tabs(["🔑 Log In", "➕ Register User"])
        
        users = load_users()

        # --- LOGIN TAB ---
        with tab_login:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Log In", type="primary", use_container_width=True)
                
                if submit:
                    # Validate inputs first (Anti-Injection)
                    is_valid, msg = validate_input(username, password)
                    if not is_valid:
                         st.error(f"⚠️ {msg}")
                    elif username in users and check_hash(users[username], password):
                        st.session_state["password_correct"] = True
                        st.session_state["user"] = username
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")

        # --- REGISTER TAB ---
        with tab_reg:
            with st.form("register_form"):
                st.caption("Create a new secure account.")
                new_user = st.text_input("New Username")
                new_pass = st.text_input("New Password", type="password")
                reg_submit = st.form_submit_button("Create Account", use_container_width=True)
                
                if reg_submit:
                    if new_user in users:
                        st.error("⚠️ User already exists!")
                    else:
                        # Security Validation
                        is_valid, msg = validate_input(new_user, new_pass)
                        if is_valid:
                            save_user(new_user, new_pass)
                            st.success(f"✅ User '{new_user}' created securely! Please Log In.")
                        else:
                            st.warning(f"⚠️ {msg}")

    return False

# ==========================================
# 3. HYBRID DATA ENGINE (FRED + TREASURY)
# ==========================================

def normalize_to_billions(series):
    if series.empty: return series
    last_val = series.iloc[-1]
    if last_val > 100_000_000: return series / 1_000_000_000 
    elif last_val > 100_000: return series / 1_000 
    return series

@st.cache_data(ttl=3600)
def fetch_tga_daily(years_back=1):
    try:
        base_url = "https://api.fiscaldata.treasury.gov/services/api/fiscal_service/v1/accounting/dts/dts_table_1"
        start_date = (dt.datetime.now() - dt.timedelta(days=365 * years_back)).strftime("%Y-%m-%d")
        params = {
            'fields': 'record_date,account_type,close_today_bal',
            'filter': f'record_date:gte:{start_date}',
            'page[size]': 5000, 'sort': '-record_date'
        }
        r = requests.get(base_url, params=params, headers=HEADERS)
        if r.status_code != 200: return pd.DataFrame()
        
        df = pd.DataFrame(r.json()['data'])
        df = df[df['account_type'].str.contains("Closing Balance", na=False)]
        df['date'] = pd.to_datetime(df['record_date']).dt.tz_localize(None)
        df['tga'] = df['close_today_bal'].astype(float)
        return df.set_index('date')[['tga']].sort_index()
    except: return pd.DataFrame()

@st.cache_data(ttl=3600)
def fetch_macro_data_fred(api_key, years_back=1):
    if not api_key: return None
    end_date = dt.datetime.now()
    start_date = end_date - dt.timedelta(days=365 * years_back)
    fred_tickers = ['WALCL', 'RRPONTSYD'] 
    
    try:
        macro = web.DataReader(fred_tickers, 'fred', start_date, end_date, api_key=api_key)
        macro = macro.rename(columns={'WALCL': 'fed_assets', 'RRPONTSYD': 'rrp'})
        
        tga_daily = fetch_tga_daily(years_back)
        if not tga_daily.empty:
            macro = macro.join(tga_daily, how='outer')
        else:
            tga_fred = web.DataReader('WTREGEN', 'fred', start_date, end_date, api_key=api_key)
            macro = macro.join(tga_fred.rename(columns={'WTREGEN': 'tga'}))

        macro['tga'] = normalize_to_billions(macro['tga'])
        macro['rrp'] = normalize_to_billions(macro['rrp'])
        macro['fed_assets'] = normalize_to_billions(macro['fed_assets'])
        
        if macro['fed_assets'].isnull().all(): macro['fed_assets'] = 7200.0 
        
        macro = macro.ffill().dropna()
        macro['net_liq_proxy'] = macro['fed_assets'] - macro['tga'] - macro['rrp']
        
        window = 20
        macro['liq_mean'] = macro['net_liq_proxy'].rolling(window).mean()
        macro['liq_std'] = macro['net_liq_proxy'].rolling(window).std()
        macro['liq_std'] = macro['liq_std'].replace(0, 1) 
        macro['cross_liq'] = (macro['net_liq_proxy'] - macro['liq_mean']) / macro['liq_std']
        
        def get_score(z):
            if pd.isna(z): return 0
            if z < -2: return -5
            if z < -1: return -3
            if z < -0.5: return -1
            if z > 2: return 5
            if z > 1: return 3
            if z > 0.5: return 1
            return 0
            
        macro['liqScore'] = macro['cross_liq'].apply(get_score)
        return macro
        
    except Exception as e:
        st.sidebar.error(f"FRED API Error: {e}")
        return None

# ==========================================
# 4. STOCK ANALYSIS
# ==========================================

def identify_patterns(df):
    df['body'] = abs(df['close'] - df['open'])
    df['range'] = df['high'] - df['low']
    df['upper_shadow'] = df['high'] - df[['close', 'open']].max(axis=1)
    df['lower_shadow'] = df[['close', 'open']].min(axis=1) - df['low']
    
    cond_hammer = (df['lower_shadow'] >= 2 * df['body']) & (df['upper_shadow'] <= 0.5 * df['body'])
    df['prev_close'] = df['close'].shift(1)
    df['prev_open'] = df['open'].shift(1)
    cond_engulf = (df['prev_close'] < df['prev_open']) & (df['close'] > df['open']) & \
                  (df['open'] < df['prev_close']) & (df['close'] > df['prev_open'])
    
    conditions = [cond_engulf, cond_hammer]
    choices = ['Bull Engulf', 'Hammer']
    sentiment = ['Bullish', 'Bullish']
    
    df['pattern'] = np.select(conditions, choices, default=None)
    df['sentiment'] = np.select(conditions, sentiment, default='None')
    return df

def fetch_200_weekly_ma(ticker):
    try:
        df = yf.download(ticker, period="5y", interval="1wk", progress=False)
        if df.empty: return None
        if isinstance(df.columns, pd.MultiIndex): df.columns = df.columns.get_level_values(0)
        wma = df['Close'].rolling(window=200).mean()
        return wma.iloc[-1]
    except:
        return None

def analyze_stock(ticker, macro_df, timeframe_code, interval_code):
    try:
        stock_data = yf.download(str(ticker), period=timeframe_code, interval=interval_code, auto_adjust=True, progress=False)
        if stock_data.empty: return None
        if isinstance(stock_data.columns, pd.MultiIndex): stock_data.columns = stock_data.columns.get_level_values(0)
        
        df = stock_data[['Open', 'High', 'Low', 'Close', 'Volume']].copy()
        df.columns = ['open', 'high', 'low', 'close', 'volume']
        if df.index.tz is not None: df.index = df.index.tz_localize(None)

        df['vp'] = ((df['high']+df['low']+df['close'])/3) * df['volume']
        window = 20
        df['vwap'] = df['vp'].rolling(window).sum() / df['volume'].rolling(window).sum()
        df['ema_20'] = df['close'].ewm(span=20, adjust=False).mean()
        df['ema_50'] = df['close'].ewm(span=50, adjust=False).mean()
        
        delta = df['close'].diff()
        gain = (delta.where(delta > 0, 0)).rolling(window=14).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=14).mean()
        rs = gain / loss
        df['rsi'] = 100 - (100 / (1 + rs))

        df['range'] = df['high'] - df['low']
        df['range'] = df['range'].replace(0, 0.01)
        df['buy_vol_est'] = df['volume'] * ((df['close'] - df['low']) / df['range'])
        df['sell_vol_est'] = df['volume'] - df['buy_vol_est']
        
        df = identify_patterns(df)

        if macro_df is not None and not macro_df.empty:
            macro_reindexed = macro_df.reindex(df.index, method='ffill')
            macro_reindexed = macro_reindexed.ffill()
            df = pd.concat([df, macro_reindexed], axis=1)
        else:
            df['liqScore'] = 0; df['net_liq_proxy'] = 0; df['cross_liq'] = 0

        return df.dropna(subset=['close'])
    except: return None

def get_company_name(ticker):
    try: return yf.Ticker(ticker).info.get('longName', ticker)
    except: return ticker

# ==========================================
# 5. EXTRAS
# ==========================================
def fetch_av_quote(symbol, api_key):
    if not api_key: return None
    try:
        r = requests.get(f"https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={symbol}&apikey={api_key}").json()
        return float(r.get("Global Quote", {})['05. price'])
    except: return None

def get_options_chain(ticker, current_price):
    try:
        tk = yf.Ticker(ticker)
        exps = tk.options
        if not exps: return None, None, None
        opt = tk.option_chain(exps[0])
        calls = opt.calls[(opt.calls['strike'] >= current_price*0.85) & (opt.calls['strike'] <= current_price*1.15)]
        puts = opt.puts[(opt.puts['strike'] >= current_price*0.85) & (opt.puts['strike'] <= current_price*1.15)]
        return calls, puts, exps
    except: return None, None, None

def search_web(query):
    if not SEARCH_AVAILABLE: return "⚠️ Install `duckduckgo-search` for AI Chat."
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(f"{query} finance news", region='us-en', timelimit='w', max_results=3))
        if not results: return "No recent news found."
        return "\n\n".join([f"**[{r['title']}]({r['href']})**\n{r['body']}" for r in results])
    except: return "Search Failed."

# ==========================================
# 6. MAIN EXECUTION
# ==========================================

if login_system():
    st.sidebar.title("🖥️ Market Terminal")
    st.sidebar.write(f"User: **{st.session_state.get('user', 'Admin')}**")

    with st.sidebar.expander("⚡ Controls", expanded=True):
        timeframe_map = {
            "1 Day (1m)": ("1d", "1m"), "5 Days (15m)": ("5d", "15m"), 
            "1 Month (Daily)": ("1mo", "1d"), "3 Months": ("3mo", "1d"), "YTD": ("ytd", "1d")
        }
        selected_tf = st.selectbox("Timeframe", list(timeframe_map.keys()))
        tf_code, interval_code = timeframe_map[selected_tf]
        years_back = st.slider("Macro Lookback", 0.5, 3.0, 1.0)

    with st.sidebar.expander("🔑 API Keys", expanded=True):
        fred_key = st.text_input("FRED Key", type="password", help="Leave blank to skip Macro")
        av_key = st.text_input("Alpha Vantage Key", type="password", help="Optional (Real-Time Price)")

    with st.sidebar.expander("🤖 Market AI", expanded=False):
        q = st.text_input("Ask Agent:")
        if st.button("Search") and q: st.markdown(search_web(q))

    if st.sidebar.button("🔒 Log Out", type="secondary"):
        st.session_state["password_correct"] = False
        st.rerun()

    st.sidebar.divider()

    col_title, col_search = st.columns([2, 1])
    with col_title: st.title("Pro Market Scanner")
    with col_search: ticker = st.text_input("Ticker", value="SPY", label_visibility="collapsed").upper()

    if st.button("🚀 RUN", type="primary", use_container_width=True):
        with st.spinner("Analyzing..."):
            comp_name = get_company_name(ticker)
            
            macro_df = None
            if fred_key:
                macro_df = fetch_macro_data_fred(fred_key, years_back)
            
            df = analyze_stock(ticker, macro_df, tf_code, interval_code)
            wma_200 = fetch_200_weekly_ma(ticker)
            
        if df is not None:
            live_price = fetch_av_quote(ticker, av_key) or df['close'].iloc[-1]
            last = df.iloc[-1]
            liq_val = int(last.get('liqScore', 0))
            net_liq_total = last.get('net_liq_proxy', 0) / 1000
            
            st.markdown(f"### {comp_name} ({ticker})")
            
            if fred_key:
                st.sidebar.markdown("### 🌊 Net Liquidity")
                st.sidebar.metric("Liq Score", f"{liq_val}", "Bullish" if liq_val > 0 else "Bearish", 
                                  delta_color="normal" if liq_val > 0 else "inverse")
                st.sidebar.progress((liq_val + 5) / 10)
                st.sidebar.caption(f"Net Liq: ${net_liq_total:.2f}T")
            else:
                st.sidebar.info("Enter FRED Key to see Liquidity Score")
                
            tab_macro, tab_tech, tab_opt = st.tabs(["🏦 Macro & Liquidity", "📈 Technical & Momentum", "⛓️ Options Desk"])
            
            with tab_macro:
                if fred_key and macro_df is not None:
                    last_macro = macro_df.iloc[-1]
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Liquidity Score", f"{liq_val}", "Bullish" if liq_val > 0 else "Bearish")
                    m2.metric("Net Liquidity", f"${net_liq_total:.2f}T")
                    m3.metric("Fed Assets", f"${last_macro['fed_assets']:.2f}B")
                    m4.metric("RRP Usage", f"${last_macro['rrp']:.2f}B")
                    
                    fig_macro = make_subplots(rows=2, cols=1, shared_xaxes=True, row_heights=[0.7, 0.3], vertical_spacing=0.05)
                    fig_macro.add_trace(go.Scatter(x=df.index, y=df['net_liq_proxy'], fill='tozeroy', line=dict(color='#00FFAA'), name="Net Liq"), row=1, col=1)
                    fig_macro.add_trace(go.Scatter(x=df.index, y=df['cross_liq'], line=dict(color='orange'), name="Z-Score"), row=2, col=1)
                    fig_macro.update_layout(height=600, template="plotly_dark", paper_bgcolor="#1E1E1E", plot_bgcolor="#1E1E1E")
                    st.plotly_chart(fig_macro, use_container_width=True)
                else:
                    st.warning("⚠️ FRED Data Unavailable. Enter API Key to unlock Macro Desk.")

            with tab_tech:
                vwap_trend = "BULLISH" if last['close'] > last['vwap'] else "BEARISH"
                ema_trend = "GOLDEN" if last['ema_20'] > last['ema_50'] else "DEATH"
                rsi_val = last['rsi']
                
                wma_text = "N/A"
                wma_delta = "N/A"
                if wma_200:
                    diff = ((live_price - wma_200) / wma_200) * 100
                    wma_text = f"{wma_200:.2f}"
                    wma_delta = f"{diff:+.1f}%"

                t1, t2, t3, t4, t5 = st.columns(5)
                t1.metric("Price", f"{live_price:,.2f}", delta=f"{(live_price - df['close'].iloc[-2]):.2f}")
                t2.metric("VWAP Trend", vwap_trend)
                t3.metric("EMA Trend", ema_trend)
                t4.metric("RSI (14)", f"{rsi_val:.0f}")
                t5.metric("200-Week MA", wma_text, wma_delta)
                
                fig_tech = make_subplots(rows=3, cols=1, shared_xaxes=True, vertical_spacing=0.02, 
                                         row_heights=[0.6, 0.2, 0.2], subplot_titles=("Price Action", "RSI", "Volume"))

                fig_tech.add_trace(go.Candlestick(x=df.index, open=df['open'], high=df['high'], low=df['low'], close=df['close'], name="Price"), row=1, col=1)
                fig_tech.add_trace(go.Scatter(x=df.index, y=df['vwap'], line=dict(color='#D300FF', width=1, dash='dot'), name="VWAP"), row=1, col=1)
                fig_tech.add_trace(go.Scatter(x=df.index, y=df['ema_20'], line=dict(color='#FFD700', width=1), name="EMA 20"), row=1, col=1)
                fig_tech.add_trace(go.Scatter(x=df.index, y=df['ema_50'], line=dict(color='#00FFFF', width=1), name="EMA 50"), row=1, col=1)
                
                if wma_200:
                    fig_tech.add_hline(y=wma_200, line_dash="longdash", line_color="white", annotation_text="200 WMA", row=1, col=1)
                
                if interval_code == "1d":
                    bull = df[df['sentiment'] == 'Bullish']
                    if not bull.empty: fig_tech.add_trace(go.Scatter(x=bull.index, y=bull['low']*0.99, mode='markers', marker=dict(symbol='triangle-up', size=12, color='#00FF00'), name="Bull"), row=1, col=1)

                fig_tech.add_trace(go.Scatter(x=df.index, y=df['rsi'], line=dict(color='#00CCFF', width=2), name="RSI"), row=2, col=1)
                fig_tech.add_hline(y=70, line_dash="dot", line_color="red", row=2, col=1)
                fig_tech.add_hline(y=30, line_dash="dot", line_color="green", row=2, col=1)

                fig_tech.add_trace(go.Bar(x=df.index, y=df['buy_vol_est'], marker_color='#00FF00', name="Buy"), row=3, col=1)
                fig_tech.add_trace(go.Bar(x=df.index, y=df['sell_vol_est'], marker_color='#FF0000', name="Sell"), row=3, col=1)
                
                if interval_code in ['1m', '5m', '15m', '30m', '1h']:
                     fig_tech.update_xaxes(rangebreaks=[dict(bounds=["sat", "mon"]), dict(bounds=[16, 9.5], pattern="hour")])

                fig_tech.update_layout(height=900, template="plotly_dark", paper_bgcolor="#1E1E1E", plot_bgcolor="#1E1E1E", hovermode="x unified", xaxis_rangeslider_visible=False)
                st.plotly_chart(fig_tech, use_container_width=True)

            with tab_opt:
                calls, puts, exps = get_options_chain(ticker, live_price)
                if calls is not None:
                    st.subheader(f"Expiry: {exps[0]}")
                    c1, c2, c3 = st.columns(3)
                    total_c = calls['openInterest'].sum(); total_p = puts['openInterest'].sum()
                    pc_ratio = (total_p / total_c) if total_c > 0 else 0
                    
                    c1.metric("Put/Call Ratio", f"{pc_ratio:.2f}", "Bearish" if pc_ratio > 1 else "Bullish")
                    c2.metric("Total Call OI", f"{total_c:,}")
                    c3.metric("Total Put OI", f"{total_p:,}")

                    fig_opt = go.Figure()
                    fig_opt.add_trace(go.Bar(x=calls['strike'], y=calls['openInterest'], name='Call OI', marker_color='#00FF00'))
                    fig_opt.add_trace(go.Bar(x=puts['strike'], y=puts['openInterest'], name='Put OI', marker_color='#FF0000'))
                    fig_opt.add_vline(x=live_price, line_dash="dash", line_color="white")
                    fig_opt.update_layout(title="Open Interest Walls", barmode='overlay', template="plotly_dark", paper_bgcolor="#1E1E1E", plot_bgcolor="#1E1E1E", height=500)
                    st.plotly_chart(fig_opt, use_container_width=True)
                    
                    col_c, col_p = st.columns(2)
                    with col_c:
                        st.markdown("#### Call Chain")
                        st.dataframe(calls[['strike', 'bid', 'ask', 'volume', 'openInterest']].style.format({"strike": "{:.1f}"}), height=400)
                    with col_p:
                        st.markdown("#### Put Chain")
                        st.dataframe(puts[['strike', 'bid', 'ask', 'volume', 'openInterest']].style.format({"strike": "{:.1f}"}), height=400)
                else: st.info("No options found.")
                
        else: st.error("Failed to load data.")