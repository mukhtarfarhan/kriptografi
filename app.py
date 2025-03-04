import streamlit as st

# Konfigurasi tema
st.set_page_config(
    page_title="Detective Crypto App",
    page_icon="🕵️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# CSS untuk tema detektif
st.markdown(
    """
    <style>
    .stApp {
        background-color: #1e1e1e;
        color: #ffffff;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        background-color: #2d2d2d;
        color: #ffffff;
    }
    .stButton>button {
        background-color: #ff4b4b;
        color: #ffffff;
        border-radius: 5px;
        border: none;
        padding: 10px 20px;
        font-size: 16px;
    }
    .stButton>button:hover {
        background-color: #ff1a1a;
    }
    .stRadio>div>label {
        color: #ffffff;
    }
    .stSelectbox>div>div>div {
        background-color: #2d2d2d;
        color: #ffffff;
    }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
        color: #ff4b4b;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header dengan tema detektif
st.markdown(
    """
    <div style="text-align: center;">
        <h1>🕵️ Detective Crypto App</h1>
        <p>Selamat datang di aplikasi enkripsi dan dekripsi dengan tema detektif!</p>
        <p>Pilih metode kriptografi di sidebar untuk memulai.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Navigasi ke halaman yang sesuai
st.sidebar.title("Menu")
st.sidebar.write("Pilih metode kriptografi:")
page = st.sidebar.radio(
    "Pilih Halaman",
    ("Simple XOR", "RC4", "DES", "AES")
)

if page == "Simple XOR":
    st.switch_page("pages/1_📄_Simple_XOR.py")
elif page == "RC4":
    st.switch_page("pages/2_📄_RC4.py")
elif page == "DES":
    st.switch_page("pages/3_📄_DES.py")
elif page == "AES":
    st.switch_page("pages/4_📄_AES.py")