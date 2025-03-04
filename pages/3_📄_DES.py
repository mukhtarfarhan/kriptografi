import streamlit as st
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from io import BytesIO

# Fungsi untuk membuat counter manual (8 byte/64 bit)
def create_des_counter(iv):
    counter = int.from_bytes(iv, byteorder='big')
    while True:
        yield counter.to_bytes(8, byteorder='big')
        counter += 1

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

st.title("🕵️ DES Encryption/Decryption")

# Input data
input_type = st.radio("Pilih sumber data:", ("Teks", "File", "Ciphertext (Base64)"))
data = None
file_name = None
if input_type == "Teks":
    data = st.text_area("Masukkan teks:")
elif input_type == "File":
    uploaded_file = st.file_uploader("Unggah file:", type=None)
    if uploaded_file:
        data = uploaded_file.read()
        file_name = uploaded_file.name
elif input_type == "Ciphertext (Base64)":
    ciphertext_input = st.text_area("Masukkan ciphertext (Base64):")
    if ciphertext_input:
        try:
            data = base64.b64decode(ciphertext_input)
        except Exception as e:
            st.error(f"Gagal mendecode ciphertext: {e}")

key = st.text_input("Masukkan kunci (8 karakter):")

# Pilih mode
mode = st.radio("Pilih mode:", ("ECB", "CBC", "CTR"))

# Pilih operasi
operation = st.radio("Pilih operasi:", ("Enkripsi", "Dekripsi"))

# Pilih format file hasil (hanya untuk dekripsi)
if operation == "Dekripsi":
    file_format = st.selectbox(
        "Pilih format file hasil:",
        ("Teks", "PDF", "Gambar (PNG)", "Gambar (JPG)", "Word (DOCX)", "Excel (XLSX)", "Text (TXT)", "Binary (BIN)")
    )
else:
    file_format = None

if st.button("Proses"):
    if data and key and len(key) == 8:
        key = key.encode()
        if isinstance(data, str):
            data = data.encode()

        if mode == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
            if operation == "Enkripsi":
                result = cipher.encrypt(pad(data, DES.block_size))
            else:
                result = unpad(cipher.decrypt(data), DES.block_size)
        elif mode == "CBC":
            if operation == "Enkripsi":
                iv = get_random_bytes(8)
                cipher = DES.new(key, DES.MODE_CBC, iv)
                result = iv + cipher.encrypt(pad(data, DES.block_size))
            else:
                iv = data[:8]
                cipher = DES.new(key, DES.MODE_CBC, iv)
                result = unpad(cipher.decrypt(data[8:]), DES.block_size)
        elif mode == "CTR":
            iv = get_random_bytes(8)
            counter = create_des_counter(iv)
            cipher = DES.new(key, DES.MODE_ECB)
            
            if operation == "Enkripsi":
                encrypted_blocks = []
                for i in range(0, len(data), 8):
                    block = data[i:i + 8]
                    counter_block = next(counter)
                    encrypted_counter = cipher.encrypt(counter_block)
                    encrypted_block = bytes([b1 ^ b2 for b1, b2 in zip(block, encrypted_counter)])
                    encrypted_blocks.append(encrypted_block)
                result = iv + b"".join(encrypted_blocks)
            else:
                iv = data[:8]
                ciphertext = data[8:]
                counter = create_des_counter(iv)
                decrypted_blocks = []
                for i in range(0, len(ciphertext), 8):
                    block = ciphertext[i:i + 8]
                    counter_block = next(counter)
                    encrypted_counter = cipher.encrypt(counter_block)
                    decrypted_block = bytes([b1 ^ b2 for b1, b2 in zip(block, encrypted_counter)])
                    decrypted_blocks.append(decrypted_block)
                result = b"".join(decrypted_blocks)

        if operation == "Enkripsi":
            with st.spinner("Sedang mengenkripsi..."):
                ciphertext_base64 = base64.b64encode(result).decode()
                st.code(ciphertext_base64)
                st.download_button("Unduh Hasil", data=result, file_name="encrypted_result.bin", mime="application/octet-stream")
        else:
            with st.spinner("Sedang mendekripsi..."):
                try:
                    if file_format == "Teks":
                        st.code(result.decode('utf-8'))
                    else:
                        output_file_name = "decrypted_result" + {"PDF": ".pdf", "Gambar (PNG)": ".png", "Gambar (JPG)": ".jpg", "Word (DOCX)": ".docx", "Excel (XLSX)": ".xlsx", "Text (TXT)": ".txt", "Binary (BIN)": ".bin"}[file_format]
                        st.download_button("Unduh Hasil", data=result, file_name=output_file_name, mime="application/octet-stream")
                except Exception as e:
                    st.error(f"Gagal mendekripsi: {e}")
    else:
        st.error("Masukkan data dan kunci yang valid (8 karakter)!")
