import streamlit as st
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from io import BytesIO

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

st.title("🕵️ AES Encryption/Decryption")

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

key = st.text_input("Masukkan kunci (16/24/32 karakter):")

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
    if data and key and len(key) in [16, 24, 32]:
        key = key.encode()
        if isinstance(data, str):
            data = data.encode()

        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            if operation == "Enkripsi":
                result = cipher.encrypt(pad(data, AES.block_size))
            else:
                result = unpad(cipher.decrypt(data), AES.block_size)
        elif mode == "CBC":
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            if operation == "Enkripsi":
                result = iv + cipher.encrypt(pad(data, AES.block_size))
            else:
                result = unpad(cipher.decrypt(data[16:]), AES.block_size)
        elif mode == "CTR":
            nonce = get_random_bytes(15)  # Nonce 15 byte untuk AES
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            if operation == "Enkripsi":
                result = nonce + cipher.encrypt(data)  # Gabungkan nonce dengan ciphertext
            else:
                # Pisahkan nonce dari ciphertext
                nonce = data[:15]
                ciphertext = data[15:]
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)  # Inisialisasi ulang cipher dengan nonce yang sama
                result = cipher.decrypt(ciphertext)

        if operation == "Enkripsi":
            with st.spinner("Sedang mengenkripsi..."):
                st.write("Hasil Enkripsi (Base64):")
                ciphertext_base64 = base64.b64encode(result).decode()
                st.code(ciphertext_base64)

                # Tombol untuk copy ciphertext
                st.write("Salin ciphertext berikut untuk dekripsi:")
                st.code(ciphertext_base64)

                # Unduh hasil
                if file_name:
                    output_file_name = f"encrypted_{file_name.split('.')[0]}.bin"
                else:
                    output_file_name = "encrypted_result.bin"

                st.download_button(
                    label="Unduh Hasil",
                    data=result,
                    file_name=output_file_name,
                    mime="application/octet-stream"
                )
        else:
            with st.spinner("Sedang mendekripsi..."):
                try:
                    st.write("Hasil Dekripsi:")

                    # Jika hasil dekripsi berupa teks
                    if file_format == "Teks":
                        try:
                            st.code(result.decode('utf-8'))
                        except UnicodeDecodeError:
                            st.error("Hasil dekripsi bukan teks yang valid. Silakan pilih format file lain.")
                    else:
                        # Simpan hasil dekripsi sesuai format yang dipilih
                        output_file_name = f"decrypted_{file_name.split('.')[0]}" if file_name else "decrypted_result"
                        output_file_name += {
                            "PDF": ".pdf",
                            "Gambar (PNG)": ".png",
                            "Gambar (JPG)": ".jpg",
                            "Word (DOCX)": ".docx",
                            "Excel (XLSX)": ".xlsx",
                            "Text (TXT)": ".txt",
                            "Binary (BIN)": ".bin"
                        }[file_format]

                        st.download_button(
                            label="Unduh Hasil",
                            data=result,
                            file_name=output_file_name,
                            mime="application/octet-stream"
                        )
                except Exception as e:
                    st.error(f"Gagal mendekripsi: {e}")
    else:
        st.error("Masukkan data dan kunci yang valid (16/24/32 karakter)!")