import streamlit as st
import secrets
import os
import time
import hashlib
import base64
from functools import reduce

# ---------- helpers ----------
def _xor_bytes(*chunks: bytes) -> bytes:
    """XOR all byte chunks together (assumes equal length)."""
    return bytes(reduce(lambda a, b: a ^ b, pair) for pair in zip(*chunks))

def extra_entropy_blob(size: int = 32, user_msg="") -> bytes:
    """Blend multiple entropy sources into one byte blob."""
    tstamp   = int(time.time_ns()).to_bytes(16, "big")          # 16 bytes

    blobs = (
        secrets.token_bytes(size),                              # CSPRNG
        os.urandom(size),                                       # OS entropy
        hashlib.sha256(tstamp).digest()[:size],                 # time-based
        hashlib.sha256(user_msg.encode()).digest()[:size],      # user input
    )
    return _xor_bytes(*blobs)

# ---------- main credentials ----------
def userpass(fname: str, lname: str, user_msg: str):
    username = f"{fname}.{lname}_{secrets.randbelow(1000):03d}"
    raw_pwd  = extra_entropy_blob(user_msg=user_msg)            # 32 raw bytes
    password = base64.urlsafe_b64encode(raw_pwd).decode()       # printable
    return username, password

# ---------- Streamlit App ----------
st.title("Entropy-Boosted Password Generator")

st.markdown("Enter your first and last name to generate a username and password.")

fname = st.text_input("First Name")
lname = st.text_input("Last Name")
user_msg = st.text_input("Type some random gibberish for extra entropy:")

if st.button("Generate Credentials"):
    if fname and lname:
        username, password = userpass(fname, lname, user_msg)
        st.success(f"Username: {username}")
        st.success(f"Password: {password}")
    else:
        st.warning("Please enter both first and last names.")
