from flask import Flask, render_template, request, redirect, session
import os, json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from datetime import datetime, timezone
import glob
import requests

app = Flask(__name__)
app.secret_key = "supersecret"
WALLET_DIR = "wallets"
USERS_FILE = "users.json"
PENDING_FILE = "pending_transactions.json"
os.makedirs(WALLET_DIR, exist_ok=True)

def broadcast_tx(tx):
    try:
        peers = json.load(open("p2p/peers.json"))
    except:
        peers = []
    for peer in peers:
        try:
            requests.post(f"http://{peer}/new_tx", json=tx, timeout=3)
        except:
            continue

# --- Helper untuk keypair ---
def generate_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

def save_private_key(priv, filename, password: str):
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password.encode())
    )
    with open(filename, "wb") as f:
        f.write(pem)

def sign_tx(priv, from_addr, to_addr, amount, ts):
    data = f"{from_addr}{to_addr}{amount:.6f}{ts}"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode("utf-8"))
    h = digest.finalize()
    der = priv.sign(h, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes((r.bit_length()+7)//8, "big") + s.to_bytes((s.bit_length()+7)//8, "big")
    return sig.hex()

def utc_rfc3339():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def get_balance(address):
    total = 0.0
    for file in glob.glob(os.path.join("blockchain_files", "*.zthx")):
        try:
            with open(file, "r") as f:
                block = json.load(f)
                for tx in block.get("Transactions", []):
                    if tx.get("from") == address:
                        total -= float(tx["amount"])
                    if tx.get("to") == address:
                        total += float(tx["amount"])
        except Exception as e:
            print(f"Skip file {file}: {e}")
            continue
    return round(total, 8)

def get_transactions_for_address(address):
    history = []
    for file in glob.glob(os.path.join("blockchain_files", "*.zthx")):
        try:
            with open(file, "r") as f:
                block = json.load(f)
                for tx in block.get("Transactions", []):
                    if tx.get("from") == address or tx.get("to") == address:
                        history.append(tx)
        except:
            continue
    # urutkan berdasarkan timestamp
    return sorted(history, key=lambda x: x["timestamp"])


@app.route("/")
def home():
    return redirect("/login")

# --- ROUTES ---
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]   # password login
        wallet_pass = request.form["wallet_password"]

        priv, pub = generate_keypair()
        address = "zyth-" + os.urandom(8).hex()

        os.makedirs(f"{WALLET_DIR}/{username}", exist_ok=True)
        save_private_key(priv, f"{WALLET_DIR}/{username}/private.pem", wallet_pass)

        with open(f"{WALLET_DIR}/{username}/public.pem", "wb") as f:
            f.write(pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        with open(f"{WALLET_DIR}/{username}/address.txt", "w") as f:
            f.write(address)

        try:
            users = json.load(open(USERS_FILE,"r"))
        except:
            users = {}
        users[username] = {"password": password, "wallet_password": wallet_pass, "address": address}
        json.dump(users, open(USERS_FILE,"w"), indent=2)

        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = json.load(open(USERS_FILE,"r"))
        if username in users and users[username]["password"] == password:
            session["user"] = {"username": username, "address": users[username]["address"]}
            return redirect("/dashboard")
        return "Login gagal", 401
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    user = session["user"]
    balance = get_balance(user["address"])
    return render_template("dashboard.html", user=user, balance=balance)

@app.route("/send", methods=["GET","POST"])
def send():
    if "user" not in session:
        return redirect("/login")
    if request.method == "POST":
        broadcast_tx(tx)
        to_addr = request.form["to"].strip()
        amount = float(request.form["amount"])
        ts = utc_rfc3339()

        users = json.load(open(USERS_FILE,"r"))
        username = session["user"]["username"]
        from_addr = users[username]["address"]
        wallet_pass = users[username]["wallet_password"]

        with open(f"{WALLET_DIR}/{username}/private.pem","rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=wallet_pass.encode())

        sig = sign_tx(priv, from_addr, to_addr, amount, ts)

        tx = {"from": from_addr,"to": to_addr,"amount": amount,"timestamp": ts,"signature": sig}

        try:
            data = json.load(open(PENDING_FILE,"r"))
        except:
            data = []
        data.append(tx)
        json.dump(data, open(PENDING_FILE,"w"), indent=2)
        return redirect("/dashboard")
    return render_template("send.html")

@app.route("/pending")
def pending():
    try:
        txs = json.load(open(PENDING_FILE,"r"))
    except:
        txs = []
    return render_template("pending.html", txs=txs)

@app.route("/history")
def history():
    if "user" not in session:
        return redirect("/login")
    user = session["user"]
    txs = get_transactions_for_address(user["address"])
    return render_template("history.html", txs=txs)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
