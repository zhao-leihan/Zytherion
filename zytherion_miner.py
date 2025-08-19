# zytherion_miner_gui.py

import json
import os
import time
import hashlib
import base64
import glob
import threading
import requests
from datetime import datetime
from io import BytesIO

import customtkinter as ctk
from PIL import Image, ImageTk
from tkinter import messagebox, scrolledtext

# ---------------- Block & Tx structure ----------------
class Transaction:
    def __init__(self, from_addr, to_addr, amount, timestamp=None):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.amount = amount
        self.timestamp = timestamp or datetime.utcnow().isoformat()

    def to_dict(self):
        return {
            "from": self.from_addr,
            "to": self.to_addr,
            "amount": self.amount,
            "timestamp": self.timestamp
        }

class Block:
    def __init__(self, index, prev_hash, transactions, miner, reward):
        self.index = index
        self.timestamp = datetime.utcnow().isoformat()
        self.transactions = transactions
        self.previous_hash = prev_hash
        self.nonce = 0
        self.miner = miner
        self.reward = reward
        self.hash = ""

    def calculate_hash(self):
        record = f"{self.index}{self.timestamp}{self.transactions}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(record.encode()).hexdigest()

# ---------------- Blockchain Utils ----------------
BLOCK_FOLDER = "./blockchain_files"
MEMPOOL_FILE = "pending_transactions.json"
HALVING_FILE = "halving.zthx"
HALVING_INTERVAL = 10
DIFFICULTY = 5

def load_chain():
    if not os.path.exists(BLOCK_FOLDER):
        os.makedirs(BLOCK_FOLDER)
        return [create_genesis_block()]
    files = glob.glob(os.path.join(BLOCK_FOLDER, "*.zthx"))
    if not files:
        return [create_genesis_block()]
    blocks = []
    for f in files:
        with open(f, "r") as fp:
            try:
                blk = json.load(fp)
                blocks.append(blk)
            except:
                continue
    blocks.sort(key=lambda b: b["Index"])
    return blocks

def create_genesis_block():
    genesis = {
        "Index": 0,
        "Timestamp": datetime.utcnow().isoformat(),
        "Transactions": [{"from": "SYSTEM", "to": "GENESIS", "amount": 0, "timestamp": datetime.utcnow().isoformat()}],
        "PreviousHash": "0",
        "Nonce": 0,
        "Miner": "GENESIS",
        "Reward": 0,
        "Hash": ""
    }
    genesis["Hash"] = hashlib.sha256(str(genesis).encode()).hexdigest()
    save_block(genesis)
    return genesis

def save_block(block):
    raw = f"block_{block['Index']}"
    encoded = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()).decode()
    file_path = os.path.join(BLOCK_FOLDER, encoded[:20] + ".zthx")
    with open(file_path, "w") as f:
        json.dump(block, f, indent=2)

def get_reward(index):
    if not os.path.exists(HALVING_FILE):
        open(HALVING_FILE, "w").write("50")
    base = float(open(HALVING_FILE).read().strip())
    halvings = index // HALVING_INTERVAL
    return base / (2 ** halvings)

def mine_block(block, difficulty, log_callback, stop_event):
    prefix = "0" * difficulty
    start_time = time.time()
    last_log_time = start_time
    
    while not stop_event.is_set():
        h = block.calculate_hash()
        if h.startswith(prefix):
            block.hash = h
            return True
        block.nonce += 1
        
        current_time = time.time()
        if current_time - last_log_time > 1: # Log every second
            log_callback(f"⛏ Mining... Nonce: {block.nonce}, Hash: {h[:12]}...")
            last_log_time = current_time
            
    return False

PENDING_FILE = "pending_transactions.json"

def get_pending_transactions():
    if not os.path.exists(PENDING_FILE):
        return []
    try:
        return json.load(open(PENDING_FILE, "r"))
    except:
        return []

def broadcast_block(block_data):
    try:
        peers = json.load(open("p2p/peers.json"))
    except:
        peers = []

    for peer in peers:
        try:
            res = requests.post(f"http://{peer}/new_block", json=block_data, timeout=3)
            print(f"Broadcast to {peer} → {res.status_code}")
        except Exception as e:
            print(f"Failed to reach {peer}: {e}")

def clear_mempool():
    json.dump([], open(PENDING_FILE, "w"))

# ---------------- GUI Application ----------------
class ZytherionMinerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Setup window
        self.title("Zytherion Mining Suite")
        self.geometry("900x700")
        self.resizable(True, True)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        # Custom purple color
        self.PURPLE = "#B794F6"
        self.LIGHT_PURPLE = "#D6BCFA"
        self.WHITE = "#FFFFFF"
        self.DARK_BG = "#1A1A2E"
        self.LIGHT_BG = "#F7F7FF"
        self.miners = {}
        self.stop_mining_event = threading.Event()

        self.chain = load_chain()
        self.create_widgets()
        self.update_status()
        self.auto_update_status()

    def create_widgets(self):
        # === Header Frame ===
        header_frame = ctk.CTkFrame(self, height=80, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=10)

        try:
            response = requests.get("https://github.com/zhao-leihan/Logo-Zytherion-coin/blob/main/Zytherion.png?raw=true", timeout=5)
            image_data = Image.open(BytesIO(response.content))
            image_data = image_data.resize((60, 60))
            self.logo_image = ImageTk.PhotoImage(image_data)
            logo_label = ctk.CTkLabel(header_frame, image=self.logo_image, text="")
            logo_label.pack(side="left", padx=10)
        except Exception as e:
            print("Failed to load logo:", e)
            logo_label = ctk.CTkLabel(header_frame, text="⚡", font=("Arial", 40))
            logo_label.pack(side="left", padx=10)

        title_label = ctk.CTkLabel(
            header_frame,
            text="ZYTHERION MINING SUITE",
            font=("Arial", 24, "bold"),
            text_color=self.PURPLE
        )
        title_label.pack(side="left", padx=10)

        # Theme toggle
        self.theme_switch = ctk.CTkSwitch(header_frame, text="🌙 / ☀️", command=self.toggle_theme)
        self.theme_switch.pack(side="right", padx=20)

        # === Tabs ===
        self.tabview = ctk.CTkTabview(self, width=850, height=500)
        self.tabview.pack(pady=10, padx=20, fill="both", expand=True)

        self.tab_solo = self.tabview.add("Solo Mining")
        self.tab_group = self.tabview.add("Group Mining")
        self.tab_status = self.tabview.add("Status")

        self.create_solo_tab()
        self.create_group_tab()
        self.create_status_tab()

        # === Log Console (Bigger) ===
        log_frame = ctk.CTkFrame(self, height=300, width=200)
        log_frame.pack(fill="x", padx=20, pady=10)

        log_label = ctk.CTkLabel(log_frame, text="⛏ Mining Log", font=("Consolas", 14, "bold"), text_color=self.PURPLE)
        log_label.pack(anchor="w", padx=10)

        self.log_text = ctk.CTkTextbox(log_frame, height=100, font=("Consolas", 11))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_text.configure(state="disabled")

    def create_solo_tab(self):
        # Use a main frame for better structure
        main_frame = ctk.CTkFrame(self.tab_solo, fg_color="transparent")
        main_frame.pack(expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="Enter your wallet address to start solo mining", font=("Arial", 16, "bold")).pack(pady=(10, 5))
        ctk.CTkLabel(main_frame, text="Earn a full block reward for every block you find.", font=("Arial", 12)).pack(pady=(0, 20))
        
        # Frame for address input
        addr_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        addr_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(addr_frame, text="Wallet Address:", font=("Arial", 12)).pack(side="left", padx=(0, 10))
        self.solo_addr = ctk.CTkEntry(addr_frame, width=400, placeholder_text="e.g. ZYTH_xxxxxxxxxxxxx")
        self.solo_addr.pack(side="left", fill="x", expand=True)
        
        # Frame for buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        self.btn_solo = ctk.CTkButton(
            button_frame,
            text="🔷 Start Solo Mining",
            command=self.start_solo,
            fg_color=self.PURPLE,
            hover_color="#9F7AEA",
            width=200
        )
        self.btn_solo.pack(side="left", padx=10)

        self.btn_solo_stop = ctk.CTkButton(
            button_frame,
            text="🛑 Stop Solo Mining",
            command=self.stop_mining,
            fg_color="red",
            hover_color="#CC0000",
            width=200
        )
        self.btn_solo_stop.pack(side="left", padx=10)
        self.btn_solo_stop.configure(state="disabled")


    def create_group_tab(self):
        main_frame = ctk.CTkFrame(self.tab_group, fg_color="transparent")
        main_frame.pack(expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="Join a group to mine together", font=("Arial", 16, "bold")).pack(pady=(10, 5))
        ctk.CTkLabel(main_frame, text="Rewards are shared equally among all members.", font=("Arial", 12)).pack(pady=(0, 20))

        # Frame for address input
        addr_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        addr_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(addr_frame, text="Your Wallet Address:", font=("Arial", 12)).pack(side="left", padx=(0, 10))
        self.group_addr = ctk.CTkEntry(addr_frame, width=400, placeholder_text="Your Wallet Address")
        self.group_addr.pack(side="left", fill="x", expand=True)

        # Frame for room code input
        code_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        code_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(code_frame, text="Room Code:", font=("Arial", 12)).pack(side="left", padx=(0, 10))
        self.group_code = ctk.CTkEntry(code_frame, width=400, placeholder_text="e.g. ABC123")
        self.group_code.pack(side="left", fill="x", expand=True)

        # Frame for buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        self.btn_group = ctk.CTkButton(
            button_frame,
            text="🟣 Start Group Mining",
            command=self.start_group,
            fg_color=self.PURPLE,
            hover_color="#9F7AEA",
            width=200
        )
        self.btn_group.pack(side="left", padx=10)

        self.btn_group_stop = ctk.CTkButton(
            button_frame,
            text="🛑 Stop Group Mining",
            command=self.stop_mining,
            fg_color="red",
            hover_color="#CC0000",
            width=200
        )
        self.btn_group_stop.pack(side="left", padx=10)
        self.btn_group_stop.configure(state="disabled")

    def create_status_tab(self):
        self.status_text = scrolledtext.ScrolledText(
            self.tab_status,
            bg="#2B2B2B" if ctk.get_appearance_mode() == "Dark" else "white",
            fg="white" if ctk.get_appearance_mode() == "Dark" else "black",
            font=("Courier", 10)
        )
        self.status_text.pack(fill="both", expand=True, padx=10, pady=10)

    def toggle_theme(self):
        current_mode = ctk.get_appearance_mode()
        if current_mode == "Dark":
            ctk.set_appearance_mode("light")
            self.status_text.config(bg="white", fg="black")
        else:
            ctk.set_appearance_mode("dark")
            self.status_text.config(bg="#2B2B2B", fg="white")
        self.update_status()

    def log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def auto_update_status(self):
        self.update_status()
        self.after(30000, self.auto_update_status) # Update every 30 seconds

    def update_status(self):
        try:
            chain = load_chain()
            self.status_text.delete(1.0, "end")
            self.status_text.insert("end", "🔐 ZYTHERION BLOCKCHAIN STATUS\n")
            self.status_text.insert("end", "─" * 50 + "\n")
            self.status_text.insert("end", f"📍 Total Blocks: {len(chain)}\n")
            self.status_text.insert("end", f"⛏️  Last Miner: {chain[-1]['Miner']}\n")
            self.status_text.insert("end", f"💰 Current Reward: {get_reward(len(chain)):.2f} ZYTH\n")
            self.status_text.insert("end", f"📅 Last Block Time: {chain[-1]['Timestamp'][:19]}\n")
            self.status_text.insert("end", f"📊 Difficulty: {DIFFICULTY}\n")
            blocks_to_halve = HALVING_INTERVAL - (len(chain) % HALVING_INTERVAL)
            self.status_text.insert("end", f"🔄 Next Halving: {blocks_to_halve} blocks\n\n")

            self.status_text.insert("end", "📜 RECENT BLOCKS:\n")
            for block in chain[-10:]:  # Show last 10
                self.status_text.insert("end", f"  ▶ Block {block['Index']} | {block['Miner']} | {block['Reward']:.2f} ZYTH\n")
        except Exception as e:
            self.log(f"Failed to update status: {e}")

    def start_solo(self):
        addr = self.solo_addr.get().strip()
        if not addr:
            messagebox.showwarning("Input Error", "⚠️ Please enter your wallet address.")
            return
        
        self.stop_mining_event.clear()
        self.btn_solo.configure(state="disabled")
        self.btn_solo_stop.configure(state="normal")
        self.log(f"🚀 Starting solo mining for {addr}...")
        
        threading.Thread(target=self.mine_single_loop, args=(addr,), daemon=True).start()

    def start_group(self):
        addr = self.group_addr.get().strip()
        code = self.group_code.get().strip()
        if not addr or not code:
            messagebox.showwarning("Input Error", "⚠️ Please fill both address and room code.")
            return
        
        self.stop_mining_event.clear()
        self.btn_group.configure(state="disabled")
        self.btn_group_stop.configure(state="normal")
        self.log(f"👥 Starting group mining for room {code}...")
        
        threading.Thread(target=self.mine_group_loop, args=(addr, code), daemon=True).start()

    def stop_mining(self):
        self.stop_mining_event.set()
        self.btn_solo.configure(state="normal")
        self.btn_solo_stop.configure(state="disabled")
        self.btn_group.configure(state="normal")
        self.btn_group_stop.configure(state="disabled")
        self.log("🛑 Mining process stopped by user.")

    def mine_single_loop(self, address):
        while not self.stop_mining_event.is_set():
            try:
                chain = load_chain()
                prev = chain[-1]

                txs = get_pending_transactions()
                reward = get_reward(len(chain))
                coinbase = Transaction("SYSTEM", address, reward).to_dict()
                txs.insert(0, coinbase)

                new_block = Block(len(chain), prev["Hash"], txs, address, reward)
                self.log(f"⛏ Mining block #{new_block.index} for {address}...")

                success = mine_block(new_block, DIFFICULTY, self.log, self.stop_mining_event)
                
                if success:
                    block_data = {
                        "Index": new_block.index,
                        "Timestamp": new_block.timestamp,
                        "Transactions": new_block.transactions,
                        "PreviousHash": prev["Hash"],
                        "Nonce": new_block.nonce,
                        "Miner": address,
                        "Reward": reward,
                        "Hash": new_block.hash
                    }
                    save_block(block_data)
                    broadcast_block(block_data)
                    clear_mempool()
                    self.log(f"✅ Block {new_block.index} SUCCESSFULLY MINED! Reward: {reward:.2f} ZYTH")
                    self.update_status()
                    time.sleep(1) # Small delay before starting next block
                elif self.stop_mining_event.is_set():
                    break
            except Exception as e:
                self.log(f"❌ Mining failed: {str(e)}")
                time.sleep(5) # Wait before retrying

    def mine_group_loop(self, address, room_code):
        while not self.stop_mining_event.is_set():
            try:
                chain = load_chain()
                prev = chain[-1]
                room_file = f"room_data.json_{room_code}"
                if not os.path.exists(room_file):
                    self.log(f"❌ Room file {room_file} not found.")
                    self.stop_mining()
                    return

                room = json.load(open(room_file))
                members = room.get("members", [])
                if not members:
                    self.log("❌ No members in room. Group mining stopped.")
                    self.stop_mining()
                    return

                reward_total = get_reward(len(chain))
                share = reward_total / len(members)

                txs = get_pending_transactions()
                for m in members:
                    txs.append(Transaction("SYSTEM", m["address"], share).to_dict())

                new_block = Block(len(chain), prev["Hash"], txs, address, reward_total)
                self.log(f"👥 Mining group block #{new_block.index} for room {room_code}...")

                success = mine_block(new_block, DIFFICULTY, self.log, self.stop_mining_event)
                
                if success:
                    block_data = {
                        "Index": new_block.index,
                        "Timestamp": new_block.timestamp,
                        "Transactions": new_block.transactions,
                        "PreviousHash": prev["Hash"],
                        "Nonce": new_block.nonce,
                        "Miner": address,
                        "Reward": reward_total,
                        "Hash": new_block.hash
                    }
                    save_block(block_data)
                    broadcast_block(block_data)
                    clear_mempool()
                    self.log(f"✅ Group block {new_block.index} mined! {share:.2f} ZYTH each")
                    self.update_status()
                    time.sleep(1)
                elif self.stop_mining_event.is_set():
                    break
            except Exception as e:
                self.log(f"❌ Group mining failed: {str(e)}")
                time.sleep(5)

if __name__ == "__main__":
    app = ZytherionMinerApp()
    app.mainloop()