import json, os, time, hashlib, base64, glob
from datetime import datetime
import threading
import requests, json

# ANSI Escape Codes for coloring the output
# We'll use a combination of purple and white, with bold text for emphasis.
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    WHITE = "\033[97m"
    PURPLE = "\033[95m"
    # A simple utility for a solid white block in text charts
    BLOCK_WHITE = "\033[47m \033[0m" # white background
    BLOCK_PURPLE = "\033[45m \033[0m" # purple background

BLOCK_FOLDER = "./blockchain_files"
MEMPOOL_FILE = "pending_transactions.json"
HALVING_FILE = "halving.zthx"
HALVING_INTERVAL = 10
DIFFICULTY = 5

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
    print(f"\n{Color.BOLD}{Color.PURPLE}⚡ Creating Genesis Block...{Color.RESET}")
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
    print(f"{Color.WHITE}✔ Block {block['Index']} saved → {file_path}{Color.RESET}")

def get_reward(index):
    if not os.path.exists(HALVING_FILE):
        open(HALVING_FILE, "w").write("50")  # default reward
    base = float(open(HALVING_FILE).read().strip())
    halvings = index // HALVING_INTERVAL
    return base / (2 ** halvings)

def mine_block(block, difficulty):
    prefix = "0" * difficulty
    while True:
        h = block.calculate_hash()
        if h.startswith(prefix):
            block.hash = h
            return
        block.nonce += 1
        if block.nonce % 100000 == 0:
            print(f"{Color.PURPLE} Mining block : {block.index}, nonce : {block.nonce}, hash : {h}...{Color.RESET}")

PENDING_FILE = "pending_transactions.json"

def get_pending_transactions():
    if not os.path.exists(PENDING_FILE):
        return []
    try:
        return json.load(open(PENDING_FILE,"r"))
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
    json.dump([], open(PENDING_FILE,"w"))

def print_banner():
    """Prints a large, stylized banner for the CLI."""
    print(f"{Color.BOLD}{Color.PURPLE}")
    print(f"{Color.BOLD}{Color.WHITE}     - ZYTHERION MINING CLI -{Color.RESET}\n")

def print_chart(chain):
    """Prints a simple text-based chart showing block progress."""
    index = len(chain)
    blocks_to_halving = HALVING_INTERVAL - (index % HALVING_INTERVAL)
    progress_percent = int(((HALVING_INTERVAL - blocks_to_halving) / HALVING_INTERVAL) * 100)
    
    # Create the colored progress bar
    bar_length = 30
    filled_length = int(bar_length * progress_percent / 100)
    bar = f"{Color.PURPLE}{'█' * filled_length}{Color.WHITE}{'░' * (bar_length - filled_length)}{Color.RESET}"
    
    print(f"{Color.BOLD}{Color.WHITE}--- Blockchain Status ---{Color.RESET}")
    print(f"Block Count: {Color.PURPLE}{index}{Color.RESET}")
    print(f"Next Halving in: {Color.PURPLE}{blocks_to_halving}{Color.RESET} blocks")
    print(f"Progress: {bar} {progress_percent}%")
    print("-" * 25 + "\n")

# ---------------- Mining ----------------
def mine_single(address):
    chain = load_chain()
    prev = chain[-1]

    # 🔹 ambil pending transaction
    txs = get_pending_transactions()

    # 🔹 tambahkan coinbase reward (hadiah mining)
    reward = get_reward(len(chain))
    coinbase = Transaction("SYSTEM", address, reward).to_dict()
    txs.insert(0, coinbase)

    new_block = Block(len(chain), prev["Hash"], txs, address, reward)
    print(f"\n{Color.PURPLE} Mining block {new_block.index} solo for {address}...{Color.RESET}")
    mine_block(new_block, DIFFICULTY)

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
    # 🔹 kosongkan mempool
    clear_mempool()

    print(f"\n{Color.BOLD}{Color.WHITE} Solo block {new_block.index} mined! Reward {reward:.2f} ZYTH{Color.RESET}")
    print_chart(load_chain())


def mine_group(address, room_code):
    chain = load_chain()
    prev = chain[-1]

    room_file = f"room_data.json_{room_code}"
    if not os.path.exists(room_file):
        print(f"{Color.PURPLE} Room file not found{Color.RESET}")
        return

    room = json.load(open(room_file))
    members = room.get("members", [])
    if not members:
        print(f"{Color.PURPLE} No members in room{Color.RESET}")
        return

    reward_total = get_reward(len(chain))
    share = reward_total / len(members)

    # 🔹 ambil pending tx dulu
    txs = get_pending_transactions()

    # 🔹 bagi reward ke semua anggota
    for m in members:
        txs.append(Transaction("SYSTEM", m["address"], share).to_dict())

    new_block = Block(len(chain), prev["Hash"], txs, address, reward_total)
    print(f"\n{Color.PURPLE}⛏ Group mining block {new_block.index} for room {room_code}...{Color.RESET}")
    mine_block(new_block, DIFFICULTY)

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
    # 🔹 kosongkan mempool
    clear_mempool()

    print(f"\n{Color.BOLD}{Color.WHITE} Group block {new_block.index} mined! Total {reward_total:.2f} ZYTH → {share:.2f} each{Color.RESET}")
    print_chart(load_chain())


# ---------------- CLI ----------------
if __name__ == "__main__":
    import sys

    print_banner()
    
    if len(sys.argv) < 3:
        print(f"{Color.BOLD}{Color.PURPLE}Usage:{Color.RESET}")
        print(f"{Color.WHITE} python miner.py solo {Color.PURPLE}<your_address>{Color.RESET}")
        print(f"{Color.WHITE} python miner.py group {Color.PURPLE}<your_address> <room_code>{Color.RESET}")
        sys.exit(1)
        
    print_chart(load_chain())

    mode = sys.argv[1]
    if mode == "solo":
        address = sys.argv[2]
        while True:
            mine_single(address)
    elif mode == "group":
        if len(sys.argv) < 4:
            print(f"{Color.PURPLE}Need <your_address> and <room_code>{Color.RESET}")
            sys.exit(1)
        address = sys.argv[2]
        room_code = sys.argv[3]
        while True:
            mine_group(address, room_code)
