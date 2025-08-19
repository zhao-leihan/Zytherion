from flask import Flask, request, jsonify
import os, json, requests

app = Flask(__name__)

BLOCKCHAIN_DIR = "blockchain_files"
PEERS_FILE = "p2p/peers.json"

os.makedirs("p2p", exist_ok=True)
os.makedirs(BLOCKCHAIN_DIR, exist_ok=True)

def sync_chain():
    peers = get_peers()
    longest_chain = []
    for peer in peers:
        try:
            res = requests.get(f"http://{peer}/get_chain", timeout=5)
            if res.status_code == 200:
                chain = res.json()
                if len(chain) > len(longest_chain):
                    longest_chain = chain
        except:
            continue
    
    if longest_chain:
        print(f"🔄 Sync chain, got {len(longest_chain)} blocks from peers")
        for block in longest_chain:
            idx = block["Index"]
            filename = os.path.join(BLOCKCHAIN_DIR, f"block_{idx}.zthx")
            json.dump(block, open(filename, "w"), indent=2)

def get_peers():
    if not os.path.exists(PEERS_FILE):
        return []
    try:
        return json.load(open(PEERS_FILE))
    except:
        return []

def save_peers(peers):
    json.dump(peers, open(PEERS_FILE,"w"), indent=2)

@app.route("/new_block", methods=["POST"])
def new_block():
    block = request.json
    if not block: 
        return jsonify({"status":"error","msg":"empty"}), 400
    
    idx = block["Index"]
    filename = os.path.join(BLOCKCHAIN_DIR, f"block_{idx}.zthx")
    json.dump(block, open(filename,"w"), indent=2)
    print(f"Received new block {idx} from peer")
    return jsonify({"status":"ok"})

@app.route("/add_peer", methods=["POST"])
def add_peer():
    peer = request.json.get("peer")
    if not peer: return jsonify({"status":"error"}),400
    
    peers = get_peers()
    if peer not in peers:
        peers.append(peer)
        save_peers(peers)
        print(f"👥 Added new peer: {peer}")
    return jsonify({"status":"ok","peers":peers})

@app.route("/peers", methods=["GET"])
def peers():
    return jsonify(get_peers())

@app.route("/get_chain", methods=["GET"])
def get_chain():
    files = sorted(os.listdir(BLOCKCHAIN_DIR))
    chain = []
    for f in files:
        if f.endswith(".zthx"):
            try:
                chain.append(json.load(open(os.path.join(BLOCKCHAIN_DIR, f))))
            except:
                continue
    return jsonify(chain)

PENDING_FILE = "pending.json"

@app.route("/new_tx", methods=["POST"])
def new_tx():
    tx = request.json
    if not tx: return jsonify({"status":"error"}),400
    
    try:
        pending = json.load(open(PENDING_FILE))
    except:
        pending = []
    
    pending.append(tx)
    json.dump(pending, open(PENDING_FILE,"w"), indent=2)
    print(f"📩 Received TX {tx}")
    return jsonify({"status":"ok"})

if __name__ == "__main__":
    # jalankan dengan port unik tiap node
    sync_chain()
    app.run(host="0.0.0.0", port=5001)
