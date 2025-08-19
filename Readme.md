# Zytherion v1.0

Zytherion is a simple blockchain project (version 1.0) still under development.  
Its main purpose is to allow mining Zyth Coins using Flask and a simple peer-to-peer (P2P) system.

---

## Requirements

Make sure Python is installed, then install the following dependencies:

```bash
pip install flask requests cryptography
```

Or use `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## How to Run

### 1. Add Your Peers
Before running the node, register other peers (nodes) in the network.  
Open P2P/peer.json and add your peers like this:

```python
peers = [
    "http://127.0.0.1:5000",
    "http://127.0.0.1:5001",
    "http://127.0.0.1:5002"
]
```

🔗 Make sure all peers can connect to each other (localhost for testing or local network IPs).

---

### 2. Run Flask Server
Open a terminal and run the main server:

```bash
python app.py
```

The server will be active at `http://127.0.0.1:5000` (port may vary depending on configuration).

---

### 3. Run Miner
Open a new terminal (or tab) and run the miner script:

```bash
python miner.py
```

The miner will start processing transactions and mining new blocks to the blockchain.

---

## 🧱 Current Features

- Simple blockchain with hashing and proof-of-work  
- Basic peer-to-peer network  
- Coin mining (reward system)  
- Block validation using cryptography  
- Broadcast transactions & blocks to all peers  

---

## Development Notes

- Use `app.py` as the main node (Flask server)  
- Use `miner.py` to start the mining process  
- All peers must have synchronized peer lists for the network to work  

---

## Roadmap

- Wallet with public/private keys  
- Simple GUI  
- Node auto-discovery  
- Digital transactions with signatures  
- Database integration  

---

## Contribution

You can help develop this project! Open issues, pull requests, or discuss ideas in this repository.

---
