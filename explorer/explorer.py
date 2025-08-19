from flask import Flask, render_template, request
import os, json, glob

app = Flask(__name__)
BLOCKCHAIN_DIR = "blockchain_files"

def load_chain():
    files = sorted(glob.glob(os.path.join(BLOCKCHAIN_DIR, "*.zthx")))
    chain = []
    for f in files:
        try:
            block = json.load(open(f))
            chain.append(block)
        except:
            continue
    return chain

@app.route("/")
def index():
    chain = load_chain()
    # Pilih blok pertama dari rantai sebagai blok yang ditampilkan secara default
    default_block = chain[0] if chain else None
    return render_template("explorer.html", chain=chain, block=default_block)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7001)
