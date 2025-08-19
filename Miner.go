package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Block struct {
	Index        int
	Timestamp    string
	Transactions []Transaction
	PreviousHash string
	Hash         string
	Nonce        int
	Miner        string
	Reward       float64
}

type Transaction struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	Amount    float64 `json:"amount"`
	Timestamp string  `json:"timestamp"`
	Signature string  `json:"signature"`
	PubKey    string  `json:"pubKey"` // public key pengirim
}

type Blockchain struct {
	Chain      []Block
	Difficulty int
	sync.Mutex
}

type Member struct {
	Username string  `json:"username"`
	Address  string  `json:"address"`
	Balance  float64 `json:"balance"`
	Joined   string  `json:"joined"`
}

var blockchain = &Blockchain{
	Difficulty: 5,
}

const blockFolder = "./blockchain_files"
const halvingFile = "halving.zthx"
const halvingInterval = 10

func generateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return priv, &priv.PublicKey
}

func savePrivateKey(priv *ecdsa.PrivateKey, filename string) {
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
	pemData := pem.EncodeToMemory(pemBlock)
	_ = os.WriteFile(filename, pemData, 0600)
}

func savePublicKey(pub *ecdsa.PublicKey, filename string) {
	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pemData := pem.EncodeToMemory(pemBlock)
	_ = os.WriteFile(filename, pemData, 0644)
}

func publicKeyToAddress(pub *ecdsa.PublicKey) string {
	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	hash := sha256.Sum256(pubBytes)
	return "zyth-" + hex.EncodeToString(hash[:8])
}

func signTransaction(priv *ecdsa.PrivateKey, tx Transaction) string {
	data := tx.From + tx.To + fmt.Sprintf("%f", tx.Amount) + tx.Timestamp
	hash := sha256.Sum256([]byte(data))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
	sig := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(sig)
}

func verifyTransaction(tx Transaction) bool {
	// Coinbase transaction tidak perlu verifikasi
	if tx.From == "SYSTEM" {
		return true
	}

	data := tx.From + tx.To + fmt.Sprintf("%f", tx.Amount) + tx.Timestamp
	hash := sha256.Sum256([]byte(data))

	sigBytes, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
	s := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])

	block, _ := pem.Decode([]byte(tx.PubKey))
	if block == nil {
		return false
	}
	pubKeyIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	pubKey := pubKeyIfc.(*ecdsa.PublicKey)

	return ecdsa.Verify(pubKey, hash[:], r, s)
}

func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + fmt.Sprintf("%v", block.Transactions) + block.PreviousHash + strconv.Itoa(block.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mineBlock(block *Block, difficulty int) {
	prefix := strings.Repeat("0", difficulty)
	for {
		hash := calculateHash(*block)
		if strings.HasPrefix(hash, prefix) {
			block.Hash = hash
			break
		}
		block.Nonce++
		if block.Nonce%100000 == 0 {
			fmt.Printf("Mining... index: %d, nonce: %d, hash: %s\n", block.Index, block.Nonce, hash)
		}
	}
}

func createTransaction(from, to string, amount float64) Transaction {
	return Transaction{
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

const mempoolFile = "pending_transactions.json"

func addTransaction(tx Transaction) {
	var txs []Transaction
	data, err := ioutil.ReadFile(mempoolFile)
	if err == nil {
		_ = json.Unmarshal(data, &txs)
	}
	txs = append(txs, tx)
	jsonData, _ := json.MarshalIndent(txs, "", "  ")
	_ = ioutil.WriteFile(mempoolFile, jsonData, 0644)
}

func getPendingTransactions() []Transaction {
	var txs []Transaction
	data, err := ioutil.ReadFile(mempoolFile)
	if err == nil {
		_ = json.Unmarshal(data, &txs)
	}
	return txs
}

func clearMempool() {
	_ = ioutil.WriteFile(mempoolFile, []byte("[]"), 0644)
}

func getBalance(address string) float64 {
	balance := 0.0
	for _, block := range blockchain.Chain {
		for _, tx := range block.Transactions {
			if tx.From == address {
				balance -= tx.Amount
			}
			if tx.To == address {
				balance += tx.Amount
			}
		}
	}
	return balance
}

func validateTransaction(tx Transaction) bool {
	if !verifyTransaction(tx) {
		fmt.Println("❌ Invalid signature")
		return false
	}
	if tx.From != "SYSTEM" {
		balance := getBalance(tx.From)
		if balance < tx.Amount {
			fmt.Printf("❌ Insufficient balance for %s\n", tx.From)
			return false
		}
	}
	return true
}

func saveBlockAsZythFile(block Block) {
	os.MkdirAll(blockFolder, os.ModePerm)
	raw := fmt.Sprintf("block_%d", block.Index)
	hash := sha256.Sum256([]byte(raw))
	encoded := base64.URLEncoding.EncodeToString(hash[:])
	filename := fmt.Sprintf("%s/%s.zyth", blockFolder, encoded[:20])

	// Save binary (.zyth)
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(block)
	if err == nil {
		_ = ioutil.WriteFile(filename, buf.Bytes(), 0644)
	}

	// Save JSON for web access
	jsonPath := fmt.Sprintf("%s/%s.json", blockFolder, encoded[:20])
	jsonData, _ := json.MarshalIndent(block, "", "  ")
	_ = ioutil.WriteFile(jsonPath, jsonData, 0644)

	fmt.Printf("✔ Block %d saved to %s\n", block.Index, filename)
}

func createGenesisBlock() Block {
	fmt.Println("No chain found. Creating genesis block...")
	genesis := Block{
		Index:     0,
		Timestamp: time.Now().Format(time.RFC3339),
		Transactions: []Transaction{
			{From: "SYSTEM", To: "GENESIS", Amount: 0, Timestamp: time.Now().Format(time.RFC3339)},
		},
		PreviousHash: "0",
		Nonce:        0,
	}
	mineBlock(&genesis, blockchain.Difficulty)
	genesis.Hash = calculateHash(genesis)
	saveBlockAsZythFile(genesis)
	return genesis
}

func loadAllBlocks() {
	files, err := ioutil.ReadDir(blockFolder)
	if err != nil {
		blockchain.Chain = append(blockchain.Chain, createGenesisBlock())
		return
	}

	var loaded []Block
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".zyth") {
			data, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", blockFolder, f.Name()))
			if err != nil {
				continue
			}
			var blk Block
			err = gob.NewDecoder(bytes.NewReader(data)).Decode(&blk)
			if err != nil {
				continue
			}
			loaded = append(loaded, blk)
		}
	}

	if len(loaded) == 0 {
		blockchain.Chain = append(blockchain.Chain, createGenesisBlock())
		return
	}

	sort.Slice(loaded, func(i, j int) bool {
		return loaded[i].Index < loaded[j].Index
	})
	blockchain.Chain = loaded
	fmt.Printf("Loaded %d blocks from file.\n", len(loaded))
}

func getReward(index int) float64 {
	raw, err := ioutil.ReadFile(halvingFile)
	if err != nil {
		log.Fatalf("Cannot read halving file: %v", err)
	}
	base, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
	if err != nil {
		log.Fatalf("Invalid halving base: %v", err)
	}
	halvings := index / halvingInterval
	reward := base / math.Pow(2, float64(halvings))
	return reward
}

func mineSingle(address string) {
	loadAllBlocks()
	prev := blockchain.Chain[len(blockchain.Chain)-1]

	// Ambil transaksi pending
	pending := getPendingTransactions()

	// Filter transaksi valid
	var validTxs []Transaction
	for _, tx := range pending {
		if validateTransaction(tx) {
			validTxs = append(validTxs, tx)
		} else {
			fmt.Printf("❌ Invalid transaction: %+v\n", tx)
		}
	}

	// Tambahkan coinbase transaction (reward ke miner)
	reward := getReward(len(blockchain.Chain))
	coinbase := createTransaction("SYSTEM", address, reward)

	// Gabungkan coinbase + transaksi valid
	txs := append([]Transaction{coinbase}, validTxs...)

	newBlock := Block{
		Index:        len(blockchain.Chain),
		Timestamp:    time.Now().Format(time.RFC3339),
		Transactions: txs,
		PreviousHash: prev.Hash,
		Nonce:        0,
		Miner:        address,
		Reward:       reward,
	}

	fmt.Printf("Mining block %d by %s...\n", newBlock.Index, address)
	mineBlock(&newBlock, blockchain.Difficulty)
	newBlock.Hash = calculateHash(newBlock)

	blockchain.Lock()
	blockchain.Chain = append(blockchain.Chain, newBlock)
	blockchain.Unlock()

	saveBlockAsZythFile(newBlock)

	// Kosongkan mempool
	clearMempool()

	fmt.Printf("✅ Block %d mined! Hash: %s | Reward: %.8f ZYTH\n",
		newBlock.Index, newBlock.Hash, reward)
}

func mineGroup(address, roomCode string) {
	loadAllBlocks()
	prev := blockchain.Chain[len(blockchain.Chain)-1]

	// Baca member dari file room
	roomFile := fmt.Sprintf("room_data.json_%s", roomCode)
	roomBytes, err := ioutil.ReadFile(roomFile)
	if err != nil {
		log.Fatalf("❌ Failed to read room file: %v", err)
	}

	var room struct {
		Members []Member `json:"members"`
	}

	if err := json.Unmarshal(roomBytes, &room); err != nil {
		log.Fatalf("❌ Failed to parse room file: %v", err)
	}

	rewardTotal := getReward(len(blockchain.Chain))
	share := rewardTotal / float64(len(room.Members))

	rewardMap := make(map[string]float64)
	for _, m := range room.Members {
		rewardMap[m.Address] = share
	}

	var txs []Transaction
	for _, m := range room.Members {
		txs = append(txs, createTransaction("SYSTEM", m.Address, share))
	}

	newBlock := Block{
		Index:        len(blockchain.Chain),
		Timestamp:    time.Now().Format(time.RFC3339),
		Transactions: txs,
		PreviousHash: prev.Hash,
		Nonce:        0,
		Miner:        address,
		Reward:       rewardTotal,
	}

	fmt.Printf("Mining block %d by %s...\n", newBlock.Index, address)
	mineBlock(&newBlock, blockchain.Difficulty)
	newBlock.Hash = calculateHash(newBlock)

	blockchain.Lock()
	blockchain.Chain = append(blockchain.Chain, newBlock)
	blockchain.Unlock()

	saveBlockAsZythFile(newBlock)

	fmt.Printf("✅ Block %d mined! Hash: %s | Total Reward: %.8f ZYTH → %.8f each\n",
		newBlock.Index, newBlock.Hash, rewardTotal, share)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run miner.go <your_address> <room_code>")
		return
	}
	address := os.Args[1]
	roomCode := os.Args[2]

	fmt.Printf(" Starting continuous mining for %s (room %s)...\n", address, roomCode)
	for {
		mineGroup(address, roomCode)
	}
}
