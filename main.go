package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/gorilla/mux"
)

type Block struct {
	Pos       int
	Data      LearningSession
	Timestamp string
	Hash      string
	PrevHash  string
}

type LearningSession struct {
	SessionID    string `json:"session_id"`
	MentorID     string `json:"mentor_id"`
	LearnerID    string `json:"learner_id"`
	CourseID     string `json:"course_id"`
	StartTime    string `json:"start_time"`
	EndTime      string `json:"end_time"`
	CoursePrice  int    `json:"course_price"`
	TokensEarned int    `json:"tokens_earned"`
	IsGenesis    bool   `json:"is_genesis"`
}

type Course struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	MentorID    string `json:"mentor_id"`
	Description string `json:"description"`
	Price       int    `json:"price"`
}

func (b *Block) generateHash() {
	bytes, _ := json.Marshal(b.Data)
	data := string(b.Pos) + b.Timestamp + string(bytes) + b.PrevHash
	hash := sha256.New()
	hash.Write([]byte(data))
	b.Hash = hex.EncodeToString(hash.Sum(nil))
}

func CreateBlock(prevBlock *Block, learningSession LearningSession) *Block {
	block := &Block{}
	block.Pos = prevBlock.Pos + 1
	block.Timestamp = time.Now().String()
	block.Data = learningSession
	block.PrevHash = prevBlock.Hash
	block.generateHash()
	return block
}

type Blockchain struct {
	blocks []*Block
}

var BlockChain *Blockchain

func (bc *Blockchain) AddBlock(data LearningSession) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	block := CreateBlock(prevBlock, data)
	if validBlock(block, prevBlock) {
		bc.blocks = append(bc.blocks, block)
	}
}

func GenesisBlock() *Block {
	return CreateBlock(&Block{}, LearningSession{IsGenesis: true})
}

func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{GenesisBlock()}}
}

func validBlock(block, prevBlock *Block) bool {
	if prevBlock.Hash != block.PrevHash {
		return false
	}
	if !block.validateHash(block.Hash) {
		return false
	}
	if prevBlock.Pos+1 != block.Pos {
		return false
	}
	return true
}

func (b *Block) validateHash(hash string) bool {
	b.generateHash()
	return b.Hash == hash
}

func getBlockchain(w http.ResponseWriter, r *http.Request) {
	jbytes, err := json.MarshalIndent(BlockChain.blocks, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}
	io.WriteString(w, string(jbytes))
}

func writeBlock(w http.ResponseWriter, r *http.Request) {
	var learningSession LearningSession
	if err := json.NewDecoder(r.Body).Decode(&learningSession); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("could not decode learning session: %v", err)
		return
	}

	// Calculate duration and tokens earned
	startTime, _ := time.Parse(time.RFC3339, learningSession.StartTime)
	endTime, _ := time.Parse(time.RFC3339, learningSession.EndTime)
	duration := endTime.Sub(startTime)
	learningSession.TokensEarned = int(duration.Hours()) * learningSession.CoursePrice

	// Update mentor's token balance
	_, err := db.Exec("UPDATE users SET token_balance = token_balance + $1 WHERE id = $2", learningSession.TokensEarned, learningSession.MentorID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not update mentor's token balance: %v", err)
		return
	}

	BlockChain.AddBlock(learningSession)
	resp, err := json.MarshalIndent(learningSession, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not marshal payload: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func newCourse(w http.ResponseWriter, r *http.Request) {
	var course Course
	if err := json.NewDecoder(r.Body).Decode(&course); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if course.Title == "" || course.MentorID == "" || course.Price < 0 {
		http.Error(w, "Invalid course data", http.StatusBadRequest)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&course); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not create: %v", err)
		w.Write([]byte("could not create new Course"))
		return
	}

	h := md5.New()
	io.WriteString(h, course.Title+course.MentorID)
	course.ID = fmt.Sprintf("%x", h.Sum(nil))

	resp, err := json.MarshalIndent(course, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not marshal payload: %v", err)
		w.Write([]byte("could not save course data"))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func main() {
	initDB()
	BlockChain = NewBlockchain()

	r := mux.NewRouter()

	// Auth routes
	r.HandleFunc("/signup", Signup).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")

	// HTML routes
	r.HandleFunc("/", serveTemplate("index.html")).Methods("GET")
	r.HandleFunc("/blockchain", AuthMiddleware(serveTemplate("blockchain.html"))).Methods("GET")
	r.HandleFunc("/new-session", AuthMiddleware(serveTemplate("new-session.html"))).Methods("GET")
	r.HandleFunc("/new-course", AuthMiddleware(serveTemplate("new-course.html"))).Methods("GET")

	// API routes
	r.HandleFunc("/api/blockchain", AuthMiddleware(getBlockchain)).Methods("GET")
	r.HandleFunc("/api/session", AuthMiddleware(writeBlock)).Methods("POST")
	r.HandleFunc("/api/course", AuthMiddleware(newCourse)).Methods("POST")

	// ... (rest of the main function)
	log.Println("Listening on port 3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}

func serveTemplate(tmpl string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles("templates/" + tmpl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t.Execute(w, nil)
	}
}
