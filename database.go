package main

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("postgres", "postgres://username:password@localhost/dbname?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// Create tables if they don't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			token_balance INT DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS courses (
			id SERIAL PRIMARY KEY,
			title TEXT NOT NULL,
			mentor_id INT REFERENCES users(id),
			description TEXT,
			price INT
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}
