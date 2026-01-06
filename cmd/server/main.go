package main

import (
	"log"
	"net/http"
	"os"

	"github.com/berckan/domainhunter/internal/handlers"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Static files
	fs := http.FileServer(http.Dir("web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes
	http.HandleFunc("/", handlers.Home)
	http.HandleFunc("/check", handlers.CheckDomain)
	http.HandleFunc("/check-bulk", handlers.CheckBulk)
	http.HandleFunc("/scan-short", handlers.ScanShort)
	http.HandleFunc("/check-multitld", handlers.CheckMultiTLD)

	log.Printf("Server starting on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
