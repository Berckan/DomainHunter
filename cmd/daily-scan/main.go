package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/berckan/domainhunter/internal/checker"
	"github.com/berckan/domainhunter/internal/models"
)

func main() {
	apiKey := os.Getenv("RESEND_API_KEY")
	emailTo := os.Getenv("EMAIL_TO")

	if apiKey == "" || emailTo == "" {
		fmt.Println("Error: RESEND_API_KEY and EMAIL_TO environment variables required")
		os.Exit(1)
	}

	fmt.Println("🔍 Starting daily domain scan...")

	domainChecker := checker.New()
	var allAvailable []models.DomainResult

	// Scan 1-char domains (no prefix needed)
	fmt.Println("Scanning 1-char domains...")
	domains1 := checker.GenerateShortDomainsMultiTLD(1, "")
	results1 := domainChecker.CheckBulkHybrid(domains1)
	for _, r := range results1 {
		if r.Status == models.StatusAvailable {
			allAvailable = append(allAvailable, r)
		}
	}
	fmt.Printf("  Found %d available\n", countAvailable(results1))

	// Scan 2-char domains with common prefixes
	prefixes2 := []string{"a", "b", "c", "x", "z", "0", "1"}
	for _, prefix := range prefixes2 {
		fmt.Printf("Scanning 2-char domains (prefix: %s)...\n", prefix)
		domains2 := checker.GenerateShortDomainsMultiTLD(2, prefix)
		results2 := domainChecker.CheckBulkHybrid(domains2)
		for _, r := range results2 {
			if r.Status == models.StatusAvailable {
				allAvailable = append(allAvailable, r)
			}
		}
		fmt.Printf("  Found %d available\n", countAvailable(results2))
		time.Sleep(2 * time.Second) // Rate limiting between batches
	}

	fmt.Printf("\n✅ Total available domains found: %d\n", len(allAvailable))

	// Send email
	if len(allAvailable) > 0 {
		err := sendEmail(apiKey, emailTo, allAvailable)
		if err != nil {
			fmt.Printf("❌ Error sending email: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("📧 Email sent successfully!")
	} else {
		fmt.Println("📭 No available domains found, skipping email")
	}
}

func countAvailable(results []models.DomainResult) int {
	count := 0
	for _, r := range results {
		if r.Status == models.StatusAvailable {
			count++
		}
	}
	return count
}

func sendEmail(apiKey, to string, domains []models.DomainResult) error {
	// Group domains by TLD for better readability
	byTLD := make(map[string][]string)
	for _, d := range domains {
		parts := strings.Split(d.Domain, ".")
		if len(parts) >= 2 {
			tld := parts[len(parts)-1]
			byTLD[tld] = append(byTLD[tld], d.Domain)
		}
	}

	// Build HTML email
	var html strings.Builder
	html.WriteString(`<html><body style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">`)
	html.WriteString(`<h1 style="color: #22c55e;">🎯 Domain Hunter - Daily Report</h1>`)
	html.WriteString(fmt.Sprintf(`<p style="color: #666;">Found <strong>%d</strong> available domains</p>`, len(domains)))
	html.WriteString(`<p style="color: #999; font-size: 12px;">` + time.Now().Format("January 2, 2006 at 15:04 MST") + `</p>`)

	for tld, domainList := range byTLD {
		html.WriteString(fmt.Sprintf(`<h3 style="color: #333; margin-top: 20px;">.%s (%d)</h3>`, tld, len(domainList)))
		html.WriteString(`<div style="display: flex; flex-wrap: wrap; gap: 8px;">`)
		for _, domain := range domainList {
			html.WriteString(fmt.Sprintf(`<span style="background: #f0fdf4; border: 1px solid #22c55e; padding: 4px 8px; border-radius: 4px; font-family: monospace;">%s</span>`, domain))
		}
		html.WriteString(`</div>`)
	}

	html.WriteString(`<hr style="margin-top: 30px; border: none; border-top: 1px solid #eee;">`)
	html.WriteString(`<p style="color: #999; font-size: 12px;">Sent by <a href="https://domain-hunter.fly.dev">Domain Hunter</a> • <a href="https://github.com/Berckan/DomainHunter">GitHub</a></p>`)
	html.WriteString(`</body></html>`)

	// Resend API payload
	payload := map[string]interface{}{
		"from":    "Domain Hunter <onboarding@resend.dev>",
		"to":      []string{to},
		"subject": fmt.Sprintf("🎯 %d domains available - %s", len(domains), time.Now().Format("Jan 2")),
		"html":    html.String(),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("resend API returned status %d", resp.StatusCode)
	}

	return nil
}
