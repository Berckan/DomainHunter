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

	// Scan 1-char domains (36 names × 24 TLDs = 864 domains)
	fmt.Println("Scanning 1-char domains across 24 TLDs...")
	domains1 := checker.GenerateShortDomainsMultiTLD(1, "")
	fmt.Printf("Checking %d domains...\n", len(domains1))

	results1 := domainChecker.CheckBulkHybrid(domains1)
	for _, r := range results1 {
		if r.Status == models.StatusAvailable {
			allAvailable = append(allAvailable, r)
		}
	}

	// Scan 2-char domains (1296 names × 24 TLDs = 31104 domains)
	fmt.Println("\nScanning 2-char domains across 24 TLDs...")
	domains2 := checker.GenerateShortDomainsMultiTLD(2, "")
	fmt.Printf("Checking %d domains...\n", len(domains2))

	results2 := domainChecker.CheckBulkHybrid(domains2)
	for _, r := range results2 {
		if r.Status == models.StatusAvailable {
			allAvailable = append(allAvailable, r)
		}
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

	// Build HTML email with table-based layout for email clients
	var html strings.Builder
	html.WriteString(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden;">

<!-- Header -->
<tr>
<td style="background-color: #14532d; padding: 30px; text-align: center;">
<h1 style="color: #22c55e; margin: 0; font-family: Arial, sans-serif; font-size: 28px;">🎯 Domain Hunter</h1>
<p style="color: #86efac; margin: 10px 0 0 0; font-family: Arial, sans-serif; font-size: 14px;">Daily Report</p>
</td>
</tr>

<!-- Summary -->
<tr>
<td style="padding: 30px; text-align: center; border-bottom: 1px solid #e5e5e5;">
<p style="font-family: Arial, sans-serif; font-size: 18px; color: #333; margin: 0;">
Found <strong style="color: #22c55e; font-size: 32px;">`)
	html.WriteString(fmt.Sprintf("%d", len(domains)))
	html.WriteString(`</strong> available domains
</p>
<p style="font-family: Arial, sans-serif; font-size: 12px; color: #999; margin: 10px 0 0 0;">`)
	html.WriteString(time.Now().Format("January 2, 2006"))
	html.WriteString(`</p>
</td>
</tr>

<!-- Domains by TLD -->
<tr>
<td style="padding: 20px 30px;">
`)

	for tld, domainList := range byTLD {
		html.WriteString(fmt.Sprintf(`
<table width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom: 20px;">
<tr>
<td style="background-color: #f0fdf4; padding: 10px 15px; border-radius: 6px 6px 0 0; border-left: 4px solid #22c55e;">
<strong style="font-family: Arial, sans-serif; font-size: 16px; color: #14532d;">.%s</strong>
<span style="font-family: Arial, sans-serif; font-size: 12px; color: #666; margin-left: 8px;">(%d domains)</span>
</td>
</tr>
<tr>
<td style="padding: 15px; background-color: #fafafa; border-radius: 0 0 6px 6px;">
`, tld, len(domainList)))

		for i, domain := range domainList {
			if i > 0 {
				html.WriteString(` `)
			}
			html.WriteString(fmt.Sprintf(`<code style="display: inline-block; background-color: #ffffff; border: 1px solid #d1d5db; padding: 6px 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 14px; color: #111; margin: 3px;">%s</code>`, domain))
		}

		html.WriteString(`
</td>
</tr>
</table>
`)
	}

	html.WriteString(`
</td>
</tr>

<!-- Footer -->
<tr>
<td style="background-color: #f9f9f9; padding: 20px 30px; text-align: center; border-top: 1px solid #e5e5e5;">
<p style="font-family: Arial, sans-serif; font-size: 12px; color: #999; margin: 0;">
Sent by <a href="https://domain-hunter.fly.dev" style="color: #22c55e;">Domain Hunter</a> ·
<a href="https://github.com/Berckan/DomainHunter" style="color: #22c55e;">GitHub</a>
</p>
</td>
</tr>

</table>
</td></tr>
</table>
</body>
</html>`)

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
