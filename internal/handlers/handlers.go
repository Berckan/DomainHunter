package handlers

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/berckan/domainhunter/internal/checker"
	"github.com/berckan/domainhunter/internal/models"
)

var (
	templates     = template.Must(template.ParseGlob("web/templates/*.html"))
	domainChecker = checker.New()
)

// Home renders the main page
func Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	templates.ExecuteTemplate(w, "index.html", nil)
}

// CheckDomain handles single domain check via HTMX
func CheckDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// Add .com if no TLD provided
	if !strings.Contains(domain, ".") {
		domain = domain + ".com"
	}

	result := domainChecker.Check(domain)
	templates.ExecuteTemplate(w, "result.html", result)
}

// CheckBulk handles multiple domain checks
func CheckBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domainsRaw := r.FormValue("domains")
	lines := strings.Split(domainsRaw, "\n")

	var domains []string
	for _, line := range lines {
		d := strings.TrimSpace(line)
		if d != "" {
			if !strings.Contains(d, ".") {
				d = d + ".com"
			}
			domains = append(domains, d)
		}
	}

	if len(domains) == 0 {
		http.Error(w, "No domains provided", http.StatusBadRequest)
		return
	}

	// Limit to 50 domains per request
	if len(domains) > 50 {
		domains = domains[:50]
	}

	results := domainChecker.CheckBulk(domains)
	templates.ExecuteTemplate(w, "results-bulk.html", results)
}

// ScanShort scans short domains (2-3 chars) and returns only available ones
func ScanShort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lengthStr := r.FormValue("length")
	tld := strings.TrimSpace(r.FormValue("tld"))
	prefix := strings.ToLower(strings.TrimSpace(r.FormValue("prefix")))

	length, err := strconv.Atoi(lengthStr)
	if err != nil || length < 1 || length > 3 {
		http.Error(w, "Length must be 1, 2, or 3", http.StatusBadRequest)
		return
	}

	if tld == "" {
		tld = "com"
	}
	tld = strings.TrimPrefix(tld, ".")

	// Generate domains
	domains := checker.GenerateShortDomains(length, tld)

	// Filter by prefix if provided
	if prefix != "" {
		var filtered []string
		for _, d := range domains {
			if strings.HasPrefix(d, prefix) {
				filtered = append(filtered, d)
			}
		}
		domains = filtered
	}

	// Limit to prevent abuse (max 500 domains per scan)
	if len(domains) > 500 {
		domains = domains[:500]
	}

	if len(domains) == 0 {
		templates.ExecuteTemplate(w, "scan-empty.html", nil)
		return
	}

	// Check all domains concurrently
	allResults := domainChecker.CheckBulk(domains)

	// Filter only available domains
	var available []models.DomainResult
	for _, r := range allResults {
		if r.Status == models.StatusAvailable {
			available = append(available, r)
		}
	}

	data := struct {
		Available []models.DomainResult
		Total     int
		Checked   int
	}{
		Available: available,
		Total:     len(available),
		Checked:   len(domains),
	}

	templates.ExecuteTemplate(w, "scan-results.html", data)
}
