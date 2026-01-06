package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/berckan/domainhunter/internal/checker"
)

var (
	templates = template.Must(template.ParseGlob("web/templates/*.html"))
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
