package checker

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/berckan/domainhunter/internal/models"
	"github.com/likexian/whois"
)

// Checker handles domain availability checks
type Checker struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// New creates a new domain checker
func New() *Checker {
	return &Checker{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, "8.8.8.8:53")
			},
		},
		timeout: 10 * time.Second,
	}
}

// Patterns that indicate domain IS registered (taken) - check these FIRST
var takenPatterns = []string{
	"registrar:",
	"registrant:",
	"creation date:",
	"created:",
	"registry expiry date:",
	"expiration date:",
	"name server:",
	"nameserver:",
	"nserver:",
	"dnssec:",
	"registrar iana id:",
	"domain status:",
	"admin contact:",
	"tech contact:",
	"billing contact:",
}

// Patterns that indicate domain is NOT registered (available)
var availablePatterns = []string{
	"no match for",
	"not found",
	"no entries found",
	"domain not found",
	"no data found",
	"status: free",
	"status: available",
	"no object found",
	"object does not exist",
	"nothing found",
	"no information available",
	"is available for registration",
	"is free",
	"domain is available",
	"the queried object does not exist",
	"no such domain",
	"domain name has not been registered",
	"no matching record",
}

// Check verifies if a single domain is available using WHOIS
func (c *Checker) Check(domain string) models.DomainResult {
	result := models.DomainResult{
		Domain:    domain,
		CheckedAt: time.Now(),
	}

	// Try WHOIS lookup
	whoisResult, err := whois.Whois(domain)
	if err != nil {
		// WHOIS failed - mark as taken (conservative approach)
		result.Status = models.StatusTaken
		return result
	}

	whoisLower := strings.ToLower(whoisResult)

	// FIRST: Check if domain is taken (more reliable)
	for _, pattern := range takenPatterns {
		if strings.Contains(whoisLower, pattern) {
			result.Status = models.StatusTaken
			return result
		}
	}

	// SECOND: Check for premium/platinum reserved domains (NOT truly available)
	if (strings.Contains(whoisLower, "premium") || strings.Contains(whoisLower, "platinum")) &&
		(strings.Contains(whoisLower, "purchase") || strings.Contains(whoisLower, "contact") ||
			strings.Contains(whoisLower, "offer") || strings.Contains(whoisLower, "reserved")) {
		result.Status = models.StatusTaken
		return result
	}
	if strings.Contains(whoisLower, "this name is reserved") {
		result.Status = models.StatusTaken
		return result
	}

	// THEN: Check if explicitly marked as available
	for _, pattern := range availablePatterns {
		if strings.Contains(whoisLower, pattern) {
			result.Status = models.StatusAvailable
			return result
		}
	}

	// If unclear, assume taken (conservative)
	result.Status = models.StatusTaken
	return result
}

// checkDNS is the fallback DNS-based check
func (c *Checker) checkDNS(domain string) models.DomainResult {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	result := models.DomainResult{
		Domain:    domain,
		CheckedAt: time.Now(),
	}

	_, err := c.resolver.LookupHost(ctx, domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				result.Status = models.StatusAvailable
				return result
			}
		}
		// Unknown DNS errors → assume taken (conservative)
		result.Status = models.StatusTaken
		return result
	}

	result.Status = models.StatusTaken
	return result
}

// CheckBulk checks multiple domains with limited concurrency (WHOIS rate limiting)
func (c *Checker) CheckBulk(domains []string) []models.DomainResult {
	results := make([]models.DomainResult, len(domains))
	var wg sync.WaitGroup

	// Limit concurrency to 5 to avoid WHOIS rate limiting
	semaphore := make(chan struct{}, 5)

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			semaphore <- struct{}{}        // acquire
			results[idx] = c.Check(d)
			<-semaphore                    // release
		}(i, domain)
	}

	wg.Wait()
	return results
}

// PremiumTLDs is a curated list of valuable TLDs for short domain scanning
var PremiumTLDs = []string{
	"com", "net", "org", "io", "dev", "app", "ai", "co",
	"me", "tv", "gg", "so", "to", "is", "sh", "ly",
	"de", "uk", "es", "fr", "it", "nl", "ch", "at",
}

// CommonTLDs is a list of popular TLDs to check
var CommonTLDs = []string{
	// Generic
	"com", "net", "org", "info", "biz", "name", "pro",
	// Tech
	"io", "dev", "app", "ai", "tech", "code", "software", "digital", "cloud", "data", "systems",
	// New gTLDs
	"co", "me", "tv", "cc", "fm", "gg", "xyz", "online", "site", "website", "web",
	"store", "shop", "buy", "sale", "market",
	"blog", "news", "media", "press", "video", "photos",
	"design", "studio", "art", "gallery", "agency", "creative",
	"live", "life", "world", "global", "international",
	"club", "social", "community", "network", "group", "team",
	"email", "link", "click", "page", "space", "zone", "one",
	// Country codes - Americas
	"us", "ca", "mx", "br", "ar", "cl", "co", "pe", "ve",
	// Country codes - Europe
	"uk", "de", "fr", "es", "it", "nl", "be", "ch", "at", "pl", "pt", "ie", "se", "no", "dk", "fi", "cz", "hu", "ro", "gr", "ru", "ua",
	// Country codes - Asia/Pacific
	"jp", "cn", "kr", "in", "au", "nz", "sg", "hk", "tw", "th", "my", "ph", "id", "vn",
	// Country codes - Other
	"za", "ae", "il", "tr", "eg", "ng", "ke",
	// Premium/Short
	"to", "is", "so", "sh", "sx", "vc", "ws", "la", "ly", "gl", "im", "ht", "mu", "nu", "pw", "tk",
}

// GenerateMultiTLD generates the same name across multiple TLDs
func GenerateMultiTLD(name string, tlds []string) []string {
	if tlds == nil {
		tlds = CommonTLDs
	}
	domains := make([]string, len(tlds))
	for i, tld := range tlds {
		domains[i] = name + "." + tld
	}
	return domains
}

// GenerateShortDomains generates all possible domains of given length
func GenerateShortDomains(length int, tld string) []string {
	if length < 1 || length > 3 {
		return nil
	}

	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	var domains []string

	switch length {
	case 1:
		for _, c := range chars {
			domains = append(domains, string(c)+"."+tld)
		}
	case 2:
		for _, c1 := range chars {
			for _, c2 := range chars {
				domains = append(domains, string(c1)+string(c2)+"."+tld)
			}
		}
	case 3:
		for _, c1 := range chars {
			for _, c2 := range chars {
				for _, c3 := range chars {
					domains = append(domains, string(c1)+string(c2)+string(c3)+"."+tld)
				}
			}
		}
	}

	return domains
}

// GenerateShortDomainsMultiTLD generates short domains across multiple TLDs
func GenerateShortDomainsMultiTLD(length int, prefix string) []string {
	if length < 1 || length > 3 {
		return nil
	}

	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	var names []string

	// Generate names based on length and prefix
	remainingLen := length - len(prefix)
	if remainingLen < 0 {
		return nil
	}

	switch remainingLen {
	case 0:
		names = append(names, prefix)
	case 1:
		for _, c := range chars {
			names = append(names, prefix+string(c))
		}
	case 2:
		for _, c1 := range chars {
			for _, c2 := range chars {
				names = append(names, prefix+string(c1)+string(c2))
			}
		}
	case 3:
		for _, c1 := range chars {
			for _, c2 := range chars {
				for _, c3 := range chars {
					names = append(names, prefix+string(c1)+string(c2)+string(c3))
				}
			}
		}
	}

	// Generate domains across all premium TLDs
	var domains []string
	for _, name := range names {
		for _, tld := range PremiumTLDs {
			domains = append(domains, name+"."+tld)
		}
	}

	return domains
}

// CheckBulkHybrid uses DNS first (fast), then WHOIS to confirm candidates
func (c *Checker) CheckBulkHybrid(domains []string) []models.DomainResult {
	// Phase 1: Fast DNS check (high concurrency)
	dnsResults := make([]models.DomainResult, len(domains))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // High concurrency for DNS

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			semaphore <- struct{}{}
			dnsResults[idx] = c.checkDNS(d)
			<-semaphore
		}(i, domain)
	}
	wg.Wait()

	// Phase 2: WHOIS confirmation for DNS "available" results
	var candidates []int
	for i, r := range dnsResults {
		if r.Status == models.StatusAvailable {
			candidates = append(candidates, i)
		}
	}

	// Confirm with WHOIS (limited concurrency)
	whoisSem := make(chan struct{}, 5)
	var wg2 sync.WaitGroup

	for _, idx := range candidates {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			whoisSem <- struct{}{}
			dnsResults[i] = c.Check(domains[i]) // Full WHOIS check
			<-whoisSem
		}(idx)
	}
	wg2.Wait()

	return dnsResults
}
