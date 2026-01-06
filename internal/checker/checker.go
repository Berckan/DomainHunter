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
		// WHOIS failed, fallback to DNS check
		return c.checkDNS(domain)
	}

	// Check if response indicates domain is available
	whoisLower := strings.ToLower(whoisResult)
	for _, pattern := range availablePatterns {
		if strings.Contains(whoisLower, pattern) {
			result.Status = models.StatusAvailable
			return result
		}
	}

	// If we got a WHOIS response without "not found" patterns, it's taken
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
		result.Status = models.StatusAvailable
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
