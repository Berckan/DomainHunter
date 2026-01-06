package checker

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/berckan/domainhunter/internal/models"
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

// Check verifies if a single domain is available
func (c *Checker) Check(domain string) models.DomainResult {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	result := models.DomainResult{
		Domain:    domain,
		CheckedAt: time.Now(),
	}

	// Try to resolve the domain
	_, err := c.resolver.LookupHost(ctx, domain)
	if err != nil {
		// DNS error usually means domain is available or doesn't exist
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				result.Status = models.StatusAvailable
				return result
			}
		}
		// Could be available, but we're not 100% sure
		result.Status = models.StatusAvailable
		return result
	}

	// Domain resolves, so it's taken
	result.Status = models.StatusTaken
	return result
}

// CheckBulk checks multiple domains concurrently
func (c *Checker) CheckBulk(domains []string) []models.DomainResult {
	results := make([]models.DomainResult, len(domains))
	var wg sync.WaitGroup

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			results[idx] = c.Check(d)
		}(i, domain)
	}

	wg.Wait()
	return results
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
