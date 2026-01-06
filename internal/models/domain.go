package models

import "time"

// DomainStatus represents the availability status of a domain
type DomainStatus string

const (
	StatusAvailable   DomainStatus = "available"
	StatusTaken       DomainStatus = "taken"
	StatusError       DomainStatus = "error"
	StatusChecking    DomainStatus = "checking"
)

// DomainResult holds the result of a domain check
type DomainResult struct {
	Domain    string       `json:"domain"`
	Status    DomainStatus `json:"status"`
	CheckedAt time.Time    `json:"checked_at"`
	Error     string       `json:"error,omitempty"`
}

// WatchedDomain represents a domain in the watch list
type WatchedDomain struct {
	ID        int64        `json:"id"`
	Domain    string       `json:"domain"`
	Status    DomainStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}
