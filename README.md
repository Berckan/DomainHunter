# Domain Hunter

A fast, concurrent domain availability checker built with Go and HTMX.

## Features

- **Real-time checking** - Instant feedback via HTMX
- **Bulk checking** - Monitor multiple domains simultaneously
- **Short domain finder** - Scan 2-3 character domains
- **Watch list** - Get notified when domains become available
- **TLD support** - Check across multiple TLDs (.com, .io, .dev, etc.)

## Tech Stack

- **Go** - Backend, concurrency, DNS/WHOIS queries
- **HTMX** - Dynamic UI without JavaScript frameworks
- **Tailwind CSS** - Styling
- **SQLite** - Local storage for watch lists

## Getting Started

```bash
# Clone
git clone https://github.com/berckan/DomainHunter.git
cd DomainHunter

# Run
go run cmd/server/main.go

# Open
open http://localhost:8080
```

## Project Structure

```
domainhunter/
├── cmd/server/       # Application entry point
├── internal/
│   ├── checker/      # Domain checking logic
│   ├── handlers/     # HTTP handlers
│   └── models/       # Data structures
├── web/
│   ├── templates/    # HTML templates
│   └── static/       # CSS, assets
└── go.mod
```

## Roadmap

- [ ] Basic domain availability check
- [ ] Bulk domain checking
- [ ] Short domain scanner (2-3 chars)
- [ ] Watch list with persistence
- [ ] Email/webhook notifications
- [ ] WHOIS information display

## Part of StackQuest 2026

This project is part of [StackQuest](https://github.com/berckan/StackQuest) - a multi-stack learning journey.

## License

MIT
