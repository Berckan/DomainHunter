# Changelog

## [2026.01.06] - v0.3.0

### Added
- Production deployment on Fly.io (Frankfurt region)
  WHY: Make the app publicly accessible for portfolio showcase
- Dockerfile with multi-stage build (9.3MB final image)
  WHY: Efficient container for fast deployments

---

## [2026.01.06] - v0.2.0

### Added
- Short Domain Scanner feature
  WHY: Core differentiator - find available 1-3 character domains across TLDs
- Prefix filtering for scanner
  WHY: Reduces search space and allows targeted domain hunting
- Multiple TLD support (.com, .io, .dev, .co, .ai, .app)
  WHY: Modern TLDs are popular for tech projects and startups

---

## [2026.01.06] - v0.1.0

### Added
- Initial project structure with Go + HTMX
  WHY: First StackQuest facet - learning Go and HTMX through a practical project
- Basic domain availability checker using DNS resolution
  WHY: Core functionality needed before adding advanced features
- Single domain quick check with real-time HTMX response
  WHY: Primary use case - check if a specific domain is available
- Bulk domain checking with concurrent goroutines
  WHY: Efficient checking of multiple domains simultaneously
- Responsive dark-mode UI with Tailwind CSS
  WHY: Portfolio-ready design from the start
