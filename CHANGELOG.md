# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

---

## [v2.0.0] - 2026-01-05

### Added
- 🎉 Initial release of ecapture_decryptor library
- ✨ TLS/QUIC traffic decryption support
- 🌐 Multi-protocol support: HTTP/1.1, HTTP/2, HTTP/3, WebSocket
- 📦 Static library (.a) for C/C++ integration
- 📦 Dynamic/shared library (.so/.dylib) support
- 🔧 C API for cross-language integration
- 📝 Comprehensive documentation and examples
- 🎯 Go API for native Go integration
- 🧪 C demo programs (offline, stream, live capture)
- 🧪 Go demo programs with HAR export
- 📄 Dual license system (Proprietary source + Non-commercial binary)

### Documentation
- 📖 Complete README with usage examples
- 📖 LICENSE and LICENSE-BINARY files
- 📖 RELEASE_GUIDE for version management
- 📖 MAKEFILE_GUIDE for build system
- 📖 Example code in C and Go

### Infrastructure
- 🏗️ Modular Makefile structure
- 🏗️ Automated release scripts
- 🏗️ Multi-platform build support
- 🏗️ Unit tests and integration tests

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| v2.0.0 | 2026-01-05 | Initial release with full features |

---

## Release Notes Guidelines

When preparing a new release, update this file with changes in each category:

### Categories

- **Added**: New features
- **Changed**: Changes in existing functionality  
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security improvements

### Commit Message Format

Use conventional commits:
```
feat: Add new feature
fix: Fix bug in decryption
docs: Update documentation
refactor: Refactor code structure
test: Add tests
chore: Update dependencies
```

### Example Entry

```markdown
## [v1.1.0] - 2026-02-01

### Added
- Support for TLS 1.3 0-RTT decryption
- New API function `DecryptWithOptions()` 
- Performance monitoring metrics

### Changed
- Improved HTTP/2 frame parsing performance by 30%
- Updated error messages for better clarity

### Fixed
- Fixed memory leak in QUIC decryption (#123)
- Corrected HTTP/3 QPACK decoding edge case (#145)

### Security
- Updated dependencies to address CVE-2025-XXXX
```

---

**Maintained by**: CFC4N  
**Contact**: cfc4n.cs@gmail.com  
**Project**: https://github.com/cfc4n/ecapture_decryptor

