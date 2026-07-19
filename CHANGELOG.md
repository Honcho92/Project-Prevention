# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-19

### Added
- Heuristic detector with 30+ patterns, brand-impersonation detection, entity extraction
- Question playbook with 35+ bait questions, hand-tuned by 10 scam types
- Honeypot with 3 personas (Margaret, Bob, Sam), auto-reply, sqlite evidence log
- Local LLM judge via Ollama (qwen2.5-coder:7b, ~1.3s per call after warmup)
- FTC/IC3/bank report pack — generates 9 ready-to-file documents
- SQLite history with FTS5 full-text search + schema migrations
- Telegram bot (long-poll, no library) with /score /honey /report /quiet /verbose /llm
- Background agent loop — auto-files report packs, sends DM
- Weekly digest — Sunday-night summary via Telegram
- Chrome extension (Manifest V3) with offline heuristic scoring + toolbar badge
- GitHub Actions CI (Python 3.11-3.13 on Linux + Windows, 88 tests)

### Privacy
- Zero external Python dependencies
- Only network calls: optional local Ollama, optional Telegram Bot API
- No data ever leaves your machine unless you wire up the bot

[0.2.0]: https://github.com/Honcho92/scam-shield/releases/tag/v0.2.0
