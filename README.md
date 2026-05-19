# NIL — Code Intelligence Engine for Termux/Android

> A lightweight, offline-first code intelligence tool written in C, designed to run natively on Android via Termux. No cloud, no Node.js, no heavy runtime — just a single binary backed by SQLite.

**Repo:** https://github.com/jaminejunior0-a11y/Nil.git

## What it does

- **Indexes your code** — scans C, Python, JS, Go, Rust, Java source files, extracts patterns using PCRE2 regex templates, stores everything in a local SQLite database
- **Semantic search** — SHA256-based text embeddings + cosine similarity + full-text search fallback
- **Terminal awareness** — parses gcc and Python error output, logs errors with file/line context
- **SID resume strings** — serializes your entire session state into a base64 string you paste into any AI chat to restore context
- **File watcher** — polls for changes, auto-reindexes (no inotify, works on Android)
- **Pattern templates** — PCRE2 regex templates to extract functions, DB queries, API calls
- **AI report generation** — connects to Ollama for architecture and security analysis (optional)

## Tech Stack
C, SQLite, OpenSSL, libcurl, PCRE2, json-c, pthreads

## Install (Termux)

\`\`\`bash
git clone https://github.com/jaminejunior0-a11y/Nil.git
cd Nil
bash setup_termux.sh
make
cp nil \$PREFIX/bin/nil
nil init
\`\`\`

## Usage

\`\`\`
nil init                    Initialize environment
nil status                  Show database stats
nil analyze <file> [sid]    Analyze a single file
nil index <path> [sid]      Index an entire codebase
nil search <query> [sid]    Search code (embeddings + FTS)
nil watch <sid> [path]      Watch directory for changes
nil report <sid>            Generate AI analysis (requires Ollama)
nil parse <file> [sid]      Parse terminal output for errors
nil resume [sid]            Generate SID resume string
nil import-sid <string>     Import SID assumptions
nil template create         Create default language templates
\`\`\`

## Contributing

We are looking for contributors to help make NIL a proper Termux package for the official repository.

**Good first issues:**
- Pipe support for \`nil parse\` (read from stdin)
- Groq/OpenAI support for \`nil report\`
- More language templates (bash, TypeScript, Rust, Lua)
- \`nil diff\` command
- Testing on different Android devices

**Bigger goals:**
- Official Termux package submission
- \`nil serve\` local HTTP API
- Recursive directory watching
- Plugin system for custom extractors

PRs welcome: https://github.com/jaminejunior0-a11y/Nil.git

## License
MIT
