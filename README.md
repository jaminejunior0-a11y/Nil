# NIL — Code Intelligence Engine for Termux/Android

> A lightweight, offline-first code intelligence tool written in C, designed to run natively on Android via Termux. No cloud, no Node.js, no heavy runtime — just a single binary backed by SQLite.

**Repo:** https://github.com/jaminejunior0-a11y/Nil.git

| Platform | Watcher | Status |
|---|---|---|
| Linux | inotify (instant) | ✅ Full support |
| Android/Termux | polling (2s) | ✅ Full support |
| macOS | polling (2s) | ✅ Full support |

---

## What it does

- **Indexes your code** — scans C, Python, JS, Go, Rust, Java source files, extracts patterns using PCRE2 regex templates, and stores everything in a local SQLite database
- **Semantic search** — finds related files using SHA256-based text embeddings and cosine similarity, plus full-text search fallback so keyword queries always work
- **Terminal awareness** — parses gcc and Python error output, logs errors with file/line context, tracks what broke and when
- **SID resume strings** — serializes your entire session state (decisions, errors, file hashes, assumptions) into a portable base64 string you can paste into any AI chat to instantly restore context across sessions
- **File watcher** — polls your working directory for changes and automatically re-indexes modified files (polling-based, no inotify, works on Android)
- **Pattern templates** — configurable `.template` files using PCRE2 regex to extract functions, DB queries, API calls from any language
- **AI report generation** — connects to a local Ollama instance to generate architecture and security analysis (optional)

---

## Tech Stack

- **Language:** C
- **Storage:** SQLite
- **Crypto/Hashing:** OpenSSL
- **HTTP/LLM:** libcurl
- **Regex:** PCRE2
- **JSON:** json-c
- **Threading:** pthreads

---

## Why it matters

Most developer tools assume a Linux desktop or a cloud connection. NIL is built specifically for mobile-first developers working in Termux on Android, where RAM is tight, there's no inotify, and you want everything local and offline.

---

## Install (Termux)

```bash
# 1. Clone the repo
git clone https://github.com/jaminejunior0-a11y/Nil.git
cd Nil

# 2. Install dependencies (builds json-c from source automatically)
bash setup_termux.sh

# 3. Compile
make

# 4. Install system-wide
cp nil $PREFIX/bin/nil

# 5. Initialize
nil init
```

---

## Usage

```
nil init                    Initialize environment
nil status                  Show database stats
nil analyze <file> [sid]    Analyze a single file
nil index <path> [sid]      Index an entire codebase
nil search <query> [sid]    Search code with embeddings + FTS
nil watch <sid> [path]      Watch directory for changes (polling)
nil report <sid>            Generate AI analysis report (requires Ollama)
nil parse <file> [sid]      Parse terminal output for errors
nil resume [sid]            Generate SID resume string
nil import-sid <string>     Import SID assumptions
nil template create         Create default language templates
```

### Example workflow

```bash
nil init
nil analyze ~/myproject/main.c myproject
nil search "sqlite3" myproject
nil parse ~/error_output.txt myproject
nil resume myproject
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NIL_OLLAMA_URL` | `http://localhost:11434/api/generate` | LLM endpoint for reports |
| `NIL_MODEL` | `llama2` | Model name to use |

---

## Contributing

NIL is working and installable on Termux today. We're looking for contributors to help make it a proper Termux package and push it to the official Termux repository.

**Good first issues:**
- Pipe support so `nil parse` reads directly from stdin instead of a file
- Groq/OpenAI API support for `nil report` (not just Ollama)
- More language templates (bash, TypeScript, Rust, Lua)
- `nil diff` command to show what changed between two indexes
- Testing on different Android devices and Termux versions

**Bigger goals:**
- Package it for the official Termux repository (`build.sh`, package metadata)
- `nil serve` — local HTTP API so other tools can query the index
- Watch subdirectories recursively in the poller
- Plugin system for custom extractors

To contribute, fork the repo, make your changes, and open a pull request at:
https://github.com/jaminejunior0-a11y/Nil.git

---

## License

MIT
