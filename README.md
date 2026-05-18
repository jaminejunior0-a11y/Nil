# NIL — Code Intelligence Engine v4.0

> **N**arrative **I**nference **L**ayer with **S**cene **I**dentity **D**escriptor Integration

NIL watches your code, extracts patterns, logs decisions, and builds a knowledge graph. When you paste terminal output into AI chats, NIL generates **SID resume strings** — portable session state that gives any AI full context of your project.

---

## The Problem

You use AI to code. Every new chat session starts from zero. You copy-paste terminal output, but the AI doesn't remember:
- What you were trying to do yesterday
- Why that fix worked (or didn't)
- What files you changed
- What errors keep recurring

## The Solution

```bash
# Terminal output -> structured decisions
$ nil parse /tmp/term.out myproject
  ModuleNotFoundError: redis at myapp.py:45
  -> Logged as decision with full causal context

# Generate portable session state
$ nil resume myproject
  SID:4.0.0:abc123:eyJhc3N1bXB0aW9ucyI6eyJmaXhfdHlwZSI6ImltcG9ydF9lcnJvciIsIm1vZHVsZSI6InJlZGlzIiwibGluZSI6NDV9fQ==

# Paste into any AI chat -> full context restored
```

---

## Features

| Feature | Implementation |
|---------|---------------|
| **File Watcher** | `inotify` with `IN_MODIFY \| IN_CREATE \| IN_MOVED_TO` — no polling |
| **Pattern Engine** | PCRE2 with `.template` files — hot-reloadable, language-specific |
| **Auto-Logger** | Every pattern match -> decision in SQLite with embedding |
| **Code Graph** | `code_snapshots` table with functions, variables, hashes |
| **AI Reports** | LLM prompt with metrics (files, functions, queries, APIs) |
| **Similarity Search** | Cosine similarity on 128-dim embeddings, <10ms for 1K files |
| **FTS5 Search** | Full-text code search via SQLite virtual table |
| **Terminal Parser** | Python tracebacks + GCC errors -> structured decisions |
| **SID Resume** | Base64-encoded, checksum-verified session state |

---

## Quick Start

### Termux

```bash
pkg install gcc sqlite openssl curl libjson-c pcre2 make git

gcc -O3 -Wall -pthread -o nil nil.c \
    -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -ldl -lpcre2-8

./nil init
./nil watch myproject ~/src/myproject
```

### Linux

```bash
sudo apt install gcc libsqlite3-dev libssl-dev libcurl4-openssl-dev \
                 libjson-c-dev libpcre2-dev make git

gcc -O3 -Wall -pthread -o nil nil.c \
    -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -ldl -lpcre2-8
```

---

## Commands

```bash
nil init                    # Initialize environment
nil watch <sid> [path]      # Watch directory via inotify
nil analyze <file> [sid]    # Analyze single file
nil index <path> [sid]      # Index entire codebase
nil report <sid>            # AI analysis report
nil search <query> [sid]    # Semantic code search
nil parse <file> [sid]      # Parse terminal output for errors
nil resume [sid]            # Generate SID resume string
nil import-sid <string>     # Import SID package
nil template create         # Create default templates
nil status                  # Show statistics
```

---

## Template System

Templates are `.template` files in `~/.nil/templates/`:

```ini
[pattern:function]
regex = ^[a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*\{
action = log
key = function.declared
language = c

[pattern:sql_query]
regex = (mysql_query|sqlite3_exec|PQexec|pg_query)\s*\([^,]*,\s*"([^"]+)"
action = report
key = database.query
language = c
```

Edit live — no restart needed.

---

## SID Resume Workflow

```bash
# 1. Start session
nil init
nil watch myproject ~/src/myproject

# 2. Something breaks — save terminal output
python myapp.py > /tmp/term.out 2>&1
nil parse /tmp/term.out myproject

# 3. Generate resume string for AI chat
nil resume myproject
# -> SID:4.0.0:abc123:eyJhc3N1bXB0aW9ucyI6eyJmaXhfdHlwZSI6ImltcG9ydF9lcnJvciIsIm1vZHVsZSI6InJlZGlzIiwibGluZSI6NDV9fQ==

# 4. Paste into any AI chat — full context restored
# 5. AI suggests fix, you apply it
# 6. Next session: nil resume myproject -> paste -> continue
```

---

## Architecture

```
~/.nil/
├── nil.db              # SQLite with FTS5, embeddings, snapshots
├── .key                # AES-256 encryption key
├── templates/
│   ├── c.template      # Function, SQL query, API call patterns
│   └── python.template # Python-specific patterns
├── analysis/           # AI-generated reports
├── sid/               # Per-project workspaces
└── terminal/          # Parsed terminal sessions
```

### Database Schema

- **decisions** — node_id, sid, action, key, value, rationale, timestamp, confidence, embedding
- **code_snapshots** — file_path, sid, language, lines, hash, embedding
- **code_patterns** — pattern matches with line numbers
- **terminal_sessions** — command, output, exit_code, cwd, embedding
- **terminal_errors** — error_type, file, line, message, stack_trace
- **sid_packages** — version, checksum, assumptions, invariants
- **analysis_reports** — AI-generated reports with metrics
- **code_fts** — FTS5 virtual table for full-text search
- **terminal_fts** — FTS5 virtual table for terminal search

---

## Causal Graph

Every decision links to its parent. When you ask "why did this break?":

```
you added caching (decision #42)
  -> forgot redis in requirements (oversight)
    -> ModuleNotFoundError (event)
      -> you asked AI for help (decision #44)
        -> AI suggested pip install redis>=4.2 (recommendation)
          -> you validated compatibility (check)
            -> you applied the fix (decision #45)
```

---

## Author

Built by an electrical and electronic engineer who got tired of re-explaining project context to AI chatbots.

---

## License

MIT
