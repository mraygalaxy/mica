# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MLL (Meta-Language Learning) / MICA is a language-learning application that tracks vocabulary acquisition as users read stories. It supports English, Spanish, and Chinese (simplified). The mobile companion app is called "Read Alien" (Android/iOS).

Full docs: `../mica.wiki/Home.md` (local clone of git@github.com:mraygalaxy/mica.wiki.git)

## Tech Stack

- **Python 2.7** — legacy codebase (uses `cStringIO`, `urllib2`, etc.)
- **Twisted** — async web server with SSL
- **CouchDB** — primary document store for users, stories, sessions, vocabulary state
- **SQLite DBs** — offline dictionaries: `cedict.db`, `jieba.db`, `pinyin.db`, `tones.db`, `eng.db`, `eng2span.db`, `cjklib.db`
- **ICTCLAS** — C++ extension for Chinese lexical analysis (compiled via `setup.py`)
- **jQuery Mobile + Backbone.js** — frontend

## Build & Run

### Install dependencies (Ubuntu)
```bash
sudo apt-get install python-dev python-openssl python-setuptools python-sqlalchemy python-twisted* python-beaker python-webob libstdc++5 python-simplejson python-daemon python-pip python-crypto python-zodb
sudo pip install cjklib pdfminer fpdf couchdb
```

### Compile the ICTCLAS C++ extension
```bash
# Copy shared libs first (64-bit):
sudo cp ictc_64bit/libICTCLAS50.* /usr/lib64 && sudo ldconfig

python setup.py build
sudo python setup.py install
cp build/*/mica_ictclas.so .
```

### Run
```bash
./test.py
```

Default credentials: `admin` / `password`. Runs on port 443 (SSL) or 80.

### Tests
```bash
python test.py           # main test/startup script
python test_ictclas.py   # Chinese lexical analysis tests
# JS tests: test/test.js
```

## Architecture

### Core Python Modules

| File | Purpose |
|------|---------|
| `mica.py` (~6400 lines) | Web server, all HTTP request routing, business logic |
| `processors.py` (~1550 lines) | Text processing pipeline (PDF extraction, word segmentation, vocabulary analysis) |
| `couch_adapter.py` (~1250 lines) | CouchDB abstraction layer |
| `templates.py` (~1150 lines) | Server-side template rendering |
| `common.py` (~470 lines) | Shared utilities, logging, config |
| `slave.py` | XML-RPC slave for distributed processing |
| `params.py` | Local configuration (not in repo — must be created) |

### Directory Structure

- `/serve/` — Frontend assets: HTML templates, CSS, JS, Bootstrap, jQuery Mobile, Backbone.js, fonts, images
- `/views/` — CouchDB design documents (JavaScript map/reduce views for accounts, chats, stories, sessions, splits, tonechanges, etc.)
- `/util/` — One-off conversion/migration scripts, ngrok tunneling helper
- `/test/` — Test suite + test data including example stories and ICTCLAS config
- `/Data/` — ICTCLAS NLP data files
- `Configure.xml` — ICTCLAS configuration for Chinese NLP

### Story Lifecycle

Stories move through four states managed in CouchDB:

1. **Untranslated** — uploaded but not yet processed
2. **Not Reviewed** — processed by `processors.py`, awaiting polyphome/conjugation review
3. **Reading** — reviewed and ready for active vocabulary learning
4. **Finished** — completed by the learner

### UI Modes

- **Review Mode** — a native speaker (or advanced learner) corrects polyphomes and conjugations before the story enters Reading. Words are color-coded by ambiguity:
  - *Grey* — single sound, single meaning (no action needed)
  - *Green* — single sound, multiple meanings (safe tone, may have wrong definition)
  - *Red* — multiple sounds and meanings (polyphome; must be corrected)
  - *Black* — previously corrected; MLL auto-selected the historically most common choice
- **Edit Mode** *(character-based languages only)* — fix incorrect word groupings via **Split** (break a multi-character word apart) or **Merge** (join separate characters into one word). MLL learns split/merge history and applies it to future translations. "Try Recommendations" bulk-applies historical edits.
- **Reading Mode** — vocabulary learning: translations are hidden by default; learner clicks to reveal and then clicks the revealed translation to mark a word as memorized. Memorization state persists across all stories.
- **Chat Mode** — real-time messaging with a custom IME that overlays per-word vocabulary metadata inline as the learner types and receives messages. Chat histories become stories in the database.

### Data Flow

1. User uploads a story (PDF or text) via the web UI
2. `processors.py` extracts text, segments words (ICTCLAS for Chinese, jieba as fallback), annotates with pinyin/translations from local SQLite DBs or Microsoft Translator API
3. Processed story is stored in CouchDB alongside per-user vocabulary state
4. Frontend (jQuery Mobile + Backbone.js) renders the annotated story; user interactions update vocabulary knowledge state back to CouchDB
5. Mobile apps (Read Alien) sync vocabulary state via CouchDB replication

### Configuration

`params.py` must be created locally with required parameters (API keys, CouchDB credentials, SSL cert paths). Not checked in.

SSL cert generation:
```bash
openssl req -x509 -nodes -days 9000 -newkey rsa:2048 -keyout mica.key -out mica.crt
```
