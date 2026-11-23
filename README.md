# WAM Agent — Web Activity Monitor

WAM Agent is a privacy-first browser safety helper. A browser extension checks
each page's **structure** (is it HTTPS? is there a password field? does a form
post to a different site?) and shows a plain-language warning. A small
**Flask** backend is a gateway for *optional* AI help and for shared,
anonymous data. WAM **warns only** — it never blocks pages, and it never
reads your passwords, messages, or other typed information.

---

## Repository layout

```
WAM/
├─ backend/                 Flask backend
│  ├─ url_utils.py          origin / HTTPS / hostname helpers (pure)
│  ├─ privacy_guard.py      builds the safe, non-personal signal summary
│  ├─ threat_rules.py       local threat rules
│  ├─ ai_budget.py          daily AI quota + result cache
│  ├─ analysis_service.py   the warning pipeline
│  ├─ app.py                Flask API gateway / entry point
│  ├─ ai_client.py          optional Gemini client (disabled without a key)
│  ├─ repository.py         shared storage (in-memory default / MariaDB)
│  ├─ settings.py           config + environment loading
│  └─ config.example.py     copy to config.py for your self-hosted MariaDB
├─ extension/               browser extension (Manifest V3, plain JavaScript)
│  ├─ manifest.json
│  ├─ content.js            page scanner (structure only, never reads values)
│  ├─ background.js         background worker + optional AI call
│  ├─ wam-local.js          shared local privacy guard + threat analyzer
│  ├─ popup.html / popup.js / popup.css   overview, warnings, settings
└─ requirements.txt
```

---

## Installation (Windows / PowerShell)

1. Install Python 3 (3.10 or newer). Check it:

   ```powershell
   python --version
   ```

2. From the project folder, install the one required dependency (Flask):

   ```powershell
   python -m pip install -r requirements.txt
   ```

No database, API key, or internet connection is needed to run the system —
it falls back to in-memory storage and local-only checks.

---

## Running the backend server

```powershell
python backend\app.py
```

The gateway listens on `http://127.0.0.1:5000`. Endpoints:

| Method | Path       | Purpose                                            |
| ------ | ---------- | --------------------------------------------------- |
| POST   | `/analyze` | Analyze an approved, non-personal feature summary  |
| GET    | `/rules`   | Shared threat rules                                |
| GET    | `/stats`   | Anonymous daily usage counts                       |
| GET    | `/health`  | Health check                                       |

`/analyze` **rejects** any request that contains a personal field (e.g.
`password`, `email`, `page_text`) or any field outside the approved allow-list.

---

## Loading the browser extension (Chrome / Edge)

1. Start the backend (above) if you want the optional AI path.
2. Open `chrome://extensions`, turn on **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Open any site and click the **WAM Agent** toolbar icon to see the overview,
   warnings, and settings. Try an `http://` page with a login form to see a
   danger warning.

The popup lets you enable/disable monitoring, pause WAM on the current site,
and set the backend URL.

---

## Using your self-hosted MariaDB (optional)

By default the backend uses in-memory storage, so it runs anywhere. To use your
own MariaDB server for the shared threat rules and anonymous counts:

```powershell
Copy-Item backend\config.example.py backend\config.py
```

Edit `backend\config.py` with your server's host, port, user, password, and
database. `config.py` is git-ignored. The backend creates its tables
automatically and, if the database is unreachable, falls back to in-memory
storage so the server still starts. Installing the driver:

```powershell
python -m pip install PyMySQL
```

(You can also provide the settings as environment variables: `WAM_DB_HOST`,
`WAM_DB_PORT`, `WAM_DB_USER`, `WAM_DB_PASSWORD`, `WAM_DB_NAME`.)

To enable real Gemini calls, set `GEMINI_API_KEY` in `config.py` (or the
`WAM_GEMINI_API_KEY` environment variable) and
`python -m pip install google-generativeai`. Without a key, WAM stays on
local-only checks.

---

## Privacy design in one line

The Privacy Guard builds a fresh object with only approved, non-personal flags
(for example `has_password_field=true`, `is_https=false`), and the gateway
rejects anything else — so sensitive content is never collected in the first
place, not merely filtered out later.
