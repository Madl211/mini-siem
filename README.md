# Mini-SIEM

A small, locally runnable security monitoring system I built to practice log analysis
and detection logic. It reads SSH and HTTP logs, pulls out the relevant events, runs
some detection rules over them, and shows the results (alerts) in a simple web UI.


## What it does

- Reads SSH auth logs (`auth.log` style) and HTTP access logs (Combined Log Format)
- Parsing doesn't crash on garbage/unknown lines - they just get counted as "unknown"
- Detection rules are defined in a YAML file (`app/detection/config.yaml`), not
  hardcoded, so adding a new threshold-based rule doesn't require touching the engine
- 6 rules are implemented: SSH brute force, login at an unusual hour, too many 404s,
  too many 500s, suspicious user agents (sqlmap, nikto, etc.), and a basic port-scan
  indicator (many different paths from one IP in a short window)
- A REST API (FastAPI) with filtering, text search, and JSON/CSV export
- A pretty minimal frontend (plain HTML/CSS/JS, no framework) with a dashboard, an
  alert table you can filter and acknowledge/resolve, an event table, a timeline view,
  and a log upload form
- SQLite as the database, nothing else needs to be installed/running
- pytest tests for the parsers, the detection engine and the API endpoints

## Setup

You need Python 3.11+ (I used 3.13 while developing this).

```powershell
cd mini-siem

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## Running it

```powershell
python run.py
```

Then open `http://127.0.0.1:8000/` for the UI, or `http://127.0.0.1:8000/docs` for the
auto-generated Swagger docs (handy for testing endpoints without the frontend).

On startup the app creates the SQLite file (`mini_siem.db`) if it doesn't exist yet and
loads the detection rules from `config.yaml`.

## Loading sample data

Go to the "Log-Upload" tab and click "Beispieldaten laden" (load sample data). This
reads the two files in `sample_logs/` (`auth.log`, `access.log`), saves the parsed
events and runs detection once over everything. There's also an API endpoint for it if
you don't want to click through the UI:

```
POST /api/logs/load-samples
```

The sample logs were written by hand to trigger all 6 rules at least once: a burst of
failed SSH logins, one login at 2:30 AM, a bunch of 404s and 500s, one request with the
`sqlmap` user agent, and a bunch of requests to different paths from the same IP. Each
file also has one intentionally broken line at the end to check that parsing doesn't
just die on bad input.

## Uploading your own logs

Either through the UI ("Log-Upload") or directly:

```
POST /api/logs/upload
  - file: the log file
  - log_type: "ssh" | "http" | "auto"
```

`auto` just checks whether the first non-empty line looks like an Apache/Nginx line
(`IP - - [...]`) or not. It's a pretty simple heuristic but works fine for the two
formats this project supports.

## Running the tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Tests run against a separate SQLite file (`test_mini_siem.db`), so they don't touch
your actual `mini_siem.db`. This is done by overriding `MINI_SIEM_DATABASE_URL` at the
top of `tests/conftest.py` before anything from `app/` gets imported. No external
services, no Postgres, nothing extra to install.


## Some decisions I made and why

- **SQLAlchemy instead of raw `sqlite3`.** Mostly because building the API filters
  (severity, status, ip, date range, text search, all combinable) by hand-concatenating
  SQL strings sounded like a good way to accidentally introduce a SQL injection bug.
  With SQLAlchemy's `select().where(...)` everything stays parameterized automatically.
- **Pydantic schemas are separate from the SQLAlchemy models.** The models describe the
  DB tables, the schemas describe what the API accepts/returns. E.g. `AlertUpdate` only
  exposes the `status` field for PATCH requests, and severities/statuses use `Literal`
  types so invalid values get rejected before any of my code even runs.
- **Parsers and the detection engine don't touch the database directly** - they work
  with plain dataclasses (`ParsedEvent`, `Rule`). That made it a lot easier to write
  fast unit tests without spinning up a DB for every single parsing test.
- **Rules have a `type` field** (`threshold_count`, `unique_count`, `time_window`,
  `immediate`) instead of one giant if/elif per rule name. Adding another "count X
  events per IP" rule later is just a new YAML entry, no engine code changes needed.
- **Duplicate alert prevention:** before creating an alert, the engine checks whether
  the events involved are already linked to an alert of the same type. If none of them
  are new, it skips creating another alert. This matters because `/api/logs/analyze`
  can be run repeatedly on the same data without spamming duplicate alerts every time.
- **Separate database for tests.** `DATABASE_URL` reads from an env var
  (`MINI_SIEM_DATABASE_URL`) with a fallback to the normal `mini_siem.db`, so pytest can
  point at a throwaway file instead of wiping your real data every test run.
- **No real/sensitive log data anywhere.** All IPs in the sample logs are from the
  ranges reserved for documentation (RFC 5737 / TEST-NET), not real addresses.

## API overview

| Endpoint | What it does |
|---|---|
| `GET /api/events` | List events, filter by `source_ip`, `event_type`, `username`, `path`, `since`, `until`, `q` |
| `GET /api/events/{id}` | Get one event |
| `GET /api/alerts` | List alerts, filter by `severity`, `status`, `alert_type`, `source_ip`, `since`, `until`, `q` |
| `GET /api/alerts/{id}` | Get one alert |
| `PATCH /api/alerts/{id}` | Change alert status (`OPEN` / `ACKNOWLEDGED` / `RESOLVED`) |
| `POST /api/logs/upload` | Upload + parse + save + analyze a log file |
| `POST /api/logs/analyze` | Re-run detection over everything already stored |
| `POST /api/logs/load-samples` | Load the bundled sample logs |
| `GET /api/stats` | Dashboard numbers |
| `GET /api/export/json?dataset=alerts\|events` | Export as JSON |
| `GET /api/export/csv?dataset=alerts\|events` | Export as CSV |

## Known limitations

I want to be upfront about the stuff that's simplified/not perfect here:

- Timestamps are stored as naive datetimes (no real timezone handling). Fine for a
  local single-user tool, would need fixing for anything real.
- Uploading the same log file twice creates duplicate `Event` rows (new IDs each time),
  so you can get duplicate alerts if you upload the exact same file twice. The dedup
  logic only prevents duplicates for events that are already in the DB across multiple
  detection runs, not across multiple uploads of identical content.
- The "port scan" rule only looks at different HTTP paths in the logs, it has nothing
  to do with actual network-level port scanning (this project never touches raw
  network traffic, only log files).
- The auto-detection for log type is a one-line heuristic (checks for `" - - ["` in the
  first line). Works for the two formats supported here, would need to be smarter to
  support more log formats.
