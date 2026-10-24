# Suspicious Login Detector

A console program written in Python. It reads a login log in CSV format, flags the logins that look like an account takeover, and gives each account a risk score. It uses only the standard library, so there is nothing to install. Python 3.8 or newer is required.

The report text printed by the program is in Russian.

## Quick start in PyCharm

1. Create a project (New Project → Pure Python → Create) or open a folder with File → Open.
2. Put these files into the project folder, for example by dragging them into the Project tree:
   - `detector.py`
   - `sample_logins.csv` (optional demo data)
   - `test_detector.py` (optional tests)
3. Open the Terminal tool window (the `>_` icon) and run:

   ```
   python detector.py sample_logins.csv
   ```

   If `python` is not found, use `python3`.

4. Run it on your own log by passing your file name instead:

   ```
   python detector.py my_logins.csv
   ```

### Running with the green Run button

When the run selector at the top says "Current File", PyCharm has no place for parameters. Create a run configuration once:

1. Click the selector → Edit Configurations.
2. Click **+** and choose **Python**.
3. Set **Script** to `detector.py` and **Parameters** to `my_logins.csv`.
4. Click OK. The green triangle now runs the detector on your file.

For colored output in the Run window, enable "Emulate terminal in output console" in the same dialog, or add `--color` to the parameters.

### Running the tests

Right-click `test_detector.py` → Run 'Python tests in test_detector'. Or from the terminal:

```
python -m unittest -v
```

## Log format

Columns: time, user, IP, country, result, device. Time, user and result are required.

```
time,user,ip,country,result,device
2026-10-24 03:18:20,m.petrov,203.0.113.77,VN,success,Linux / curl
```

- **Delimiter:** comma, semicolon or tab.
- **Header row:** English or Russian names are understood, for example `time` / `timestamp` / `date`, `user` / `username` / `login` / `email`, `ip` / `ip_address`, `country`, `result` / `status`, `device` / `user_agent`. Without a header row, the column order shown above is assumed.
- **Time:** `2026-10-24 03:18:20`, `2026-10-24T03:18:20+06:00` or `24.10.2026 03:18`. Times without a time zone are treated as one shared zone.
- **Result:** `success` / `fail`. Also accepted: `ok` / `denied`, `1` / `0`, `true` / `false`, and the Russian words `успех` / `ошибка`.
- **Country:** a two-letter code (`NL`) or a country name in English or Russian. About 40 countries are built in.
- Rows that cannot be parsed are skipped and counted in the report.

## What the detector checks

| Rule | Triggers when | Severity |
|---|---|---|
| Password guessing (brute force) | 5 or more failed logins to one account within 10 minutes | medium, high at twice the threshold |
| Success after repeated failures | a successful login within 15 minutes after 3 or more failures | high |
| Password spraying | one IP fails against 4 or more different accounts within 10 minutes | high |
| Impossible travel | two logins from different countries that would need more than 900 km/h | high |
| New country | first login from a country after 3 successful logins | medium |
| New device | same, for the device | low |
| Many addresses in an hour | 3 or more different IPs within 60 minutes | medium |
| Night login | successful login between 00:00 and 05:00 in log time | low |

Distances are measured between country centers, so the estimate is rough for large countries. If a country is not in the built-in list, only a country change within one hour is flagged.

### Risk score

A high finding adds 40 points, medium 20, low 8. A repeat of the same rule adds half. The maximum is 100. A score of 60 or more is high risk, 25 or more is medium, anything lower is low.

## Command-line options

| Option | Default | Meaning |
|---|---|---|
| `path` | `sample_logins.csv` next to the script | CSV file to analyze |
| `--fails N` | 5 | failed logins that count as password guessing |
| `--window N` | 10 | length of the window for a series, in minutes |
| `--spray N` | 4 | accounts tried from one IP that count as spraying |
| `--speed N` | 900 | speed limit for impossible travel, km/h |
| `--min-level L` | low | show findings at this level or higher (`low`, `medium`, `high`) |
| `--json` | off | print the result as JSON |
| `--color` | off | force ANSI colors |

Example:

```
python detector.py my_logins.csv --fails 8 --speed 1000 --min-level medium
```

## Using it from your own code

```python
from detector import Config, analyze, parse_log

with open("my_logins.csv", encoding="utf-8-sig") as f:
    events, skipped = parse_log(f.read())

report = analyze(events, Config(fails=8), skipped)
for finding in report.findings:
    print(finding.severity, finding.title, finding.subject, finding.text)
```

## Troubleshooting

- **`No such file or directory: ...sample_logins.csv`**: you ran the script without a file name and the demo file is not in the project folder. Either copy `sample_logins.csv` into the folder or pass your own file, for example `python detector.py my_logins.csv`.
- **`Не нашёл столбцы времени, логина и результата`** (could not find the time, user and result columns): add a header row such as `time,user,ip,country,result,device`.
- **Empty table in PyCharm**: when a CSV opens in table mode and looks empty, switch to the **Text** tab at the bottom of the editor and paste the rows there. Save with Ctrl+S.
