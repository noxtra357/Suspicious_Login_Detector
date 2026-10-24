"""Детектор подозрительных входов"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Справочники
# ---------------------------------------------------------------------------

SEVERITY = {
    "high": {"label": "Высокий", "points": 40, "rank": 3},
    "medium": {"label": "Средний", "points": 20, "rank": 2},
    "low": {"label": "Низкий", "points": 8, "rank": 1},
}

RULES = {
    "brute": {
        "name": "Перебор пароля",
        "act": "Сбросьте пароль, включите блокировку после серии неудач и проверьте, был ли после неё успешный вход.",
    },
    "afterfail": {
        "name": "Вход после серии неудач",
        "act": "Считайте учётную запись скомпрометированной: смените пароль, завершите активные сессии, проверьте действия после входа.",
    },
    "spray": {
        "name": "Распыление паролей",
        "act": "Заблокируйте адрес и проверьте все перечисленные учётные записи на успешные входы с него.",
    },
    "travel": {
        "name": "Невозможное перемещение",
        "act": "Спросите владельца. Если он не путешествовал и не использует VPN, завершите сессии и смените пароль.",
    },
    "newcountry": {
        "name": "Новая страна",
        "act": "Уточните у владельца, был ли это он. Включите подтверждение входа из новых стран.",
    },
    "newdevice": {
        "name": "Новое устройство",
        "act": "Если вход не похож на привычки владельца, запросите повторное подтверждение.",
    },
    "night": {
        "name": "Ночной вход",
        "act": "Сверьте с рабочим графиком владельца. Сам по себе это слабый признак.",
    },
    "manyip": {
        "name": "Много адресов за час",
        "act": "Проверьте, не передан ли доступ другим людям и не идёт ли вход через прокси или нестабильную сеть.",
    },
}

# код: (название по-русски, название по-английски, широта, долгота центра страны)
COUNTRIES = {
    "NL": ("Нидерланды", "Netherlands", 52.2, 5.5),
    "DE": ("Германия", "Germany", 51.2, 10.4),
    "FR": ("Франция", "France", 46.6, 2.2),
    "GB": ("Великобритания", "United Kingdom", 54.0, -2.5),
    "ES": ("Испания", "Spain", 40.2, -3.6),
    "IT": ("Италия", "Italy", 42.8, 12.5),
    "PL": ("Польша", "Poland", 52.1, 19.4),
    "SE": ("Швеция", "Sweden", 62.0, 15.0),
    "UA": ("Украина", "Ukraine", 49.0, 31.4),
    "BY": ("Беларусь", "Belarus", 53.7, 27.9),
    "RO": ("Румыния", "Romania", 45.9, 24.9),
    "TR": ("Турция", "Turkey", 39.0, 35.2),
    "RU": ("Россия", "Russia", 61.5, 99.0),
    "KZ": ("Казахстан", "Kazakhstan", 48.0, 67.0),
    "KG": ("Киргизия", "Kyrgyzstan", 41.5, 74.6),
    "UZ": ("Узбекистан", "Uzbekistan", 41.4, 64.6),
    "GE": ("Грузия", "Georgia", 42.2, 43.5),
    "AM": ("Армения", "Armenia", 40.3, 44.9),
    "AZ": ("Азербайджан", "Azerbaijan", 40.3, 47.7),
    "IR": ("Иран", "Iran", 32.4, 53.7),
    "AE": ("ОАЭ", "United Arab Emirates", 24.3, 54.3),
    "EG": ("Египет", "Egypt", 26.8, 30.0),
    "NG": ("Нигерия", "Nigeria", 9.1, 8.7),
    "ZA": ("ЮАР", "South Africa", -29.0, 24.7),
    "IN": ("Индия", "India", 22.9, 79.6),
    "CN": ("Китай", "China", 35.0, 103.0),
    "JP": ("Япония", "Japan", 36.6, 138.0),
    "KR": ("Южная Корея", "South Korea", 36.4, 127.8),
    "VN": ("Вьетнам", "Vietnam", 16.0, 106.3),
    "TH": ("Таиланд", "Thailand", 15.1, 101.0),
    "SG": ("Сингапур", "Singapore", 1.35, 103.8),
    "ID": ("Индонезия", "Indonesia", -2.2, 117.3),
    "AU": ("Австралия", "Australia", -25.7, 134.5),
    "US": ("США", "United States", 39.8, -98.6),
    "CA": ("Канада", "Canada", 56.1, -106.3),
    "MX": ("Мексика", "Mexico", 23.9, -102.5),
    "BR": ("Бразилия", "Brazil", -14.2, -51.9),
    "AR": ("Аргентина", "Argentina", -35.4, -65.2),
}

COUNTRY_BY_NAME: Dict[str, str] = {}
for _code, _v in COUNTRIES.items():
    COUNTRY_BY_NAME[_v[0].lower()] = _code
    COUNTRY_BY_NAME[_v[1].lower()] = _code

# Названия столбцов, которые понимает парсер (в нормализованном виде).
SYNONYMS = {
    "time": ["time", "timestamp", "date", "datetime", "время", "дата", "датаивремя"],
    "user": ["user", "username", "login", "account", "email", "пользователь", "логин", "учетнаязапись"],
    "ip": ["ip", "ipaddress", "адрес", "ipадрес"],
    "country": ["country", "страна", "geo"],
    "result": ["result", "status", "outcome", "результат", "статус"],
    "device": ["device", "useragent", "ua", "устройство", "клиент"],
}
DEFAULT_ORDER = ["time", "user", "ip", "country", "result", "device"]

SUCCESS_WORDS = {"success", "succeeded", "ok", "pass", "allowed", "1", "true", "успех", "успешно", "да"}
FAIL_WORDS = {
    "fail", "failed", "failure", "error", "denied", "blocked", "invalid",
    "0", "false", "ошибка", "неудача", "неуспешно", "отказ", "нет",
}


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------

@dataclass
class LoginEvent:
    t: float        # время в секундах (Unix)
    hour: int       # час так, как он записан в журнале
    ts: str         # время строкой из журнала
    user: str
    ip: str
    country: str
    device: str
    ok: bool        # True: успешный вход, False: неудачный


@dataclass
class Config:
    fails: int = 5               # неудач для «перебора пароля»
    window_min: int = 10         # окно серии, минут
    spray: int = 4               # логинов с одного IP для «распыления паролей»
    speed_kmh: float = 900.0     # предельная скорость перемещения


@dataclass
class Finding:
    rule: str
    severity: str
    t: float
    ts: str
    subject: str                 # логин или «IP x.x.x.x»
    user: Optional[str]
    ip: str
    country: str
    text: str

    @property
    def title(self) -> str:
        return RULES[self.rule]["name"]


@dataclass
class UserScore:
    user: str
    score: int
    level: str
    count: int


@dataclass
class Report:
    events: int
    skipped: int
    users: int
    findings: List[Finding]
    scores: List[UserScore]
    clean: List[str]


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def plural(n: int, forms: Tuple[str, str, str]) -> str:
    """plural(3, ('вход', 'входа', 'входов')) -> 'входа'"""
    a = abs(n) % 100
    b = a % 10
    if 10 < a < 20:
        return forms[2]
    if 1 < b < 5:
        return forms[1]
    if b == 1:
        return forms[0]
    return forms[2]


def fmt_duration(seconds: float) -> str:
    m = max(1, round(seconds / 60))
    if m < 60:
        return f"{m} мин"
    h, r = divmod(m, 60)
    return f"{h} ч" + (f" {r} мин" if r else "")


def fmt_num(x: float) -> str:
    return f"{round(x):,}".replace(",", " ")


def level_for(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def haversine_km(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    r = 6371.0
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def normalize_country(raw: str) -> str:
    s = raw.strip()
    if not s:
        return ""
    if re.fullmatch(r"[A-Za-z]{2}", s):
        return s.upper()
    return COUNTRY_BY_NAME.get(s.lower(), s)


def country_label(code: str) -> str:
    if code in COUNTRIES:
        return f"{code} ({COUNTRIES[code][0]})"
    return code


def parse_time(s: str) -> Optional[Tuple[float, int]]:
    """Возвращает (секунды, час из записи) или None, если формат не распознан.

    Понимает «2026-10-24 03:18:20», «2026-10-24T03:18:20+06:00» и «24.10.2026 03:18».
    Время без часового пояса считается одним и тем же поясом для всех записей.
    """
    s = s.strip()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})", s)
    if m:
        x = s.replace(" ", "T", 1)
        if x[-1] in "Zz":
            x = x[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(x)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp(), int(m.group(4))
    m = re.match(r"^(\d{2})\.(\d{2})\.(\d{4})[T ](\d{2}):(\d{2})(?::(\d{2}))?$", s)
    if m:
        d, mo, y, h, mi, sec = m.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec or 0), tzinfo=timezone.utc)
        except ValueError:
            return None
        return dt.timestamp(), int(h)
    return None


def parse_result(v: str) -> Optional[bool]:
    v = v.strip().lower()
    if v in SUCCESS_WORDS:
        return True
    if v in FAIL_WORDS:
        return False
    return None


def _norm_header(s: str) -> str:
    return re.sub(r"[\s_\-]+", "", s.lower().replace("ё", "е"))


# ---------------------------------------------------------------------------
# Чтение журнала
# ---------------------------------------------------------------------------

def parse_log(text: str) -> Tuple[List[LoginEvent], int]:
    """Разбирает CSV. Возвращает (события по времени, число пропущенных строк).

    Бросает ValueError, если не удалось понять, где какой столбец.
    """
    lines = [ln for ln in text.lstrip("﻿").splitlines() if ln.strip()]
    if not lines:
        return [], 0

    delimiter = max([",", ";", "\t"], key=lambda d: lines[0].count(d))
    rows = list(csv.reader(lines, delimiter=delimiter, skipinitialspace=True))

    head = [_norm_header(c) for c in rows[0]]

    def find(keys: List[str]) -> int:
        for i, h in enumerate(head):
            if h in keys:
                return i
        return -1

    idx = {name: find(keys) for name, keys in SYNONYMS.items()}
    if idx["time"] >= 0 and idx["user"] >= 0 and idx["result"] >= 0:
        start = 1
    elif parse_time(rows[0][0]) is not None:
        idx = {name: i for i, name in enumerate(DEFAULT_ORDER)}
        start = 0
    else:
        raise ValueError(
            "Не нашёл столбцы времени, логина и результата. "
            "Добавьте строку заголовков, например: time,user,ip,country,result,device"
        )

    def get(row: List[str], name: str) -> str:
        i = idx[name]
        return row[i].strip() if 0 <= i < len(row) else ""

    events: List[LoginEvent] = []
    skipped = 0
    for row in rows[start:]:
        parsed = parse_time(get(row, "time"))
        ok = parse_result(get(row, "result"))
        user = get(row, "user")
        if parsed is None or ok is None or not user:
            skipped += 1
            continue
        events.append(LoginEvent(
            t=parsed[0], hour=parsed[1], ts=get(row, "time"), user=user,
            ip=get(row, "ip"), country=normalize_country(get(row, "country")),
            device=get(row, "device"), ok=ok,
        ))
    events.sort(key=lambda e: e.t)
    return events, skipped


# ---------------------------------------------------------------------------
# Анализ
# ---------------------------------------------------------------------------

def analyze(events: List[LoginEvent], cfg: Optional[Config] = None, skipped: int = 0) -> Report:
    cfg = cfg or Config()
    window = cfg.window_min * 60
    findings: List[Finding] = []

    by_user: Dict[str, List[LoginEvent]] = defaultdict(list)
    fails_by_ip: Dict[str, List[LoginEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda x: x.t):
        by_user[e.user].append(e)
        if not e.ok and e.ip:
            fails_by_ip[e.ip].append(e)

    def add(rule: str, severity: str, e: LoginEvent, text: str,
            ip: Optional[str] = None, spray: bool = False) -> None:
        findings.append(Finding(
            rule=rule, severity=severity, t=e.t, ts=e.ts,
            subject=f"IP {e.ip}" if spray else e.user,
            user=None if spray else e.user,
            ip=e.ip if ip is None else ip, country=e.country, text=text,
        ))

    for user, items in by_user.items():
        fails = [e for e in items if not e.ok]
        succ = [e for e in items if e.ok]

        # Перебор пароля: много неудач за короткое окно
        i = 0
        while i < len(fails):
            j = i
            while j + 1 < len(fails) and fails[j + 1].t - fails[i].t <= window:
                j += 1
            n = j - i + 1
            if n >= cfg.fails:
                group = fails[i:j + 1]
                ips = list(dict.fromkeys(x.ip for x in group if x.ip))
                last = group[-1]
                text = (
                    f"{n} {plural(n, ('неудачный вход', 'неудачных входа', 'неудачных входов'))} "
                    f"за {fmt_duration(last.t - group[0].t)}"
                )
                if ips:
                    text += f" с {'адресов' if len(ips) > 1 else 'адреса'} {', '.join(ips[:3])}"
                add("brute", "high" if n >= cfg.fails * 2 else "medium", last, text + ".", ip=", ".join(ips))
                i = j + 1
            else:
                i += 1

        # Успешный вход вскоре после серии неудач
        for e in succ:
            recent = [f for f in fails if f.t <= e.t and e.t - f.t <= 15 * 60]
            if len(recent) >= 3:
                same_ip = any(f.ip and f.ip == e.ip for f in recent)
                k = len(recent)
                text = (
                    f"Успешный вход через {fmt_duration(e.t - recent[-1].t)} после {k} "
                    f"{plural(k, ('неудачной попытки', 'неудачных попыток', 'неудачных попыток'))}"
                    + (", в том числе с того же адреса." if same_ip else ".")
                )
                add("afterfail", "high", e, text)

        # Новая страна и новое устройство (нужно хотя бы три успешных входа в прошлом)
        seen_countries: Dict[str, None] = {}
        seen_devices = set()
        for prior, e in enumerate(succ):
            if prior >= 3:
                if e.country and e.country not in seen_countries:
                    known = ", ".join(country_label(c) for c in seen_countries)
                    add("newcountry", "medium", e,
                        f"Первый вход из страны {country_label(e.country)}. До этого учётная запись входила из {known}.")
                if e.device and e.device.lower() not in seen_devices:
                    add("newdevice", "low", e,
                        f"Устройство «{e.device}» раньше не встречалось у этой учётной записи.")
            if e.country:
                seen_countries.setdefault(e.country, None)
            if e.device:
                seen_devices.add(e.device.lower())

        # Невозможное перемещение между соседними успешными входами
        for a, b in zip(succ, succ[1:]):
            if not a.country or not b.country or a.country == b.country:
                continue
            dt = b.t - a.t
            ca, cb = COUNTRIES.get(a.country), COUNTRIES.get(b.country)
            if ca and cb:
                dist = haversine_km(ca[2:], cb[2:])
                speed = dist / max(dt / 3600, 1 / 60)
                if dist >= 300 and speed > cfg.speed_kmh:
                    add("travel", "high", b,
                        f"Вход из {country_label(a.country)}, через {fmt_duration(dt)} вход из {country_label(b.country)}. "
                        f"Расстояние около {fmt_num(round(dist, -1))} км, нужна скорость около "
                        f"{fmt_num(round(speed, -2))} км/ч при пороге {fmt_num(cfg.speed_kmh)}.")
            elif dt <= 3600:
                add("travel", "medium", b,
                    f"Вход из {country_label(a.country)}, через {fmt_duration(dt)} вход из {country_label(b.country)}. "
                    "Расстояние оценить нельзя: одна из стран не распознана.")

        # Ночные входы
        for e in succ:
            if e.hour < 5:
                add("night", "low", e, f"Успешный вход около {e.hour:02d}:00 по времени журнала.")

        # Много адресов за час
        i = 0
        while i < len(succ):
            j = i
            while j + 1 < len(succ) and succ[j + 1].t - succ[i].t <= 3600:
                j += 1
            ips = list(dict.fromkeys(x.ip for x in succ[i:j + 1] if x.ip))
            if len(ips) >= 3:
                n = len(ips)
                add("manyip", "medium", succ[j],
                    f"{n} {plural(n, ('разный адрес', 'разных адреса', 'разных адресов'))} "
                    f"за {fmt_duration(succ[j].t - succ[i].t)}: {', '.join(ips)}.",
                    ip=", ".join(ips))
                i = j + 1
            else:
                i += 1

    # Распыление паролей: один IP, много разных логинов
    for ip, items in fails_by_ip.items():
        i = 0
        while i < len(items):
            j = i
            while j + 1 < len(items) and items[j + 1].t - items[i].t <= window:
                j += 1
            users = list(dict.fromkeys(x.user for x in items[i:j + 1]))
            if len(users) >= cfg.spray:
                n = j - i + 1
                shown = ", ".join(users[:5]) + (" и другие." if len(users) > 5 else ".")
                add("spray", "high", items[j],
                    f"С одного адреса за {fmt_duration(items[j].t - items[i].t)} {n} "
                    f"{plural(n, ('неудачный вход', 'неудачных входа', 'неудачных входов'))} в {len(users)} "
                    f"{plural(len(users), ('учётную запись', 'учётные записи', 'учётных записей'))}: {shown}",
                    spray=True)
                i = j + 1
            else:
                i += 1

    findings.sort(key=lambda f: (-SEVERITY[f.severity]["rank"], -f.t))

    # Риск по учётным записям: первое срабатывание правила даёт полные баллы,
    # повторы того же правила половину. Максимум 100.
    scores: List[UserScore] = []
    for user in by_user:
        mine = sorted((f for f in findings if f.user == user), key=lambda f: f.t)
        if not mine:
            continue
        seen: Dict[str, int] = defaultdict(int)
        total = 0.0
        for f in mine:
            seen[f.rule] += 1
            pts = SEVERITY[f.severity]["points"]
            total += pts if seen[f.rule] == 1 else pts / 2
        score = min(100, round(total))
        scores.append(UserScore(user, score, level_for(score), len(mine)))
    scores.sort(key=lambda s: (-s.score, -s.count))

    scored = {s.user for s in scores}
    clean = [u for u in by_user if u not in scored]
    return Report(events=len(events), skipped=skipped, users=len(by_user),
                  findings=findings, scores=scores, clean=clean)


# ---------------------------------------------------------------------------
# Вывод
# ---------------------------------------------------------------------------

def render_text(report: Report, color: bool = False, min_level: str = "low") -> str:
    def paint(s: str, code: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    codes = {"high": "31;1", "medium": "33;1", "low": "34;1"}
    high_users = sum(1 for s in report.scores if s.level == "high")
    out: List[str] = [
        paint("Детектор подозрительных входов", "1"),
        f"Записей: {report.events} · учётных записей: {report.users} · "
        f"находок: {len(report.findings)} · высокий риск: {high_users}",
    ]
    if report.skipped:
        out.append(paint(
            f"Пропущено {report.skipped} {plural(report.skipped, ('строка', 'строки', 'строк'))}: "
            "не удалось разобрать время, логин или результат.", "33"))

    out += ["", paint("РЕЙТИНГ РИСКА", "1")]
    if report.scores:
        width = max(8, max(len(s.user) for s in report.scores))
        for s in report.scores:
            filled = round(s.score / 100 * 20)
            bar = "█" * filled + "░" * (20 - filled)
            out.append(f"  {s.user:<{width}}  {paint(bar, codes[s.level])} {s.score:>3}  {SEVERITY[s.level]['label']}")
    else:
        out.append("  Подозрительных учётных записей не найдено.")
    if report.clean:
        out.append(f"  Без находок: {', '.join(report.clean[:8])}"
                   + (f" и ещё {len(report.clean) - 8}" if len(report.clean) > 8 else ""))

    out += ["", paint("НАХОДКИ", "1")]
    min_rank = SEVERITY[min_level]["rank"]
    shown = [f for f in report.findings if SEVERITY[f.severity]["rank"] >= min_rank]
    if not shown:
        out.append("  Подозрительных входов не найдено. Проверка новой страны и устройства "
                   "работает, когда у учётной записи уже есть три успешных входа.")
    for f in shown:
        tag = paint(f"[{SEVERITY[f.severity]['label'].upper()}]", codes[f.severity])
        meta = " · ".join(x for x in (f.subject, f.ts, f.ip, f.country) if x)
        out += ["", f"{tag} {paint(f.title, '1')}", f"  {meta}", f"  {f.text}",
                f"  Что проверить: {RULES[f.rule]['act']}"]
    return "\n".join(out)


def report_to_dict(report: Report) -> dict:
    return {
        "events": report.events,
        "skipped": report.skipped,
        "users": report.users,
        "scores": [asdict(s) for s in report.scores],
        "clean": report.clean,
        "findings": [dict(asdict(f), title=f.title) for f in report.findings],
    }


# ---------------------------------------------------------------------------
# Консольный запуск
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Детектор подозрительных входов: анализ журнала входов в CSV.")
    p.add_argument("path", nargs="?", default=str(Path(__file__).with_name("sample_logins.csv")),
                   help="путь к CSV (по умолчанию sample_logins.csv рядом со скриптом)")
    p.add_argument("--fails", type=int, default=5, help="неудач для перебора пароля (5)")
    p.add_argument("--window", type=int, default=10, help="окно серии, минут (10)")
    p.add_argument("--spray", type=int, default=4, help="логинов с одного IP для распыления паролей (4)")
    p.add_argument("--speed", type=float, default=900.0, help="предельная скорость перемещения, км/ч (900)")
    p.add_argument("--min-level", choices=["low", "medium", "high"], default="low",
                   help="показывать находки не ниже этого уровня")
    p.add_argument("--json", action="store_true", help="вывести результат в JSON")
    p.add_argument("--color", action="store_true", help="принудительно включить цвета ANSI")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

    try:
        text = Path(args.path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        print(f"Не удалось прочитать файл: {exc}", file=sys.stderr)
        return 2
    try:
        events, skipped = parse_log(text)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not events:
        print("В журнале нет ни одной подходящей записи.", file=sys.stderr)
        return 2

    cfg = Config(fails=max(2, args.fails), window_min=max(1, args.window),
                 spray=max(2, args.spray), speed_kmh=max(100.0, args.speed))
    report = analyze(events, cfg, skipped)

    if args.json:
        print(json.dumps(report_to_dict(report), ensure_ascii=False, indent=2))
    else:
        print(render_text(report, color=args.color or sys.stdout.isatty(), min_level=args.min_level))
    return 0


if __name__ == "__main__":
    sys.exit(main())