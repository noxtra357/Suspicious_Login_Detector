import unittest
from pathlib import Path

from detector import Config, analyze, parse_log

SAMPLE = Path(__file__).with_name("sample_logins.csv")


class SampleLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        events, skipped = parse_log(SAMPLE.read_text(encoding="utf-8-sig"))
        cls.events = events
        cls.report = analyze(events, Config(), skipped)

    def rules_for(self, user):
        return {f.rule for f in self.report.findings if f.user == user}

    def test_totals(self):
        self.assertEqual(len(self.events), 42)
        self.assertEqual(self.report.users, 5)
        self.assertEqual(len(self.report.findings), 12)

    def test_bruteforce_and_success_after_failures(self):
        self.assertTrue({"brute", "afterfail"} <= self.rules_for("m.petrov"))

    def test_impossible_travel(self):
        self.assertIn("travel", self.rules_for("a.ivanova"))

    def test_slow_trip_is_not_impossible(self):
       
        self.assertNotIn("travel", self.rules_for("m.petrov"))

    def test_password_spraying_attributed_to_ip(self):
        spray = [f for f in self.report.findings if f.rule == "spray"]
        self.assertEqual(len(spray), 1)
        self.assertEqual(spray[0].subject, "IP 198.51.100.23")
        self.assertIsNone(spray[0].user)

    def test_many_addresses(self):
        self.assertIn("manyip", self.rules_for("s.karimova"))

    def test_night_login(self):
        self.assertIn("night", self.rules_for("admin"))

    def test_single_typo_is_not_suspicious(self):
        self.assertEqual(self.rules_for("d.nurlan"), set())
        self.assertIn("d.nurlan", self.report.clean)

    def test_risk_ranking(self):
        scores = {s.user: s for s in self.report.scores}
        self.assertEqual(self.report.scores[0].user, "m.petrov")
        self.assertEqual(scores["m.petrov"].score, 100)
        self.assertEqual(scores["a.ivanova"].level, "high")
        self.assertEqual(scores["s.karimova"].level, "medium")
        self.assertEqual(scores["admin"].level, "low")

    def test_thresholds_are_respected(self):
        cfg = Config(speed_kmh=20000)
        report = analyze(self.events, cfg)
        self.assertNotIn("travel", {f.rule for f in report.findings})
        cfg = Config(fails=11)
        report = analyze(self.events, cfg)
        self.assertNotIn("brute", {f.rule for f in report.findings})


class ParsingTests(unittest.TestCase):
    def test_semicolons_russian_headers_and_dates(self):
        text = (
            "Дата и время;Логин;IP-адрес;Страна;Результат;Устройство\n"
            "24.10.2026 03:18:20;ivan;192.0.2.1;Россия;успех;Chrome\n"
            "24.10.2026 03:19:00;ivan;192.0.2.1;Россия;ошибка;Chrome\n"
        )
        events, skipped = parse_log(text)
        self.assertEqual(skipped, 0)
        self.assertEqual([e.ok for e in events], [True, False])
        self.assertEqual(events[0].country, "RU")
        self.assertEqual(events[0].hour, 3)

    def test_default_column_order_without_header(self):
        events, _ = parse_log("2026-10-24 10:00:00,anna,192.0.2.1,NL,success,Firefox\n")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].user, "anna")

    def test_bad_rows_are_counted(self):
        text = (
            "time,user,ip,country,result,device\n"
            "2026-10-24 10:00:00,anna,192.0.2.1,NL,success,Firefox\n"
            "вчера,anna,192.0.2.1,NL,success,Firefox\n"
            "2026-10-24 10:05:00,anna,192.0.2.1,NL,возможно,Firefox\n"
        )
        events, skipped = parse_log(text)
        self.assertEqual(len(events), 1)
        self.assertEqual(skipped, 2)

    def test_unknown_columns_raise(self):
        with self.assertRaises(ValueError):
            parse_log("foo,bar,baz\n1,2,3\n")

    def test_timezone_offsets(self):
        text = (
            "time,user,ip,country,result,device\n"
            "2026-10-24T10:00:00+06:00,anna,192.0.2.1,KG,success,Chrome\n"
            "2026-10-24T04:00:00Z,anna,192.0.2.1,KG,success,Chrome\n"
        )
        events, _ = parse_log(text)
        self.assertEqual(events[0].t, events[1].t)


if __name__ == "__main__":
    unittest.main()
