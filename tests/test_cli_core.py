import csv

from cli import main


def test_tvla_cli(tmp_path):
    path = tmp_path / "timings.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["class0_ns", "class1_ns"])
        writer.writeheader()
        for a, b in [(10, 10), (11, 11), (9, 9), (10, 10)]:
            writer.writerow({"class0_ns": a, "class1_ns": b})
    assert main(["tvla", str(path)]) == 0


def test_scan_cli_returns_nonzero_for_finding(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "def f(secret, x):\n    if secret == x:\n        return True\n    return False\n",
        encoding="utf-8",
    )
    assert main(["scan", str(source)]) == 1
