# tests/test_scan.py
import subprocess, json, pathlib

def test_folder_scan(tmp_path):
    # Build demo project
    demo = tmp_path / "proj"
    demo.mkdir()
    (demo / "good.py").write_text(
        "import requests\n"
        "requests.get('https://x.com', verify=True)\n"
        "def create_user(name): pass\n"
    )
    (demo / "bad.py").write_text(
        'url = "http://example.com"\nprint(url)\n'
    )

    # Run the installed console script
    out_base = tmp_path / "scan_out"
    subprocess.run(
        ["ato-scan", "-i", str(demo), "-o", str(out_base)],
        check=True,
    )

    # Validate results
    data = json.loads((out_base.with_suffix(".json")).read_text())
    status = {item["control"]: item["status"] for item in data["results"]}
    assert status["SC-12"] == "not compliant"
    assert status["AC-2"] == "not compliant"
