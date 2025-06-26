"""
ato_cli/cli.py
─────────────────────────────────────────────────────────────────────────
Strict folder-scanner MVP

Implemented controls
  • SC-12  – Encryption in transit  (TLS / HTTPS)
  • AC-2   – Account management     (user-creation)
  • SC-13  – Encryption at rest     (AES / KMS / key-vault)
  • CM-2   – Baseline configuration (config files present)

Outputs
  <base>.txt / .md / .json / _oscal.json
"""

from __future__ import annotations
import os, re, json, uuid, pathlib, click
from openai import OpenAI

# ────────────────────────── CONFIG ──────────────────────────────────────
SCAN_EXTS = {
    ".py", ".tf", ".yml", ".yaml",          # Python / Terraform / YAML
    ".java", ".js", ".mjs", ".ts", ".tsx",  # Java / JS / TS
    ".r", ".R",                             # R scripts
    ".conf", ".ini", ".cfg", ".json",       # config/baseline files (for CM-2)
}

MODEL = os.getenv("OPENAI_MODEL", "placeholder")   # gpt-4o, gpt-3.5-turbo, etc.


# ────────────────────────── GPT CLIENT ──────────────────────────────────
def get_openai_client():
    if MODEL == "placeholder":
        return None
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError(
            "OPENAI_MODEL is set but OPENAI_API_KEY is missing.\n"
            "Export OPENAI_API_KEY or set OPENAI_MODEL=placeholder."
        )
    return OpenAI(api_key=key)


client = get_openai_client()


def chat(prompt: str, *, temp=0.3, max_tokens=200) -> str:
    if MODEL == "placeholder":
        return "[GPT disabled]"
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=temp,
        max_tokens=max_tokens,
    )
    return resp.choices[0].message.content.strip()


def gpt_ssp(control_id: str, code: str, status: str) -> str:
    return chat(
        f"Write an SSP narrative for NIST control {control_id}. "
        f"Compliance={status}. Code sample:\n{code[:1000]}"
    )


def gpt_fix(control_id: str, code: str) -> str:
    return chat(
        f"Suggest a remediation to comply with NIST control {control_id}:\n{code[:1000]}",
        temp=0.4,
        max_tokens=150,
    )


# ────────────────────────── HELPER FUNCTIONS ────────────────────────────
def collect_paths(target: str) -> list[pathlib.Path]:
    """Return all files (recursively) whose suffix is in SCAN_EXTS."""
    p = pathlib.Path(target)
    if p.is_file():
        return [p]
    return [f for f in p.rglob("*") if f.suffix in SCAN_EXTS]


def scan_file(path: pathlib.Path) -> tuple[dict, str]:
    """Scan one file and return a dict of control results + code snippet."""
    code = path.read_text(encoding="utf-8", errors="ignore")
    res: dict[str, dict] = {}

    # ── SC-12  Encryption in transit ────────────────────────────────────
    tls_hit = "https://" in code or re.search(r"tls1\.[2-3]", code, re.I)
    res["SC-12"] = {
        "file": str(path),
        "status": "compliant" if tls_hit else "not compliant",
        "reason": "Found HTTPS/TLS use" if tls_hit else "No HTTPS or TLS detected",
        "suggestion": "Use TLS 1.2+ or secure endpoints" if not tls_hit else None,
    }

    # ── AC-2  Account management ───────────────────────────────────────
    ac2_hit = re.search(
        r"(create[_A-Z]?user|add[_A-Z]?user|useradd|new[_A-Z]?user|"
        r"createUser|addUser|registerUser|user\.create|Users\.insert)",
        code,
        re.I,
    )
    res["AC-2"] = {
        "file": str(path),
        "status": "compliant" if ac2_hit else "not compliant",
        "reason": "Found user-creation logic" if ac2_hit else "No account-management found",
        "suggestion": "Implement user provisioning (e.g., create_user)" if not ac2_hit else None,
    }

    # ── SC-13  Encryption at rest ───────────────────────────────────────
    enc_hit = re.search(
        r"(aes[-_]?(128|192|256)|encrypt\(|kms|key[_-]?vault|diskEncryption|EnableEncryption)",
        code,
        re.I,
    )
    res["SC-13"] = {
        "file": str(path),
        "status": "compliant" if enc_hit else "not compliant",
        "reason": "Detected encryption-at-rest logic"
        if enc_hit
        else "No encryption-at-rest code found",
        "suggestion": (
            "Use AES-256, a managed KMS key, or a cloud key-vault service "
            "to encrypt data at rest"
            if not enc_hit
            else None
        ),
    }

    # ── CM-2  Baseline configuration present ───────────────────────────
    cm2_hit = path.suffix in {".conf", ".ini", ".cfg"} or "baseline" in str(path).lower()
    res["CM-2"] = {
        "file": str(path),
        "status": "compliant" if cm2_hit else "not compliant",
        "reason": "Found baseline configuration file"
        if cm2_hit
        else "No baseline configuration file detected",
        "suggestion": (
            "Add or document a secured baseline configuration "
            "(e.g., .conf / .ini file)"
            if not cm2_hit
            else None
        ),
    }

    return res, code[:1000]


def consolidate(file_reports):
    """Strict: any failing file flips control to NOT COMPLIANT, record all failures."""
    merged: dict[str, dict] = {}
    for file_rep in file_reports:
        for cid, r in file_rep.items():
            merged.setdefault(
                cid,
                {
                    "control": cid,
                    "status": "compliant",
                    "reason": "All scanned files passed.",
                    "failures": [],
                },
            )
            if r["status"] == "not compliant":
                merged[cid]["status"] = "not compliant"
                merged[cid]["reason"] = r["reason"]
                if r.get("suggestion"):
                    merged[cid]["suggestion"] = r["suggestion"]
                merged[cid]["failures"].append(
                    {"file": r["file"], "reason": r["reason"]}
                )
    return merged


def write_oscal(results: dict, out_path: str):
    """Save a minimal OSCAL SSP JSON."""
    import datetime
    import os
    # Ensure output directory exists
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    ssp = {
        "oscal-version": "1.1.0",
        "system-security-plan": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "ATO CLI SSP",
                "last-modified": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            },
            "control-implementation": {
                "components": [
                    {
                        "component-uuid": "comp-1",
                        "type": "software",
                        "title": "ATO CLI Pilot",
                        "implemented-requirements": [],
                    }
                ]
            },
        }
    }
    impl = (
        ssp["system-security-plan"]["control-implementation"]["components"][0][
            "implemented-requirements"
        ]
    )
    for cid, r in results.items():
        entry = {
            "control-id": cid,
            "description": r["reason"],
            "props": [{"name": "status", "value": r["status"]}],
        }
        if "suggestion" in r:
            entry["remarks"] = r["suggestion"]
        impl.append(entry)
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(ssp, fp, indent=2)


# ───────────────────────────── CLI ENTRY ────────────────────────────────
@click.command()
@click.option("-i", "--input", required=True, help="File or directory to scan")
@click.option("-o", "--output", default="report", show_default=True, help="Output file base name")
@click.option("--gpt",   is_flag=True, help="Add GPT SSP & remediation text")
@click.option("--quiet", is_flag=True, help="One-line summary per control")
def main(input: str, output: str, gpt: bool, quiet: bool):
    paths = collect_paths(input)
    if not paths:
        click.echo("No scannable files found.")
        return

    # per-file scanning
    file_reports, snippets = [], ""
    for p in paths:
        report, code = scan_file(p)
        file_reports.append(report)
        snippets += code  # for GPT context

    results = consolidate(file_reports)

    # GPT enrichment
    if gpt and MODEL != "placeholder":
        click.echo("\n🧠  GPT enabled – generating SSP text …")
        for cid, r in results.items():
            r["ssp_text"] = gpt_ssp(cid, snippets, r["status"])
            if r["status"] == "not compliant":
                r["gpt_suggestion"] = gpt_fix(cid, snippets)
    elif gpt:
        click.echo("⚠️  GPT flag set but MODEL='placeholder' – skipping GPT calls.")

    # Terminal output
    if quiet:
        for cid, r in results.items():
            click.echo(f"{cid}: {'PASS' if r['status']=='compliant' else 'FAIL'}")
    else:
        click.echo("\nScan Results:")
        for cid, r in results.items():
            icon = "✔️" if r["status"] == "compliant" else "❌"
            click.echo(f"{icon} {cid}: {r['status'].upper()} – {r['reason']}")
            for fail in r["failures"]:
                click.echo(f"    ✖ {fail['file']}  →  {fail['reason']}")
            if "ssp_text" in r:
                click.echo(f"    📘 SSP: {r['ssp_text']}")
            if "gpt_suggestion" in r:
                click.echo(f"    💡 Fix: {r['gpt_suggestion']}")

    # Write reports -------------------------------------------------------
    with open(f"{output}.txt", "w", encoding="utf-8") as f_txt:
        for cid, r in results.items():
            f_txt.write(f"{cid}: {r['status']} – {r['reason']}\n")
            for fail in r["failures"]:
                f_txt.write(f"    ✖ {fail['file']}  →  {fail['reason']}\n")

    with open(f"{output}.md", "w", encoding="utf-8") as f_md:
        f_md.write("# ATO Compliance Scan Results\n\n")
        for cid, r in results.items():
            icon = "✅" if r["status"] == "compliant" else "❌"
            f_md.write(f"## {cid}\n{icon} **{r['status'].upper()}** – {r['reason']}\n\n")
            if "suggestion" in r:
                f_md.write(f"🛠️ Suggestion: {r['suggestion']}\n\n")
            if r["failures"]:
                f_md.write("**Failing files:**\n")
                for fail in r["failures"]:
                    f_md.write(f"- `{fail['file']}` – {fail['reason']}\n")
                f_md.write("\n")
            if "ssp_text" in r:
                f_md.write(f"📘 SSP:\n> {r['ssp_text']}\n\n")
            if "gpt_suggestion" in r:
                f_md.write(f"💡 GPT Fix:\n> {r['gpt_suggestion']}\n\n")

    with open(f"{output}.json", "w", encoding="utf-8") as fp_json:
        json.dump({"results": list(results.values())}, fp_json, indent=2)

    write_oscal(results, f"{output}/ci_report_oscal.json")
    click.echo(f"\n📄  Saved: {output}.txt  {output}.md  {output}.json")
    click.echo(f"🗄  OSCAL saved: {output}/ci_report_oscal.json")


if __name__ == "__main__":
    main()
