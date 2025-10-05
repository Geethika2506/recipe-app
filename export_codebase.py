# export_codebase.py
import os

PROJECT_ROOT = "."
OUTPUT_FILE = "codebase.md"  # use Markdown for better PDF formatting
INCLUDE_EXTS = (".py", ".html", ".css", ".js", ".json", ".yml", ".sql", ".md", ".txt")

SKIP_CONTAINS = [".git", "__pycache__", "venv", ".venv", "env", "node_modules"]
SKIP_FILES = [".env", ".env.local", ".env.production"]

def should_skip_path(path):
    for s in SKIP_CONTAINS:
        if s in path:
            return True
    return False

with open(OUTPUT_FILE, "w", encoding="utf-8", errors="replace") as out:
    out.write("# 📦 Project Codebase Export\n")
    out.write("Generated automatically by export_codebase.py\n\n")

    for root, dirs, files in os.walk(PROJECT_ROOT):
        if should_skip_path(root):
            continue

        rel_path = os.path.relpath(root, PROJECT_ROOT)
        if rel_path == ".":
            rel_path = "Root"

        out.write(f"\n\n## 📁 {rel_path}\n\n")

        for file in sorted(files):
            if file in SKIP_FILES:
                out.write(f"🚫 Skipped secret file: `{file}`\n")
                continue

            if not file.lower().endswith(INCLUDE_EXTS):
                continue

            filepath = os.path.join(root, file)
            try:
                out.write(f"\n### 📄 {file}\n\n")
                out.write("```" + filepath.split(".")[-1] + "\n")  # code block start
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    out.write(f.read())
                out.write("\n```\n")  # code block end
            except Exception as e:
                out.write(f"⚠️ Could not read {filepath}: {e}\n")

print(f"✅ Export complete → {OUTPUT_FILE}")
print("Next step: run pandoc to make the PDF.")
