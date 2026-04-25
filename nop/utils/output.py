import json
import os
from datetime import datetime

# default output directory
OUTPUT_DIR = os.path.expanduser("~/.nop/output")

def ensure_output_dir():
    # create output dir if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_json(command, target, data):
    ensure_output_dir()
    # build filename from command + target + timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    filename = f"{command}_{safe_target}_{timestamp}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)

    payload = {
        "command": command,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "result": data
    }

    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    return filepath

def save_txt(command, target, lines):
    ensure_output_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    filename = f"{command}_{safe_target}_{timestamp}.txt"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w") as f:
        f.write(f"# NOP — {command} — {target}\n")
        f.write(f"# {datetime.now().isoformat()}\n\n")
        for line in lines:
            # strip ANSI codes before writing to file
            f.write(_strip_ansi(line) + "\n")

    return filepath

def list_outputs():
    ensure_output_dir()
    files = sorted(os.listdir(OUTPUT_DIR), reverse=True)
    return [os.path.join(OUTPUT_DIR, f) for f in files if f.endswith((".json", ".txt"))]

def _strip_ansi(text):
    import re
    # remove ANSI escape codes so saved files are clean
    ansi_escape = re.compile(r"\033\[[0-9;]*m")
    return ansi_escape.sub("", text)