import magic
import os

DANGEROUS_EXTENSIONS = {'.exe', '.bat', '.cmd', '.scr', '.pif', '.js', '.vbs', '.ps1', '.jar', '.zip', '.rar'}

def check_attachment(file_storage):
    if not file_storage or file_storage.filename == '':
        return {"safe": True, "score": 0, "reason": "No attachment"}

    filename = file_storage.filename.lower()
    ext = os.path.splitext(filename)[1]

    mime = magic.from_buffer(file_storage.read(2048), mime=True)
    file_storage.seek(0)  # Reset pointer

    score = 0
    reasons = []

    if ext in DANGEROUS_EXTENSIONS:
        score += 50
        reasons.append(f"Dangerous extension: {ext}")

    if "executable" in mime or "application/x-msdownload" in mime:
        score += 40
        reasons.append("Suspicious executable content")

    return {
        "safe": score == 0,
        "score": score,
        "reason": ", ".join(reasons) if reasons else "Looks safe",
        "mime": mime,
        "extension": ext
    }