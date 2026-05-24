import os
import json
from datetime import datetime
from werkzeug.utils import secure_filename

QUARANTINE_DIR = "quarantine"

class QuarantineManager:
    def __init__(self):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

    def quarantine_email(self, file, analysis_result, user_id):
        """Move suspicious email to quarantine"""
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = f"{timestamp}_{filename}"
        
        file_path = os.path.join(QUARANTINE_DIR, safe_name)
        
        # Save the raw email
        file.seek(0)  # Reset file pointer
        file.save(file_path)

        # Save metadata
        metadata = {
            "original_filename": filename,
            "quarantined_at": timestamp,
            "risk_level": analysis_result["risk_level"],
            "score": analysis_result["score"],
            "user_id": user_id,
            "reason": "High risk detected by PhishGuard"
        }
        
        with open(os.path.join(QUARANTINE_DIR, f"{safe_name}.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        return file_path

    def get_quarantined_emails(self):
        """List all quarantined emails"""
        emails = []
        for file in os.listdir(QUARANTINE_DIR):
            if file.endswith(".json"):
                with open(os.path.join(QUARANTINE_DIR, file)) as f:
                    emails.append(json.load(f))
        return emails