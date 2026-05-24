import email
from email import policy
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

class EmailParser:
    def __init__(self, raw_email):
        self.msg = email.message_from_bytes(raw_email, policy=policy.default)

    def get_headers(self):
        return dict(self.msg.items())

    def get_body(self):
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    # Use built-in html.parser instead of lxml
                    return BeautifulSoup(payload, 'html.parser')
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    return payload.decode('utf-8', errors='ignore') if payload else ""
        payload = self.msg.get_payload(decode=True)
        if payload:
            return BeautifulSoup(payload, 'html.parser')
        return ""

    def extract_urls(self, content):
        urls = []
        if isinstance(content, BeautifulSoup):
            urls = [a['href'] for a in content.find_all('a', href=True)]
        else:
            urls = re.findall(r'https?://[^\s<>"]+', str(content))
        return urls