import glob
import re
from pathlib import Path
replacements = {
    r'href="/tour"': 'href="/tour"',
    r'href="/register"': 'href="/register"',
    r'href="/contact"': 'href="/contact"',
    r'href="/teacher-login"': 'href="/teacher-login"',
    r'href="/login"': 'href="/login"',
    r'href="/teacher"': 'href="/teacher"',
    r'href="/profile"': 'href="/profile"',
    r'window.location.href = "/register"': 'window.location.href = "/files/register.html"',
    r'window.location.href = "/contact"': 'window.location.href = "/files/contact.html"',
    r'window.location.href = "/login"': 'window.location.href = "/files/login.html"',
    r'window.location.href = "/teacher"': 'window.location.href = "/files/teacher.html"',
    r'window.location.href = "/profile"': 'window.location.href = "/files/profile.html"',
    r'window.location.href = "/teacher-login"': 'window.location.href = "/files/teacher-login.html"',
}
html_files = glob.glob('*.html') + glob.glob('files/*.html')
for path in html_files:
    p = Path(path)
    text = p.read_text(encoding='utf-8')
    new_text = text
    for patt, repl in replacements.items():
        new_text = re.sub(patt, repl, new_text)
    if new_text != text:
        p.write_text(new_text, encoding='utf-8')
print('patched', len(html_files), 'files')
