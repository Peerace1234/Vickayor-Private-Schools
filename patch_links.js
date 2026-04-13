const fs = require("fs");
const path = require("path");
const glob = require("glob");
const replacements = {
  'href="/tour"': 'href="/tour"',
  'href="/register"': 'href="/register"',
  'href="/contact"': 'href="/contact"',
  'href="/teacher-login"': 'href="/teacher-login"',
  'href="/login"': 'href="/login"',
  'href="/teacher"': 'href="/teacher"',
  'href="/profile"': 'href="/profile"',
  'window.location.href = "/register"':
    'window.location.href = "/files/register.html"',
  'window.location.href = "/contact"':
    'window.location.href = "/files/contact.html"',
  'window.location.href = "/login"':
    'window.location.href = "/files/login.html"',
  'window.location.href = "/teacher"':
    'window.location.href = "/files/teacher.html"',
  'window.location.href = "/profile"':
    'window.location.href = "/files/profile.html"',
  'window.location.href = "/teacher-login"':
    'window.location.href = "/files/teacher-login.html"',
};
const htmlFiles = glob.sync("*.html").concat(glob.sync("files/*.html"));
for (const file of htmlFiles) {
  const text = fs.readFileSync(file, "utf8");
  let updated = text;
  for (const [search, replace] of Object.entries(replacements)) {
    updated = updated.split(search).join(replace);
  }
  if (updated !== text) {
    fs.writeFileSync(file, updated, "utf8");
  }
}
console.log("patched", htmlFiles.length, "files");
