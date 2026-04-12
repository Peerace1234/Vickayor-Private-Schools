const http = require("http");
const urls = [
  "http://localhost:8080/index.html",
  "http://localhost:8080/login",
  "http://localhost:8080/register",
  "http://localhost:8080/teacher-login",
  "http://localhost:8080/teacher",
  "http://localhost:8080/profile",
];
let done = 0;
const re = /<title>([^<]*)<\/title>/i;
urls.forEach((url) => {
  http
    .get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        const m = data.match(re);
        console.log(
          `PAGE: ${url} STATUS: ${res.statusCode} LEN: ${data.length}`,
        );
        console.log(`TITLE: ${m ? m[1] : "NONE"}`);
        done += 1;
        if (done === urls.length) process.exit(0);
      });
    })
    .on("error", (err) => {
      console.log(`PAGE: ${url} ERROR: ${err.message}`);
      done += 1;
      if (done === urls.length) process.exit(0);
    });
});
