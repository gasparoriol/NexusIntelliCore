//! Labelled taint corpus (SAST v2 §6): per rule and language, a positive,
//! a safe variant (sanitizer or safe API), a static one and an evasion
//! (aliasing, two-step concatenation, mutation, false sanitizer…).

use super::*;
use crate::analyzer::{audit_file_ast, detect_grammar};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Positive,
    Safe,
    Static,
    Evasion,
}
use Kind::{Evasion, Positive, Safe, Static};

struct Case {
    rule: &'static str,
    file: &'static str,
    kind: Kind,
    src: &'static str,
}

const fn case(rule: &'static str, file: &'static str, kind: Kind, src: &'static str) -> Case {
    Case {
        rule,
        file,
        kind,
        src,
    }
}

fn findings_for(file: &str, src: &str) -> Vec<AuditFinding> {
    detect_grammar(Path::new(file))
        .map(|g| audit_file_ast(src, g))
        .unwrap_or_default()
}

const CASES: &[Case] = &[
    // ── Java ────────────────────────────────────────────────────────────────
    case(
        "java-sql-injection-taint",
        "A.java",
        Positive,
        r#"
class A {
    @GetMapping("/u")
    String find(@RequestParam String id, Statement st) throws Exception {
        String q = "SELECT * FROM users WHERE id = '" + id + "'";
        st.executeQuery(q);
        return "ok";
    }
}"#,
    ),
    case(
        "java-sql-injection-taint",
        "A.java",
        Safe,
        r#"
class A {
    String find(@RequestParam String id, Statement st) throws Exception {
        int n = Integer.parseInt(id);
        st.executeQuery("SELECT * FROM users WHERE id = " + n);
        return "ok";
    }
}"#,
    ),
    case(
        "java-sql-injection-taint",
        "A.java",
        Static,
        r#"
class A {
    void count(Statement st) throws Exception {
        st.executeQuery("SELECT COUNT(*) FROM users");
    }
}"#,
    ),
    case(
        "java-sql-injection-taint",
        "A.java",
        Evasion,
        r#"
class A {
    void find(HttpServletRequest req, Connection c) throws Exception {
        String raw = req.getParameter("id");
        String alias = raw;
        StringBuilder sb = new StringBuilder("DELETE FROM t WHERE id = ");
        sb.append(alias);
        c.createStatement().executeUpdate(sb.toString());
    }
}"#,
    ),
    case(
        "java-command-injection-taint",
        "A.java",
        Positive,
        r#"
class A {
    void ping(@RequestParam String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}"#,
    ),
    case(
        "java-command-injection-taint",
        "A.java",
        Safe,
        r#"
class A {
    void probe(@RequestParam String p) throws Exception {
        int port = Integer.parseInt(p);
        Runtime.getRuntime().exec("nc -z localhost " + port);
    }
}"#,
    ),
    case(
        "java-command-injection-taint",
        "A.java",
        Static,
        r#"
class A {
    void list() throws Exception {
        Runtime.getRuntime().exec("ls -la");
    }
}"#,
    ),
    case(
        "java-command-injection-taint",
        "A.java",
        Evasion,
        r#"
class A {
    void ping(@RequestParam String host) throws Exception {
        String cmd = host;
        cmd += " -c 1";
        new ProcessBuilder("sh", "-c", "ping " + cmd).start();
    }
}"#,
    ),
    case(
        "java-path-traversal-taint",
        "A.java",
        Positive,
        r#"
@RestController
public class VulnerableSpring {
    @GetMapping("/download")
    public String download(@RequestParam String filename) throws IOException {
        FileInputStream fis = new FileInputStream("/var/data/" + filename);
        return "done";
    }
}"#,
    ),
    case(
        "java-path-traversal-taint",
        "A.java",
        Safe,
        r#"
public class SafeConfinement {
    private static final Path BASE = Paths.get("/var/data/");

    String read(@RequestParam String input) throws Exception {
        Path resolved = BASE.resolve(input).normalize();
        if (!resolved.startsWith(BASE + File.separator)) {
            throw new SecurityException("Traversal");
        }
        String name = FilenameUtils.getName(input);
        new FileInputStream("/var/data/" + name);
        return Files.readString(resolved);
    }
}"#,
    ),
    case(
        "java-path-traversal-taint",
        "A.java",
        Static,
        r#"
public class StaticFiles {
    void loadConfig() throws IOException {
        FileInputStream fis = new FileInputStream("config.properties");
    }
}"#,
    ),
    // `!contains("..")` is not a sanitizer.
    case(
        "java-path-traversal-taint",
        "A.java",
        Evasion,
        r#"
@RestController
public class FalseGuard {
    @GetMapping("/file")
    public String read(@RequestParam String path) throws IOException {
        if (!path.contains("..")) {
            FileInputStream fis = new FileInputStream(path);
            return "ok";
        }
        return "rejected";
    }
}"#,
    ),
    // Zip Slip: archive entry names are attacker-controlled.
    case(
        "java-path-traversal-taint",
        "A.java",
        Evasion,
        r#"
public class ZipSlip {
    void extract(ZipInputStream zis, String destDir) throws IOException {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName();
            File dest = new File(destDir, name);
            FileOutputStream fos = new FileOutputStream(dest);
        }
    }
}"#,
    ),
    // `startsWith(BASE)` without a separator accepts "/data2" for "/data".
    case(
        "java-path-traversal-taint",
        "A.java",
        Evasion,
        r#"
class A {
    String read(@RequestParam String input) throws Exception {
        Path p = BASE.resolve(input).normalize();
        if (!p.startsWith(BASE)) { throw new SecurityException(); }
        return Files.readString(p);
    }
}"#,
    ),
    case(
        "java-ssrf-taint",
        "A.java",
        Positive,
        r#"
class A {
    byte[] fetch(@RequestParam String target) throws Exception {
        return new URL(target).openStream().readAllBytes();
    }
}"#,
    ),
    case(
        "java-ssrf-taint",
        "A.java",
        Safe,
        r#"
class A {
    Item get(@PathVariable String id) {
        return restTemplate.getForObject("https://api.example.org/items/{id}", Item.class, id);
    }
}"#,
    ),
    case(
        "java-ssrf-taint",
        "A.java",
        Static,
        r#"
class A {
    byte[] health() throws Exception {
        return new URL("https://example.org/health").openStream().readAllBytes();
    }
}"#,
    ),
    case(
        "java-ssrf-taint",
        "A.java",
        Evasion,
        r#"
class A {
    void call(HttpServletRequest req) throws Exception {
        String host = req.getHeader("X-Host");
        String u = "http://" + host + "/admin";
        HttpRequest r = HttpRequest.newBuilder(URI.create(u)).build();
    }
}"#,
    ),
    case(
        "java-open-redirect-taint",
        "A.java",
        Positive,
        r#"
class A {
    void login(@RequestParam String next, HttpServletResponse response) throws Exception {
        response.sendRedirect(next);
    }
}"#,
    ),
    case(
        "java-open-redirect-taint",
        "A.java",
        Safe,
        r#"
class A {
    void open(@RequestParam String id, HttpServletResponse response) throws Exception {
        response.sendRedirect("/items/" + Long.parseLong(id));
    }
}"#,
    ),
    case(
        "java-open-redirect-taint",
        "A.java",
        Static,
        r#"
class A {
    void logout(HttpServletResponse response) throws Exception {
        response.sendRedirect("/login");
    }
}"#,
    ),
    case(
        "java-open-redirect-taint",
        "A.java",
        Evasion,
        r#"
class A {
    @PostMapping("/done")
    String done(@RequestParam String url) {
        String target = url.trim();
        return "redirect:" + target;
    }
}"#,
    ),
    case(
        "java-ssti-taint",
        "A.java",
        Positive,
        r#"
class A {
    void preview(@RequestBody String tpl, Configuration cfg) throws Exception {
        Template t = new Template("preview", new StringReader(tpl), cfg);
    }
}"#,
    ),
    case(
        "java-ssti-taint",
        "A.java",
        Safe,
        r#"
class A {
    void page(@RequestParam String name, Configuration cfg, Writer out) throws Exception {
        Template t = cfg.getTemplate("page.ftl");
        t.process(Map.of("name", name), out);
    }
}"#,
    ),
    case(
        "java-ssti-taint",
        "A.java",
        Static,
        r#"
class A {
    void page(Configuration cfg) throws Exception {
        Template t = new Template("x", new StringReader("<p>${name}</p>"), cfg);
    }
}"#,
    ),
    case(
        "java-ssti-taint",
        "A.java",
        Evasion,
        r#"
class A {
    void render(@RequestParam String title, VelocityContext ctx, Writer writer) {
        String body = "<h1>" + title + "</h1>";
        Velocity.evaluate(ctx, writer, "tag", body);
    }
}"#,
    ),
    case(
        "java-log-injection-taint",
        "A.java",
        Positive,
        r#"
class A {
    void login(@RequestParam String user) {
        log.info("User login: " + user);
    }
}"#,
    ),
    case(
        "java-log-injection-taint",
        "A.java",
        Safe,
        r#"
class A {
    void login(@RequestParam String user) {
        log.info("User login: " + user.replaceAll("[\r\n]", "_"));
    }
}"#,
    ),
    case(
        "java-log-injection-taint",
        "A.java",
        Static,
        r#"
class A {
    void start() {
        log.info("Service started");
    }
}"#,
    ),
    case(
        "java-log-injection-taint",
        "A.java",
        Evasion,
        r#"
class A {
    void login(HttpServletRequest req) {
        String user = req.getParameter("user");
        String msg = String.format("login %s", user);
        LOGGER.warn(msg);
    }
}"#,
    ),
    // ── Python ──────────────────────────────────────────────────────────────
    case(
        "py-sql-injection-taint",
        "a.py",
        Positive,
        r#"
from flask import request

def find(cur):
    uid = request.args.get("id")
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)
"#,
    ),
    case(
        "py-sql-injection-taint",
        "a.py",
        Safe,
        r#"
from flask import request

def find(cur):
    uid = request.args.get("id")
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
"#,
    ),
    case(
        "py-sql-injection-taint",
        "a.py",
        Static,
        r#"
def count(cur):
    cur.execute("SELECT COUNT(*) FROM users")
"#,
    ),
    case(
        "py-sql-injection-taint",
        "a.py",
        Evasion,
        r#"
from flask import request

def find(cur):
    q = "SELECT * FROM t WHERE name = "
    name = request.form["name"]
    q += f"'{name}'"
    cur.execute(q)
"#,
    ),
    case(
        "py-command-injection-taint",
        "a.py",
        Positive,
        r#"
import os
from flask import request

def ping():
    os.system("ping -c 1 " + request.args["host"])
"#,
    ),
    case(
        "py-command-injection-taint",
        "a.py",
        Safe,
        r#"
import os, shlex
from flask import request

def ping():
    host = request.args["host"]
    os.system("ping -c 1 " + shlex.quote(host))
"#,
    ),
    case(
        "py-command-injection-taint",
        "a.py",
        Static,
        r#"
import os

def uptime():
    os.system("uptime")
"#,
    ),
    case(
        "py-command-injection-taint",
        "a.py",
        Evasion,
        r#"
import subprocess
from flask import request

def lookup():
    host = request.values.get("host")
    cmd = "nslookup %s" % host
    subprocess.Popen(cmd, shell=True)
"#,
    ),
    case(
        "py-path-traversal-taint",
        "a.py",
        Positive,
        r#"
from flask import request

def download():
    return open("/srv/files/" + request.args["name"]).read()
"#,
    ),
    case(
        "py-path-traversal-taint",
        "a.py",
        Safe,
        r#"
import os
from flask import request

def download():
    name = request.args["name"]
    return open(os.path.join(BASE, os.path.basename(name))).read()
"#,
    ),
    case(
        "py-path-traversal-taint",
        "a.py",
        Static,
        r#"
def config():
    return open("config.yaml").read()
"#,
    ),
    case(
        "py-path-traversal-taint",
        "a.py",
        Evasion,
        r#"
import os
from flask import request

def save():
    name = request.files["f"].filename
    dest = os.path.join("/uploads", name)
    if ".." not in dest:
        with open(dest, "wb") as fh:
            fh.write(b"")
"#,
    ),
    case(
        "py-ssrf-taint",
        "a.py",
        Positive,
        r#"
import requests
from flask import request

def proxy():
    return requests.get(request.args["url"]).text
"#,
    ),
    case(
        "py-ssrf-taint",
        "a.py",
        Safe,
        r#"
import requests
from flask import request

def search():
    return requests.get("https://api.example.org/items", params={"q": request.args["q"]}).text
"#,
    ),
    case(
        "py-ssrf-taint",
        "a.py",
        Static,
        r#"
from urllib.request import urlopen

def health():
    return urlopen("https://example.org/health").read()
"#,
    ),
    case(
        "py-ssrf-taint",
        "a.py",
        Evasion,
        r#"
import httpx
from flask import request

def admin():
    host = request.headers.get("X-Host")
    target = "http://%s/admin" % host
    return httpx.request("GET", target)
"#,
    ),
    case(
        "py-open-redirect-taint",
        "a.py",
        Positive,
        r#"
from flask import redirect, request

def login():
    return redirect(request.args.get("next"))
"#,
    ),
    case(
        "py-open-redirect-taint",
        "a.py",
        Safe,
        r#"
from flask import redirect, request, url_for

def profile():
    return redirect(url_for("profile", user=request.args.get("u")))
"#,
    ),
    case(
        "py-open-redirect-taint",
        "a.py",
        Static,
        r#"
from flask import redirect

def home():
    return redirect("/home")
"#,
    ),
    case(
        "py-open-redirect-taint",
        "a.py",
        Evasion,
        r#"
from django.http import HttpResponseRedirect

class LoginView(View):
    def get(self):
        next_url = self.request.GET.get("next", "/")
        return HttpResponseRedirect(next_url)
"#,
    ),
    case(
        "py-ssti-taint",
        "a.py",
        Positive,
        r#"
from flask import render_template_string, request

def hello():
    return render_template_string("<h1>" + request.args["name"] + "</h1>")
"#,
    ),
    case(
        "py-ssti-taint",
        "a.py",
        Safe,
        r#"
from flask import render_template, request

def hello():
    return render_template("hello.html", name=request.args["name"])
"#,
    ),
    case(
        "py-ssti-taint",
        "a.py",
        Static,
        r#"
from flask import render_template_string

def hello():
    return render_template_string("<h1>Hello</h1>")
"#,
    ),
    case(
        "py-ssti-taint",
        "a.py",
        Evasion,
        r#"
import jinja2
from flask import request

def preview():
    tpl = request.form.get("tpl")
    env = jinja2.Environment()
    return env.from_string(tpl).render()
"#,
    ),
    case(
        "py-log-injection-taint",
        "a.py",
        Positive,
        r#"
from flask import request

def login():
    logger.info("login " + request.form["user"])
"#,
    ),
    case(
        "py-log-injection-taint",
        "a.py",
        Safe,
        r#"
from flask import request

def login():
    user = request.form["user"]
    logger.info("login %s", user.replace("\n", "").replace("\r", ""))
"#,
    ),
    case(
        "py-log-injection-taint",
        "a.py",
        Static,
        r#"
import logging

def start():
    logging.info("started")
"#,
    ),
    case(
        "py-log-injection-taint",
        "a.py",
        Evasion,
        r#"
from flask import request

class Service:
    def login(self):
        name = request.args.get("u")
        self.log.warning("user=%s", name)
"#,
    ),
    // FastAPI path/query parameters are user input.
    case(
        "py-sql-injection-taint",
        "a.py",
        Positive,
        r#"
@app.get("/items/{item_id}")
def read_item(item_id: str, db = Depends(get_db)):
    db.execute(text("SELECT * FROM items WHERE id = '" + item_id + "'"))
"#,
    ),
    // ── JavaScript ──────────────────────────────────────────────────────────
    case(
        "js-sql-injection-taint",
        "a.js",
        Positive,
        r#"
app.get('/u', (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id);
});"#,
    ),
    case(
        "js-sql-injection-taint",
        "a.js",
        Safe,
        r#"
app.get('/u', (req, res) => {
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
});"#,
    ),
    case(
        "js-sql-injection-taint",
        "a.js",
        Static,
        r#"
function count() {
  return db.query("SELECT COUNT(*) FROM users");
}"#,
    ),
    case(
        "js-sql-injection-taint",
        "a.js",
        Evasion,
        r#"
app.post('/s', async (req, res) => {
  const { name } = req.body;
  const sql = `SELECT * FROM t WHERE name = '${name}'`;
  await prisma.$queryRawUnsafe(sql);
});"#,
    ),
    case(
        "js-command-injection-taint",
        "a.js",
        Positive,
        r#"
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec("ping -c 1 " + req.query.host);
});"#,
    ),
    case(
        "js-command-injection-taint",
        "a.js",
        Safe,
        r#"
const { execFile } = require('child_process');
app.get('/ping', (req, res) => {
  execFile("ping", ["-c", "1", req.query.host]);
});"#,
    ),
    case(
        "js-command-injection-taint",
        "a.js",
        Static,
        r#"
const { exec } = require('child_process');
function list() {
  exec("ls -la");
}"#,
    ),
    case(
        "js-command-injection-taint",
        "a.js",
        Evasion,
        r#"
app.post('/log', (req, res) => {
  const cmd = ["git", "log", req.body.ref].join(" ");
  require('child_process').execSync(cmd);
});"#,
    ),
    case(
        "js-path-traversal-taint",
        "a.js",
        Positive,
        r#"
app.get('/f/:name', (req, res) => {
  res.sendFile("/srv/files/" + req.params.name);
});"#,
    ),
    case(
        "js-path-traversal-taint",
        "a.js",
        Safe,
        r#"
app.get('/f', (req, res) => {
  fs.readFile(path.join(BASE, path.basename(req.query.f)), (e, d) => res.send(d));
});"#,
    ),
    case(
        "js-path-traversal-taint",
        "a.js",
        Static,
        r#"
const cfg = JSON.parse(fs.readFileSync("./config.json"));"#,
    ),
    case(
        "js-path-traversal-taint",
        "a.js",
        Evasion,
        r#"
app.post('/f', (req, res) => {
  const p = path.resolve(BASE, req.query.f);
  if (p.startsWith(BASE)) {
    fs.writeFileSync(p, req.body.data);
  }
});"#,
    ),
    case(
        "js-ssrf-taint",
        "a.js",
        Positive,
        r#"
app.get('/proxy', async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});"#,
    ),
    case(
        "js-ssrf-taint",
        "a.js",
        Safe,
        r#"
app.get('/search', async (req, res) => {
  const r = await axios.get("https://api.example.org/items", { params: { q: req.query.q } });
  res.json(r.data);
});"#,
    ),
    case(
        "js-ssrf-taint",
        "a.js",
        Static,
        r#"
async function health() {
  return fetch("https://example.org/health");
}"#,
    ),
    case(
        "js-ssrf-taint",
        "a.js",
        Evasion,
        r#"
app.post('/call', async (req, res) => {
  const target = new URL(req.body.path, "http://internal");
  await got(target.toString());
});"#,
    ),
    case(
        "js-open-redirect-taint",
        "a.js",
        Positive,
        r#"
app.get('/login', (req, res) => {
  res.redirect(req.query.next);
});"#,
    ),
    case(
        "js-open-redirect-taint",
        "a.js",
        Safe,
        r#"
app.get('/s', (req, res) => {
  res.redirect("/search?q=" + encodeURIComponent(req.query.q));
});"#,
    ),
    case(
        "js-open-redirect-taint",
        "a.js",
        Static,
        r#"
app.get('/logout', (req, res) => {
  res.redirect(302, "/login");
});"#,
    ),
    case(
        "js-open-redirect-taint",
        "a.js",
        Evasion,
        r#"
const next = new URLSearchParams(location.search).get("next");
window.location.href = next;"#,
    ),
    case(
        "js-ssti-taint",
        "a.js",
        Positive,
        r#"
app.post('/preview', (req, res) => {
  res.send(ejs.render(req.body.template, {}));
});"#,
    ),
    case(
        "js-ssti-taint",
        "a.js",
        Safe,
        r#"
app.get('/profile', (req, res) => {
  res.render("profile", { name: req.query.name });
});"#,
    ),
    case(
        "js-ssti-taint",
        "a.js",
        Static,
        r#"
const html = pug.render("p Hello");"#,
    ),
    case(
        "js-ssti-taint",
        "a.js",
        Evasion,
        r#"
app.get('/t', (req, res) => {
  const tpl = "<h1>" + req.query.title + "</h1>";
  const fn = Handlebars.compile(tpl);
  res.send(fn({}));
});"#,
    ),
    case(
        "js-log-injection-taint",
        "a.js",
        Positive,
        r#"
app.post('/login', (req, res) => {
  logger.info("login " + req.body.user);
});"#,
    ),
    case(
        "js-log-injection-taint",
        "a.js",
        Safe,
        r#"
app.post('/login', (req, res) => {
  logger.info("login " + req.body.user.replace(/[\r\n]/g, ""));
});"#,
    ),
    case(
        "js-log-injection-taint",
        "a.js",
        Static,
        r#"
logger.info("server started");"#,
    ),
    case(
        "js-log-injection-taint",
        "a.js",
        Evasion,
        r#"
class Auth {
  check(req) {
    this.logger.warn(`attempt by ${req.headers["x-user"]}`);
  }
}"#,
    ),
    // NestJS parameter decorators (TypeScript).
    case(
        "js-sql-injection-taint",
        "users.controller.ts",
        Positive,
        r#"
@Controller('users')
export class UsersController {
  @Get()
  find(@Query('id') id: string) {
    return this.db.query(`SELECT * FROM users WHERE id = ${id}`);
  }
}"#,
    ),
    // ── Go ──────────────────────────────────────────────────────────────────
    case("go-sql-injection-taint", "a.go", Positive, "package a\n\nfunc find(w http.ResponseWriter, r *http.Request) {\n\tid := r.URL.Query().Get(\"id\")\n\tdb.Query(\"SELECT * FROM users WHERE id = '\" + id + \"'\")\n}\n"),
    case("go-sql-injection-taint", "a.go", Safe, "package a\n\nfunc find(w http.ResponseWriter, r *http.Request) {\n\tid := r.URL.Query().Get(\"id\")\n\tdb.Query(\"SELECT * FROM users WHERE id = $1\", id)\n}\n"),
    case("go-sql-injection-taint", "a.go", Static, "package a\n\nfunc count() { db.Query(\"SELECT COUNT(*) FROM users\") }\n"),
    case("go-sql-injection-taint", "a.go", Evasion, "package a\n\nfunc del(c *gin.Context) {\n\tvar req Req\n\tc.ShouldBindJSON(&req)\n\tq := fmt.Sprintf(\"DELETE FROM t WHERE name = '%s'\", req.Name)\n\tdb.ExecContext(c, q)\n}\n"),
    case("go-command-injection-taint", "a.go", Positive, "package a\n\nfunc run(c *gin.Context) { exec.Command(c.Query(\"bin\")).Run() }\n"),
    case("go-command-injection-taint", "a.go", Safe, "package a\n\nfunc run(c *gin.Context) {\n\tn, _ := strconv.Atoi(c.Query(\"n\"))\n\texec.Command(\"sh\", \"-c\", fmt.Sprintf(\"seq %d\", n)).Run()\n}\n"),
    case("go-command-injection-taint", "a.go", Static, "package a\n\nfunc run() { exec.Command(\"ls\", \"-la\").Run() }\n"),
    case("go-command-injection-taint", "a.go", Evasion, "package a\n\nfunc run(r *http.Request) {\n\thost := r.FormValue(\"host\")\n\tcmd := \"ping -c 1 \"\n\tcmd += host\n\texec.Command(\"/bin/sh\", \"-c\", cmd).Run()\n}\n"),
    case("go-path-traversal-taint", "a.go", Positive, "package a\n\nfunc dl(w http.ResponseWriter, r *http.Request) { os.ReadFile(\"/srv/\" + r.URL.Query().Get(\"f\")) }\n"),
    case("go-path-traversal-taint", "a.go", Safe, "package a\n\nfunc dl(w http.ResponseWriter, r *http.Request) {\n\tname := filepath.Base(r.URL.Query().Get(\"f\"))\n\tos.ReadFile(filepath.Join(\"/srv\", name))\n}\n"),
    case("go-path-traversal-taint", "a.go", Static, "package a\n\nfunc cfg() { os.ReadFile(\"config.yaml\") }\n"),
    case("go-path-traversal-taint", "a.go", Evasion, "package a\n\nfunc up(r *http.Request) {\n\tp := filepath.Join(\"/srv\", mux.Vars(r)[\"name\"])\n\tif strings.HasPrefix(p, \"/srv\") {\n\t\tos.WriteFile(p, nil, 0o600)\n\t}\n}\n"),
    case("go-ssrf-taint", "a.go", Positive, "package a\n\nfunc proxy(w http.ResponseWriter, r *http.Request) { http.Get(r.URL.Query().Get(\"url\")) }\n"),
    case("go-ssrf-taint", "a.go", Safe, "package a\n\nfunc search(w http.ResponseWriter, r *http.Request) {\n\tq := url.QueryEscape(r.FormValue(\"q\"))\n\t_ = q\n\thttp.Get(\"https://api.example.org/items\")\n}\n"),
    case("go-ssrf-taint", "a.go", Static, "package a\n\nfunc health() { http.Get(\"https://example.org/health\") }\n"),
    case("go-ssrf-taint", "a.go", Evasion, "package a\n\nfunc call(c echo.Context) {\n\ttarget := \"http://\" + c.QueryParam(\"host\") + \"/admin\"\n\treq, _ := http.NewRequest(\"GET\", target, nil)\n\t_ = req\n}\n"),
    case("go-open-redirect-taint", "a.go", Positive, "package a\n\nfunc login(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.FormValue(\"next\"), 302) }\n"),
    case("go-open-redirect-taint", "a.go", Safe, "package a\n\nfunc page(w http.ResponseWriter, r *http.Request) {\n\tn, _ := strconv.Atoi(r.FormValue(\"p\"))\n\thttp.Redirect(w, r, fmt.Sprintf(\"/list?page=%d\", n), 302)\n}\n"),
    case("go-open-redirect-taint", "a.go", Static, "package a\n\nfunc logout(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, \"/login\", 302) }\n"),
    case("go-open-redirect-taint", "a.go", Evasion, "package a\n\nfunc done(c *gin.Context) {\n\tnext := c.DefaultQuery(\"next\", \"/\")\n\tc.Redirect(302, next)\n}\n"),
    case("go-ssti-taint", "a.go", Positive, "package a\n\nfunc page(r *http.Request) { template.New(\"p\").Parse(r.FormValue(\"tpl\")) }\n"),
    case("go-ssti-taint", "a.go", Safe, "package a\n\nfunc page(w http.ResponseWriter, r *http.Request) {\n\tt, _ := template.ParseFiles(\"page.html\")\n\tt.Execute(w, r.FormValue(\"name\"))\n}\n"),
    case("go-ssti-taint", "a.go", Static, "package a\n\nfunc page() { template.New(\"p\").Parse(\"<h1>{{.Name}}</h1>\") }\n"),
    case("go-ssti-taint", "a.go", Evasion, "package a\n\nfunc page(c *gin.Context) {\n\tbody := \"<h1>\" + c.PostForm(\"title\") + \"</h1>\"\n\ttemplate.Must(template.New(\"x\").Parse(body))\n}\n"),
    case("go-log-injection-taint", "a.go", Positive, "package a\n\nfunc login(r *http.Request) { log.Printf(\"login %s\", r.FormValue(\"user\")) }\n"),
    case("go-log-injection-taint", "a.go", Safe, "package a\n\nfunc login(r *http.Request) { log.Printf(\"login %s\", strconv.Quote(r.FormValue(\"user\"))) }\n"),
    case("go-log-injection-taint", "a.go", Static, "package a\n\nfunc start() { log.Println(\"server started\") }\n"),
    case("go-log-injection-taint", "a.go", Evasion, "package a\n\nfunc login(c *gin.Context) {\n\tuser := c.GetHeader(\"X-User\")\n\tlogger.Infof(\"attempt by %s\", user)\n}\n"),
    // ── C# ──────────────────────────────────────────────────────────────────
    case("cs-sql-injection-taint", "A.cs", Positive, "class C { void Find([FromQuery] string id) { var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = '\" + id + \"'\", conn); } }"),
    case("cs-sql-injection-taint", "A.cs", Safe, "class C { void Find([FromQuery] string id) { var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn); cmd.Parameters.AddWithValue(\"@id\", id); } }"),
    case("cs-sql-injection-taint", "A.cs", Static, "class C { void Count() { var cmd = new SqlCommand(\"SELECT COUNT(*) FROM users\", conn); } }"),
    case("cs-sql-injection-taint", "A.cs", Evasion, "class C { void Del() { var name = Request.Query[\"name\"]; var sb = new StringBuilder(\"DELETE FROM t WHERE name = \"); sb.Append(name); db.Database.ExecuteSqlRaw(sb.ToString()); } }"),
    case("cs-command-injection-taint", "A.cs", Positive, "class C { void Run([FromQuery] string host) { Process.Start(\"cmd.exe\", \"/c ping \" + host); } }"),
    case("cs-command-injection-taint", "A.cs", Safe, "class C { void Run([FromQuery] string n) { var count = int.Parse(n); Process.Start(\"ping\", \"-n \" + count); } }"),
    case("cs-command-injection-taint", "A.cs", Static, "class C { void Run() { Process.Start(\"notepad.exe\"); } }"),
    case("cs-command-injection-taint", "A.cs", Evasion, "class C { void Run([FromBody] Job job) { var psi = new ProcessStartInfo(\"bash\"); psi.Arguments = \"-c \" + job.Script; } }"),
    case("cs-path-traversal-taint", "A.cs", Positive, "class C { string Read([FromQuery] string file) { return File.ReadAllText(\"/srv/\" + file); } }"),
    case("cs-path-traversal-taint", "A.cs", Safe, "class C { string Read([FromQuery] string file) { var name = Path.GetFileName(file); return File.ReadAllText(Path.Combine(Root, name)); } }"),
    case("cs-path-traversal-taint", "A.cs", Static, "class C { string Read() { return File.ReadAllText(\"appsettings.json\"); } }"),
    case("cs-path-traversal-taint", "A.cs", Evasion, "class C { void Save([FromRoute] string name) { var full = Path.Combine(Root, name); if (full.StartsWith(Root)) { File.WriteAllText(full, \"\"); } } }"),
    case("cs-ssrf-taint", "A.cs", Positive, "class C { async Task Proxy([FromQuery] string url) { await _client.GetAsync(url); } }"),
    case("cs-ssrf-taint", "A.cs", Safe, "class C { async Task Search([FromQuery] string q) { await _client.GetAsync(\"https://api.example.org/items?q=\" + Uri.EscapeDataString(q)); } }"),
    case("cs-ssrf-taint", "A.cs", Static, "class C { async Task Health() { await _client.GetAsync(\"https://example.org/health\"); } }"),
    case("cs-ssrf-taint", "A.cs", Evasion, "class C { void Call([FromHeader] string host) { var target = $\"http://{host}/admin\"; var req = new HttpRequestMessage(HttpMethod.Get, target); } }"),
    case("cs-open-redirect-taint", "A.cs", Positive, "class C : Controller { IActionResult Login([FromQuery] string returnUrl) { return Redirect(returnUrl); } }"),
    case("cs-open-redirect-taint", "A.cs", Safe, "class C : Controller { IActionResult Login([FromQuery] string returnUrl) { if (Url.IsLocalUrl(returnUrl)) { return Redirect(returnUrl); } return Redirect(\"/\"); } }"),
    case("cs-open-redirect-taint", "A.cs", Static, "class C : Controller { IActionResult Logout() { return Redirect(\"/login\"); } }"),
    case("cs-open-redirect-taint", "A.cs", Evasion, "class C { void Done() { var next = Request.Query[\"next\"].ToString(); Response.Redirect(next); } }"),
    case("cs-ssti-taint", "A.cs", Positive, "class C { string Render([FromBody] string tpl) { return Engine.Razor.RunCompile(tpl, \"key\"); } }"),
    case("cs-ssti-taint", "A.cs", Safe, "class C : Controller { IActionResult Page([FromQuery] string name) { return View(\"Page\", name); } }"),
    case("cs-ssti-taint", "A.cs", Static, "class C { string Render() { return Template.Parse(\"Hello {{ name }}\").Render(); } }"),
    case("cs-ssti-taint", "A.cs", Evasion, "class C { string Render([FromForm] string title) { var body = \"<h1>\" + title + \"</h1>\"; return Template.Parse(body).Render(); } }"),
    case("cs-log-injection-taint", "A.cs", Positive, "class C { void Login([FromForm] string user) { _logger.LogInformation(\"login \" + user); } }"),
    case("cs-log-injection-taint", "A.cs", Safe, "class C { void Login([FromForm] string user) { _logger.LogInformation(\"login \" + user.Replace(\"\\n\", \"\")); } }"),
    case("cs-log-injection-taint", "A.cs", Static, "class C { void Start() { _logger.LogInformation(\"started\"); } }"),
    case("cs-log-injection-taint", "A.cs", Evasion, "class C { void Login() { var agent = Request.Headers[\"User-Agent\"]; Log.Warning($\"agent {agent}\"); } }"),
    // ── Kotlin ──────────────────────────────────────────────────────────────
    case("kotlin-sql-injection-taint", "a.kt", Positive, "class C {\n    fun find(@RequestParam id: String) {\n        jdbc.queryForList(\"SELECT * FROM users WHERE id = '$id'\")\n    }\n}"),
    case("kotlin-sql-injection-taint", "a.kt", Safe, "class C {\n    fun find(@RequestParam id: String) {\n        val n = id.toLong()\n        jdbc.queryForList(\"SELECT * FROM users WHERE id = \" + n)\n    }\n}"),
    case("kotlin-sql-injection-taint", "a.kt", Static, "class C {\n    fun count() {\n        jdbc.queryForList(\"SELECT COUNT(*) FROM users\")\n    }\n}"),
    case("kotlin-sql-injection-taint", "a.kt", Evasion, "class C {\n    fun del(req: HttpServletRequest) {\n        val name = req.getParameter(\"name\")\n        val sb = StringBuilder(\"DELETE FROM t WHERE name = \")\n        sb.append(name)\n        stmt.executeUpdate(sb.toString())\n    }\n}"),
    case("kotlin-command-injection-taint", "a.kt", Positive, "class C {\n    fun ping(@RequestParam host: String) {\n        Runtime.getRuntime().exec(\"ping -c 1 $host\")\n    }\n}"),
    case("kotlin-command-injection-taint", "a.kt", Safe, "class C {\n    fun probe(@RequestParam p: String) {\n        val port = p.toInt()\n        Runtime.getRuntime().exec(\"nc -z localhost $port\")\n    }\n}"),
    case("kotlin-command-injection-taint", "a.kt", Static, "class C {\n    fun list() {\n        Runtime.getRuntime().exec(\"ls -la\")\n    }\n}"),
    case("kotlin-command-injection-taint", "a.kt", Evasion, "class C {\n    fun run(@RequestBody script: String) {\n        val cmd = \"bash -c \" + script\n        ProcessBuilder(\"sh\", \"-c\", cmd).start()\n    }\n}"),
    case("kotlin-path-traversal-taint", "a.kt", Positive, "class C {\n    fun dl(@RequestParam(\"f\") name: String) {\n        FileInputStream(\"/srv/\" + name)\n    }\n}"),
    case("kotlin-path-traversal-taint", "a.kt", Safe, "class C {\n    fun dl(@RequestParam n: String) {\n        val id = n.toLong()\n        FileInputStream(\"/srv/$id.pdf\")\n    }\n}"),
    case("kotlin-path-traversal-taint", "a.kt", Static, "class C {\n    fun cfg() {\n        FileInputStream(\"config.properties\")\n    }\n}"),
    case("kotlin-path-traversal-taint", "a.kt", Evasion, "class C {\n    fun up(@PathVariable name: String) {\n        val dest = File(\"/uploads\", name)\n        FileOutputStream(dest)\n    }\n}"),
    case("kotlin-ssrf-taint", "a.kt", Positive, "class C {\n    fun fetch(@RequestParam target: String) {\n        URL(target).readText()\n    }\n}"),
    case("kotlin-ssrf-taint", "a.kt", Safe, "class C {\n    fun item(@RequestParam id: String) {\n        val n = id.toInt()\n        URL(\"https://api.example.org/items/$n\").readText()\n    }\n}"),
    case("kotlin-ssrf-taint", "a.kt", Static, "class C {\n    fun health() {\n        URL(\"https://example.org/health\").readText()\n    }\n}"),
    case("kotlin-ssrf-taint", "a.kt", Evasion, "class C {\n    fun call(req: HttpServletRequest) {\n        val host = req.getHeader(\"X-Host\")\n        val u = \"http://${host}/admin\"\n        URI(u)\n    }\n}"),
    case("kotlin-open-redirect-taint", "a.kt", Positive, "class C {\n    fun login(@RequestParam next: String, response: HttpServletResponse) {\n        response.sendRedirect(next)\n    }\n}"),
    case("kotlin-open-redirect-taint", "a.kt", Safe, "class C {\n    fun open(@RequestParam id: String, response: HttpServletResponse) {\n        response.sendRedirect(\"/items/\" + id.toLong())\n    }\n}"),
    case("kotlin-open-redirect-taint", "a.kt", Static, "class C {\n    fun logout(response: HttpServletResponse) {\n        response.sendRedirect(\"/login\")\n    }\n}"),
    case("kotlin-open-redirect-taint", "a.kt", Evasion, "class C {\n    fun done(req: HttpServletRequest, response: HttpServletResponse) {\n        var target = \"/\"\n        target = req.getParameter(\"next\")\n        response.sendRedirect(target)\n    }\n}"),
    case("kotlin-log-injection-taint", "a.kt", Positive, "class C {\n    fun login(@RequestParam user: String) {\n        log.info(\"User login: $user\")\n    }\n}"),
    case("kotlin-log-injection-taint", "a.kt", Safe, "class C {\n    fun login(@RequestParam id: String) {\n        log.info(\"User login: \" + id.toLong())\n    }\n}"),
    case("kotlin-log-injection-taint", "a.kt", Static, "class C {\n    fun start() {\n        log.info(\"Service started\")\n    }\n}"),
    case("kotlin-log-injection-taint", "a.kt", Evasion, "class C {\n    fun login(req: HttpServletRequest) {\n        val agent = req.getHeader(\"User-Agent\")\n        logger.warn(\"agent ${agent.trim()}\")\n    }\n}"),
    // ── Rust ────────────────────────────────────────────────────────────────
    case(
        "rust-sql-injection-taint",
        "a.rs",
        Positive,
        r#"
async fn find(Query(params): Query<HashMap<String, String>>, pool: PgPool) {
    let id = params.get("id").cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM users WHERE id = '{}'", id);
    sqlx::query(&sql).fetch_all(&pool).await.ok();
}"#,
    ),
    case(
        "rust-sql-injection-taint",
        "a.rs",
        Safe,
        r#"
async fn find(Query(params): Query<HashMap<String, String>>, pool: PgPool) {
    let id = params.get("id").cloned().unwrap_or_default();
    sqlx::query("SELECT * FROM users WHERE id = $1").bind(id).fetch_all(&pool).await.ok();
}"#,
    ),
    case(
        "rust-sql-injection-taint",
        "a.rs",
        Static,
        r#"
fn purge(conn: &Connection) {
    conn.execute("DELETE FROM sessions", []).ok();
}"#,
    ),
    case(
        "rust-sql-injection-taint",
        "a.rs",
        Evasion,
        r#"
async fn search(Json(body): Json<Search>, conn: Connection) {
    let mut sql = String::from("DELETE FROM items WHERE name = ");
    let term = body.term;
    sql.push_str(&format!("'{term}'"));
    conn.execute(&sql, []).ok();
}"#,
    ),
    case(
        "rust-command-injection-taint",
        "a.rs",
        Positive,
        r#"
async fn run(Query(q): Query<Cmd>) {
    Command::new(&q.program).spawn().ok();
}"#,
    ),
    case(
        "rust-command-injection-taint",
        "a.rs",
        Safe,
        r#"
async fn ping(Query(q): Query<Ping>) {
    Command::new("ping").arg("-c").arg("1").arg(&q.host).output().ok();
}"#,
    ),
    case(
        "rust-command-injection-taint",
        "a.rs",
        Static,
        r#"
fn list() {
    Command::new("ls").arg("-la").output().ok();
}"#,
    ),
    case(
        "rust-command-injection-taint",
        "a.rs",
        Evasion,
        r#"
fn main() {
    let line = std::env::args().nth(1).unwrap_or_default();
    Command::new("sh").arg("-c").arg(&line).status().ok();
}"#,
    ),
    case(
        "rust-ssrf-taint",
        "a.rs",
        Positive,
        r#"
async fn proxy(Query(q): Query<Proxy>) {
    reqwest::get(&q.url).await.ok();
}"#,
    ),
    case(
        "rust-ssrf-taint",
        "a.rs",
        Safe,
        r#"
async fn search(Query(q): Query<Search>, client: Client) {
    client.get("https://api.example.org/items").query(&[("q", &q.term)]).send().await.ok();
}"#,
    ),
    case(
        "rust-ssrf-taint",
        "a.rs",
        Static,
        r#"
async fn health() {
    reqwest::get("https://example.org/health").await.ok();
}"#,
    ),
    case(
        "rust-ssrf-taint",
        "a.rs",
        Evasion,
        r#"
impl Api {
    async fn admin(&self, Query(q): Query<Target>) {
        let target = format!("http://{}/admin", q.host);
        self.client.post(&target).send().await.ok();
    }
}"#,
    ),
    case(
        "rust-open-redirect-taint",
        "a.rs",
        Positive,
        r#"
async fn login(Query(q): Query<Login>) -> Redirect {
    Redirect::to(&q.next)
}"#,
    ),
    case(
        "rust-open-redirect-taint",
        "a.rs",
        Safe,
        r#"
async fn list(Query(q): Query<Page>) -> Redirect {
    let page = q.page.parse::<u32>().unwrap_or(1);
    Redirect::to(&format!("/list?page={page}"))
}"#,
    ),
    case(
        "rust-open-redirect-taint",
        "a.rs",
        Static,
        r#"
async fn logout() -> Redirect {
    Redirect::permanent("/login")
}"#,
    ),
    case(
        "rust-open-redirect-taint",
        "a.rs",
        Evasion,
        r#"
async fn done(q: web::Query<Done>) -> HttpResponse {
    let target = q.next.clone();
    HttpResponse::Found().insert_header((header::LOCATION, target.as_str())).finish()
}"#,
    ),
];

#[derive(Default)]
struct Score {
    tp: usize,
    fp: usize,
    fn_: usize,
    misses: Vec<String>,
}

/// Gate: precision ≥ 0.95 and recall ≥ 0.90 for every (rule, language).
#[test]
fn taint_corpus_precision_and_recall_per_rule_and_language() {
    let mut scores: BTreeMap<(&str, &str), Score> = BTreeMap::new();
    for (i, c) in CASES.iter().enumerate() {
        let findings = findings_for(c.file, c.src);
        let fired = findings.iter().any(|f| f.rule.id == c.rule);
        let ext = Path::new(c.file)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let score = scores.entry((c.rule, ext)).or_default();
        let expected = matches!(c.kind, Positive | Evasion);
        match (expected, fired) {
            (true, true) => score.tp += 1,
            (true, false) => {
                score.fn_ += 1;
                score.misses.push(format!("#{i} {:?}: missed", c.kind));
            }
            (false, true) => {
                score.fp += 1;
                score
                    .misses
                    .push(format!("#{i} {:?}: false positive", c.kind));
            }
            (false, false) => {}
        }
    }

    let mut failures = Vec::new();
    for ((rule, ext), s) in &scores {
        let precision = if s.tp + s.fp == 0 {
            1.0
        } else {
            s.tp as f64 / (s.tp + s.fp) as f64
        };
        let recall = if s.tp + s.fn_ == 0 {
            1.0
        } else {
            s.tp as f64 / (s.tp + s.fn_) as f64
        };
        if precision < 0.95 || recall < 0.90 {
            failures.push(format!(
                "{rule} [{ext}] precision={precision:.2} recall={recall:.2}: {}",
                s.misses.join("; ")
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "taint corpus gate failed:\n{}",
        failures.join("\n")
    );
}

/// Every taint rule has a positive, safe, static and evasion fixture.
#[test]
fn every_taint_rule_has_complete_fixtures() {
    for pack in rules::TAINT_PACKS {
        for rule in pack.rules {
            for kind in [Positive, Safe, Static, Evasion] {
                assert!(
                    CASES
                        .iter()
                        .any(|c| c.rule == rule.meta.id && c.kind == kind),
                    "{} has no {kind:?} fixture",
                    rule.meta.id
                );
            }
        }
    }
}

#[test]
fn write_sink_escalates_and_flow_has_source_and_sink_lines() {
    let src = r#"
public class VulnerableServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
    }
}"#;
    let findings = findings_for("A.java", src);
    let f = findings
        .iter()
        .find(|f| f.rule.id == "java-path-traversal-taint");
    assert!(
        f.is_some(),
        "expected a path traversal finding: {findings:?}"
    );
    if let Some(f) = f {
        assert!(f.is_write_sink, "FileOutputStream is a write sink");
        assert_eq!(f.line, 5);
        assert_eq!(f.flow, Some((4, 5)));
    }
}

#[test]
fn clean_reassignment_clears_taint_only_outside_branches() {
    let outside = r#"
class A {
    void f(@RequestParam String id, Statement st) throws Exception {
        String q = "SELECT * FROM t WHERE id = " + id;
        q = "SELECT 1";
        st.executeQuery(q);
    }
}"#;
    let inside = r#"
class A {
    void f(@RequestParam String id, Statement st, boolean admin) throws Exception {
        String q = "SELECT * FROM t WHERE id = " + id;
        if (admin) { q = "SELECT 1"; }
        st.executeQuery(q);
    }
}"#;
    let fires = |src| {
        findings_for("A.java", src)
            .iter()
            .any(|f| f.rule.id == "java-sql-injection-taint")
    };
    assert!(
        !fires(outside),
        "unconditional clean reassignment clears taint"
    );
    assert!(
        fires(inside),
        "conditional reassignment keeps taint (union of branches)"
    );
}

#[test]
fn taint_does_not_leak_across_functions() {
    let src = r#"
class A {
    void a(@RequestParam String id) { String q = id; }
    void b(Statement st) throws Exception { String q = "x"; st.executeQuery(q + id); }
}"#;
    let findings = findings_for("A.java", src);
    assert!(
        !findings
            .iter()
            .any(|f| f.rule.id == "java-sql-injection-taint"),
        "taint must be scoped per function: {findings:?}"
    );
}

#[test]
fn taint_finding_replaces_structural_finding_on_same_line() {
    let tainted = r#"
import subprocess
from flask import request

def run():
    subprocess.run(request.args["cmd"], shell=True)
"#;
    let constant = r#"
import subprocess

def run():
    subprocess.run("ls", shell=True)
"#;
    let ids = |src| -> Vec<&'static str> {
        findings_for("a.py", src)
            .iter()
            .map(|f| f.rule.id)
            .collect()
    };
    assert_eq!(ids(tainted), vec!["py-command-injection-taint"]);
    assert_eq!(ids(constant), vec!["py-command-injection-shell-true"]);
}

#[test]
fn format_args_parses_inline_names_only() {
    assert_eq!(
        format_args_in(r#""{id} {name:?} {0} {{lit}} {}""#),
        vec!["id", "name"]
    );
}

#[test]
fn parse_role_rejects_unknown_captures_and_keys() {
    let keys = ["sql"];
    assert_eq!(
        parse_role("sink.sql.write", &keys),
        Ok(Role::Sink {
            key: 0,
            write: true
        })
    );
    assert_eq!(parse_role("_helper", &keys), Ok(Role::Helper));
    assert!(parse_role("sink.cmd", &keys).is_err());
    assert!(parse_role("helper", &keys).is_err());
}

#[test]
fn every_taint_pack_compiles_for_each_language() {
    for pack in rules::TAINT_PACKS {
        for lang in pack.languages {
            let ts_lang = LANGUAGE_REGISTRY
                .iter()
                .find(|g| g.name() == *lang)
                .and_then(|g| g.tree_sitter_language());
            assert!(ts_lang.is_some(), "unknown taint language {lang}");
            if let Some(ts_lang) = ts_lang {
                let result = compile(pack, &ts_lang);
                assert!(result.is_ok(), "{lang}: {:?}", result.err());
            }
        }
    }
}

/// Parity with the former line-based Java detector on its fixture set.
#[test]
fn java_path_traversal_fixtures_keep_parity() {
    let fixtures = [
        (
            "SafeConfinement",
            include_str!("../../../tests/fixtures/java_path_traversal/SafeConfinement.java"),
            false,
        ),
        (
            "StaticFilesNoAlert",
            include_str!("../../../tests/fixtures/java_path_traversal/StaticFilesNoAlert.java"),
            false,
        ),
        (
            "VulnerableAbsoluteBypass",
            include_str!(
                "../../../tests/fixtures/java_path_traversal/VulnerableAbsoluteBypass.java"
            ),
            true,
        ),
        (
            "VulnerableSpringRead",
            include_str!("../../../tests/fixtures/java_path_traversal/VulnerableSpringRead.java"),
            true,
        ),
        (
            "VulnerableZipSlipWrite",
            include_str!("../../../tests/fixtures/java_path_traversal/VulnerableZipSlipWrite.java"),
            true,
        ),
    ];
    for (name, src, vulnerable) in fixtures {
        let fired = findings_for("A.java", src)
            .iter()
            .any(|f| f.rule.id == "java-path-traversal-taint");
        assert_eq!(fired, vulnerable, "{name}");
    }
}

/// SAST v2 §4.2.4: an N4 dynamic-SQL pattern is promoted to the taint finding
/// when a source reaches the same call, and stays a pattern otherwise.
#[test]
fn sql_dynamic_pattern_is_promoted_by_taint() {
    let tainted = "from flask import request\n\ndef f(cur):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + request.args[\"id\"])\n";
    let unproven = "def f(cur, uid):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + uid)\n";
    let ids = |src| -> Vec<&'static str> {
        findings_for("a.py", src)
            .iter()
            .map(|f| f.rule.id)
            .collect()
    };
    assert_eq!(ids(tainted), vec!["py-sql-injection-taint"]);
    assert_eq!(ids(unproven), vec!["py-sql-dynamic-construction"]);
}

// ── N2b: function summaries ──────────────────────────────────────────────────

fn ids(file: &str, src: &str) -> Vec<&'static str> {
    findings_for(file, src).iter().map(|f| f.rule.id).collect()
}

#[test]
fn flow_through_helper_that_reaches_a_sink() {
    let src = r#"
import os
from flask import request

def run_cmd(cmd):
    os.system("sh -c " + cmd)

def handler():
    run_cmd(request.args["c"])
"#;
    let findings = findings_for("a.py", src);
    let f = findings
        .iter()
        .find(|f| f.rule.id == "py-command-injection-taint" && f.line == 9)
        .expect("call to the helper is reported");
    assert!(f.description.contains("via run_cmd()"), "{}", f.description);
    assert_eq!(f.flow, Some((9, 9)));
    assert!(
        findings.iter().all(|f| f.line != 6),
        "the helper alone has no source: {findings:?}"
    );
}

#[test]
fn flow_through_helper_return_value() {
    let src = r#"
import os
from flask import request

def read_host():
    return request.args["host"]

def wrap(x):
    return "ping " + x

def handler():
    os.system(wrap(read_host()))
"#;
    assert_eq!(ids("a.py", src), vec!["py-command-injection-taint"]);
}

#[test]
fn helper_that_sanitizes_does_not_propagate() {
    let src = r#"
import os, shlex
from flask import request

def clean(x):
    return shlex.quote(x)

def handler():
    os.system("echo " + clean(request.args["c"]))
"#;
    assert!(ids("a.py", src).is_empty(), "{:?}", ids("a.py", src));
}

#[test]
fn clean_argument_to_sink_helper_is_not_reported() {
    let src = r#"
import os

def run_cmd(cmd):
    os.system(cmd)

def handler():
    run_cmd("uptime")
"#;
    assert!(ids("a.py", src).is_empty());
}

#[test]
fn flows_are_followed_through_three_nested_calls_but_not_four() {
    let chain = |extra: usize| {
        let mut s =
            String::from("import os\nfrom flask import request\n\ndef h0(x):\n    os.system(x)\n");
        for i in 1..=extra {
            s.push_str(&format!("\ndef h{i}(x):\n    h{}(x)\n", i - 1));
        }
        s.push_str(&format!(
            "\ndef handler():\n    h{extra}(request.args[\"c\"])\n"
        ));
        s
    };
    // handler → h2 → h1 → h0 is three nested calls.
    assert_eq!(ids("a.py", &chain(2)), vec!["py-command-injection-taint"]);
    assert!(
        ids("a.py", &chain(3)).is_empty(),
        "a fourth nested call is beyond depth {SUMMARY_DEPTH}"
    );
}

#[test]
fn ambiguous_function_names_are_not_resolved() {
    let src = r#"
import os
from flask import request

class A:
    def run(self, x):
        os.system(x)

class B:
    def run(self, x):
        print(x)

def handler(a):
    a.run(request.args["c"])
"#;
    // Only A.run's own body has a sink and `run` is defined twice: precision first.
    assert!(ids("a.py", src).is_empty(), "{:?}", ids("a.py", src));
}

#[test]
fn keyword_arguments_map_to_parameters_by_name() {
    let src = r#"
import os
from flask import request

def run(label, cmd):
    os.system(cmd)

def safe():
    run(label=request.args["l"], cmd="uptime")

def unsafe():
    run(cmd=request.args["c"], label="x")
"#;
    let lines: Vec<usize> = findings_for("a.py", src).iter().map(|f| f.line).collect();
    assert_eq!(lines, vec![12], "only the call passing input as `cmd`");
}

#[test]
fn recursion_terminates() {
    let src = "def f(x):\n    return g(x)\n\ndef g(x):\n    return f(x)\n";
    assert!(ids("a.py", src).is_empty());
}

#[test]
fn summaries_work_in_java_go_and_javascript() {
    let java = r#"
class A {
    void exec(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); }
    void handler(@RequestParam String c) throws Exception { exec("ping " + c); }
}"#;
    let go = "package a\n\nfunc run(c string) { exec.Command(\"sh\", \"-c\", c).Run() }\n\nfunc h(r *http.Request) { run(r.FormValue(\"c\")) }\n";
    let js = "function run(c) { require('child_process').exec(c); }\napp.get('/p', (req, res) => { run(req.query.c); });\n";
    let taint_only = |file: &str, src: &str| -> Vec<&'static str> {
        ids(file, src)
            .into_iter()
            .filter(|id| id.ends_with("-taint"))
            .collect()
    };
    assert_eq!(
        taint_only("A.java", java),
        vec!["java-command-injection-taint"]
    );
    assert_eq!(taint_only("a.go", go), vec!["go-command-injection-taint"]);
    assert_eq!(taint_only("a.js", js), vec!["js-command-injection-taint"]);
}

#[test]
fn project_summaries_resolve_calls_across_files() {
    let lib = "import os\n\ndef run_cmd(cmd):\n    os.system(cmd)\n";
    let app = "from flask import request\nfrom lib import run_cmd\n\ndef handler():\n    run_cmd(request.args[\"c\"])\n";
    let grammar = detect_grammar(Path::new("a.py")).expect("python grammar");

    assert!(
        audit_file_ast(app, grammar).is_empty(),
        "no summary for run_cmd in this file alone"
    );

    let mut known = Summaries::default();
    for _ in 0..SUMMARY_DEPTH {
        known = Summaries::from_entries(
            [lib, app]
                .iter()
                .flat_map(|src| crate::analyzer::summarize_file(src, grammar, &known)),
        );
    }
    let findings = crate::analyzer::audit_file_ast_with(app, grammar, &known);
    assert_eq!(
        findings.iter().map(|f| f.rule.id).collect::<Vec<_>>(),
        vec!["py-command-injection-taint"]
    );
    assert!(
        crate::analyzer::audit_file_ast_with(lib, grammar, &known).is_empty(),
        "the library alone has no source"
    );
}
