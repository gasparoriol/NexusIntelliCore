//! Labelled corpus for structural rules (SAST v2 §6): per rule and language,
//! a positive, a safe variant and an evasion (another spelling or API form
//! of the same weakness that must still be reported).

use super::*;
use crate::analyzer::{audit_file_ast, detect_grammar};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Positive,
    Safe,
    Evasion,
}
use Kind::{Evasion, Positive, Safe};

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

const CASES: &[Case] = &[
    // ── Fase 0 ──────────────────────────────────────────────────────────────
    case("rust-unsafe-code-block", "a.rs", Positive, "fn f(p: *mut u8) { unsafe { *p = 0; } }"),
    case("rust-unsafe-code-block", "a.rs", Safe, "fn f() {\n    // unsafe { not code }\n    let _x = 1;\n}"),
    case("rust-unsafe-code-block", "a.rs", Evasion, "fn f(p: *mut u8) {\n    unsafe\n    {\n        *p = 0;\n    }\n}"),
    case("rust-unsafe-code-fn", "a.rs", Positive, "pub unsafe fn raw(p: *mut u8) {}"),
    case("rust-unsafe-code-fn", "a.rs", Safe, "pub fn raw(p: *mut u8) {}"),
    case("rust-unsafe-code-fn", "a.rs", Evasion, "unsafe extern \"C\" fn callback() {}"),
    case("rust-unsafe-code-asm", "a.rs", Positive, "fn f() { unsafe { asm!(\"nop\"); } }"),
    case("rust-unsafe-code-asm", "a.rs", Safe, "fn f() { println!(\"asm\"); }"),
    case("rust-unsafe-code-asm", "a.rs", Evasion, "fn f() {\n    unsafe {\n        asm!(\n            \"nop\",\n        );\n    }\n}"),
    case("rust-uncaught-panic-unwrap", "a.rs", Positive, "fn f(x: Option<u8>) -> u8 { x.unwrap() }"),
    case("rust-uncaught-panic-unwrap", "a.rs", Safe, "fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }"),
    case("rust-uncaught-panic-unwrap", "a.rs", Evasion, "fn f(x: Result<u8, ()>) -> u8 { x.expect(\"present\") }"),
    case("js-code-injection-eval", "a.js", Positive, "function run(code) { return eval(code); }"),
    case("js-code-injection-eval", "a.js", Safe, "function run(code) { return JSON.parse(code); }"),
    case("js-code-injection-eval", "a.js", Evasion, "const out = eval(atob(payload));"),
    case("js-code-injection-new-function", "a.js", Positive, "const f = new Function(code);"),
    case("js-code-injection-new-function", "a.js", Safe, "const m = new Map();"),
    case("js-code-injection-new-function", "a.js", Evasion, "const f = new Function(\"a\", body);"),
    case("js-xss-inner-html", "a.js", Positive, "el.innerHTML = html;"),
    case("js-xss-inner-html", "a.js", Safe, "el.textContent = html;"),
    case("js-xss-inner-html", "a.js", Evasion, "document.getElementById(\"x\").innerHTML = \"<b>\" + name + \"</b>\";"),
    case("py-code-injection-eval", "a.py", Positive, "def run(expr):\n    return eval(expr)\n"),
    case("py-code-injection-eval", "a.py", Safe, "import ast\n\ndef run(expr):\n    return ast.literal_eval(expr)\n"),
    case("py-code-injection-eval", "a.py", Evasion, "def run(src):\n    exec(compile(src, \"x\", \"exec\"))\n"),
    case("py-command-injection-shell-true", "a.py", Positive, "import subprocess\nsubprocess.run(cmd, shell=True)\n"),
    case("py-command-injection-shell-true", "a.py", Safe, "import subprocess\nsubprocess.run([\"ls\", \"-l\"])\n"),
    case("py-command-injection-shell-true", "a.py", Evasion, "import subprocess\nsubprocess.Popen(\"ls \" + d, shell=True, cwd=\"/\")\n"),
    case("java-command-injection-exec", "A.java", Positive, "class A { void f(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); } }"),
    case("java-command-injection-exec", "A.java", Safe, "class A { void f() throws Exception { new ProcessBuilder(\"ls\").start(); } }"),
    case("java-command-injection-exec", "A.java", Evasion, "class A { void f(Runtime rt, String c) throws Exception { rt.exec(new String[]{\"sh\", \"-c\", c}); } }"),
    case("kotlin-code-injection-eval", "a.kt", Positive, "fun run(engine: ScriptEngine, script: String) = engine.eval(script)"),
    case("kotlin-code-injection-eval", "a.kt", Safe, "fun run(engine: ScriptEngine, script: String) = engine.compile(script)"),
    case("kotlin-code-injection-eval", "a.kt", Evasion, "fun run(script: String) = eval(script)"),
    // ── Java ────────────────────────────────────────────────────────────────
    case("java-weak-crypto-hash", "A.java", Positive, "class A { void f() throws Exception { MessageDigest md = MessageDigest.getInstance(\"MD5\"); } }"),
    case("java-weak-crypto-hash", "A.java", Safe, "class A { void f() throws Exception { MessageDigest md = MessageDigest.getInstance(\"SHA-256\"); } }"),
    case("java-weak-crypto-hash", "A.java", Evasion, "class A { String f(byte[] data) { return DigestUtils.sha1Hex(data); } }"),
    case("java-weak-crypto-cipher", "A.java", Positive, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"DES/CBC/PKCS5Padding\"); } }"),
    case("java-weak-crypto-cipher", "A.java", Safe, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\"); } }"),
    case("java-weak-crypto-cipher", "A.java", Evasion, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES\"); } }"),
    case("java-tls-validation-disabled", "A.java", Positive, r#"
class TrustAll implements X509TrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String auth) {}
    public void checkClientTrusted(X509Certificate[] chain, String auth) {}
    public X509Certificate[] getAcceptedIssuers() { return null; }
}"#),
    case("java-tls-validation-disabled", "A.java", Safe, r#"
class Pinned implements X509TrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
        delegate.checkServerTrusted(chain, auth);
    }
}"#),
    case("java-tls-validation-disabled", "A.java", Evasion, "class A { void f() { HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true); } }"),
    case("java-insecure-random-context", "A.java", Positive, "class A { void f() { String resetToken = Long.toHexString(new Random().nextLong()); } }"),
    case("java-insecure-random-context", "A.java", Safe, "class A { void backoff() { int jitter = new Random().nextInt(100); } }"),
    case("java-insecure-random-context", "A.java", Evasion, "class A { String generateSessionId() { return Integer.toString(ThreadLocalRandom.current().nextInt()); } }"),
    case("java-insecure-deserialization", "A.java", Positive, "class A { Object f(Socket s) throws Exception { ObjectInputStream in = new ObjectInputStream(s.getInputStream()); return in.readObject(); } }"),
    case("java-insecure-deserialization", "A.java", Safe, "class A { Item f(String json) throws Exception { return mapper.readValue(json, Item.class); } }"),
    case("java-insecure-deserialization", "A.java", Evasion, "class A { Object f(String xml) { return new XStream().fromXML(xml); } }"),
    case("java-csrf-protection-disabled", "A.java", Positive, "class A { void f(HttpSecurity http) throws Exception { http.csrf().disable(); } }"),
    case("java-csrf-protection-disabled", "A.java", Safe, "class A { void f(HttpSecurity http) throws Exception { http.csrf(c -> c.ignoringRequestMatchers(\"/webhook\")); } }"),
    case("java-csrf-protection-disabled", "A.java", Evasion, "class A { void f(HttpSecurity http) throws Exception { http.csrf(AbstractHttpConfigurer::disable); } }"),
    case("java-cors-wildcard-credentials", "A.java", Positive, "class A { @CrossOrigin(origins = \"*\", allowCredentials = \"true\") @GetMapping(\"/me\") String me() { return \"\"; } }"),
    case("java-cors-wildcard-credentials", "A.java", Safe, "class A { @CrossOrigin(origins = \"https://app.example.org\", allowCredentials = \"true\") @GetMapping(\"/me\") String me() { return \"\"; } }"),
    case("java-cors-wildcard-credentials", "A.java", Evasion, "class A { void f(CorsRegistry registry) { registry.addMapping(\"/**\").allowedOrigins(\"*\").allowCredentials(true); } }"),
    case("java-insecure-cookie-flag", "A.java", Positive, "class A { void f(Cookie cookie) { cookie.setSecure(false); } }"),
    case("java-insecure-cookie-flag", "A.java", Safe, "class A { void f(Cookie cookie) { cookie.setSecure(true); cookie.setHttpOnly(true); } }"),
    case("java-insecure-cookie-flag", "A.java", Evasion, "class A { void f(String v) { ResponseCookie c = ResponseCookie.from(\"sid\", v).httpOnly(false).build(); } }"),
    case("java-xxe-unhardened-parser", "A.java", Positive, r#"
class A {
    Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        return f.newDocumentBuilder().parse(in);
    }
}"#),
    case("java-xxe-unhardened-parser", "A.java", Safe, r#"
class A {
    Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return f.newDocumentBuilder().parse(in);
    }
}"#),
    case("java-xxe-unhardened-parser", "A.java", Evasion, "class A { void f() { XMLInputFactory xif = XMLInputFactory.newFactory(); } }"),
    // ── Kotlin ──────────────────────────────────────────────────────────────
    case("kotlin-weak-crypto-hash", "a.kt", Positive, "fun f() { val md = MessageDigest.getInstance(\"MD5\") }"),
    case("kotlin-weak-crypto-hash", "a.kt", Safe, "fun f() { val md = MessageDigest.getInstance(\"SHA-256\") }"),
    case("kotlin-weak-crypto-hash", "a.kt", Evasion, "fun f() { val md = MessageDigest.getInstance(\"sha1\") }"),
    case("kotlin-weak-crypto-cipher", "a.kt", Positive, "fun f() { val c = Cipher.getInstance(\"DES\") }"),
    case("kotlin-weak-crypto-cipher", "a.kt", Safe, "fun f() { val c = Cipher.getInstance(\"AES/GCM/NoPadding\") }"),
    case("kotlin-weak-crypto-cipher", "a.kt", Evasion, "fun f() { val c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\") }"),
    case("kotlin-insecure-deserialization", "a.kt", Positive, "fun f(input: InputStream) = ObjectInputStream(input).readObject()"),
    case("kotlin-insecure-deserialization", "a.kt", Safe, "fun f(s: String) = Json.decodeFromString<Item>(s)"),
    case("kotlin-insecure-deserialization", "a.kt", Evasion, "fun f(stream: InputStream) { val d = XMLDecoder(stream) }"),
    // ── Python ──────────────────────────────────────────────────────────────
    case("py-weak-crypto-hash", "a.py", Positive, "import hashlib\nh = hashlib.md5(data).hexdigest()\n"),
    case("py-weak-crypto-hash", "a.py", Safe, "import hashlib\nh = hashlib.md5(data, usedforsecurity=False).hexdigest()\n"),
    case("py-weak-crypto-hash", "a.py", Evasion, "import hashlib\nh = hashlib.new(\"sha1\", data)\n"),
    case("py-weak-crypto-cipher", "a.py", Positive, "from Crypto.Cipher import DES\nc = DES.new(key, DES.MODE_CBC)\n"),
    case("py-weak-crypto-cipher", "a.py", Safe, "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_GCM)\n"),
    case("py-weak-crypto-cipher", "a.py", Evasion, "c = Cipher(algorithms.AES(key), modes.ECB())\n"),
    case("py-tls-validation-disabled", "a.py", Positive, "import requests\nr = requests.get(url, verify=False)\n"),
    case("py-tls-validation-disabled", "a.py", Safe, "import requests\nr = requests.get(url, verify=\"/etc/ssl/ca.pem\")\n"),
    case("py-tls-validation-disabled", "a.py", Evasion, "import ssl\nctx = ssl.create_default_context()\nctx.verify_mode = ssl.CERT_NONE\n"),
    case("py-insecure-random-context", "a.py", Positive, "import random\n\ndef make_token():\n    return \"\".join(random.choice(ALPHABET) for _ in range(32))\n"),
    case("py-insecure-random-context", "a.py", Safe, "import random\n\ndef shuffle_deck(deck):\n    random.shuffle(deck)\n"),
    case("py-insecure-random-context", "a.py", Evasion, "import random\nreset_code = random.randint(100000, 999999)\n"),
    case("py-insecure-deserialization", "a.py", Positive, "import pickle\nobj = pickle.loads(blob)\n"),
    case("py-insecure-deserialization", "a.py", Safe, "import yaml\ncfg = yaml.load(f, Loader=yaml.SafeLoader)\n"),
    case("py-insecure-deserialization", "a.py", Evasion, "import yaml\ncfg = yaml.load(stream)\n"),
    case("py-csrf-protection-disabled", "a.py", Positive, "@csrf_exempt\ndef webhook(request):\n    pass\n"),
    case("py-csrf-protection-disabled", "a.py", Safe, "@login_required\ndef view(request):\n    pass\n"),
    case("py-csrf-protection-disabled", "a.py", Evasion, "app.config[\"WTF_CSRF_ENABLED\"] = False\n"),
    case("py-cors-wildcard-credentials", "a.py", Positive, "CORS(app, supports_credentials=True)\n"),
    case("py-cors-wildcard-credentials", "a.py", Safe, "CORS(app, origins=[\"https://app.example.org\"], supports_credentials=True)\n"),
    case("py-cors-wildcard-credentials", "a.py", Evasion, "CORS(app, origins=\"*\", supports_credentials=True)\n"),
    case("py-debug-mode-enabled", "a.py", Positive, "app.run(host=\"0.0.0.0\", debug=True)\n"),
    case("py-debug-mode-enabled", "a.py", Safe, "app.run(debug=False)\n"),
    case("py-debug-mode-enabled", "a.py", Evasion, "DEBUG = True\nALLOWED_HOSTS = []\n"),
    case("py-insecure-cookie-flag", "a.py", Positive, "resp.set_cookie(\"sid\", sid, secure=False)\n"),
    case("py-insecure-cookie-flag", "a.py", Safe, "resp.set_cookie(\"sid\", sid, secure=True, httponly=True)\n"),
    case("py-insecure-cookie-flag", "a.py", Evasion, "SESSION_COOKIE_SECURE = False\n"),
    case("py-xxe-entity-resolution", "a.py", Positive, "from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\n"),
    case("py-xxe-entity-resolution", "a.py", Safe, "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False)\n"),
    case("py-xxe-entity-resolution", "a.py", Evasion, "from lxml import etree\nparser = etree.XMLParser(no_network=False)\n"),
    // ── JavaScript ──────────────────────────────────────────────────────────
    case("js-weak-crypto-hash", "a.js", Positive, "const h = crypto.createHash('md5').update(s).digest('hex');"),
    case("js-weak-crypto-hash", "a.js", Safe, "const h = crypto.createHash('sha256').update(s).digest('hex');"),
    case("js-weak-crypto-hash", "a.js", Evasion, "const h = CryptoJS.SHA1(msg).toString();"),
    case("js-weak-crypto-cipher", "a.js", Positive, "const c = crypto.createCipheriv('des-ede3-cbc', key, iv);"),
    case("js-weak-crypto-cipher", "a.js", Safe, "const c = crypto.createCipheriv('aes-256-gcm', key, iv);"),
    case("js-weak-crypto-cipher", "a.js", Evasion, "const c = crypto.createCipheriv('aes-128-ecb', key, null);"),
    case("js-tls-validation-disabled", "a.js", Positive, "https.request({ host, rejectUnauthorized: false });"),
    case("js-tls-validation-disabled", "a.js", Safe, "https.request({ host, ca });"),
    case("js-tls-validation-disabled", "a.js", Evasion, "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"),
    case("js-insecure-random-context", "a.js", Positive, "const resetToken = Math.random().toString(36).slice(2);"),
    case("js-insecure-random-context", "a.js", Safe, "const jitter = Math.random() * 100;"),
    case("js-insecure-random-context", "a.js", Evasion, "function generateCsrf() { return Math.floor(Math.random() * 1e9); }"),
    case("js-insecure-deserialization", "a.js", Positive, "const obj = serialize.unserialize(data);"),
    case("js-insecure-deserialization", "a.js", Safe, "const obj = JSON.parse(data);"),
    case("js-insecure-deserialization", "a.js", Evasion, "const { unserialize } = require('node-serialize');\nunserialize(payload);"),
    case("js-cors-wildcard-credentials", "a.js", Positive, "app.use(cors({ origin: true, credentials: true }));"),
    case("js-cors-wildcard-credentials", "a.js", Safe, "app.use(cors({ origin: 'https://app.example.org', credentials: true }));"),
    case("js-cors-wildcard-credentials", "a.js", Evasion, "app.enableCors({ origin: '*', credentials: true });"),
    case("js-insecure-cookie-flag", "a.js", Positive, "res.cookie('sid', id, { httpOnly: false });"),
    case("js-insecure-cookie-flag", "a.js", Safe, "res.cookie('sid', id, { httpOnly: true, secure: true });"),
    case("js-insecure-cookie-flag", "a.js", Evasion, "app.use(session({ name: 'sid', cookie: { secure: false } }));"),
    // ── Go ──────────────────────────────────────────────────────────────────
    case("go-weak-crypto-hash", "a.go", Positive, "package a\n\nfunc f() { h := md5.New(); _ = h }\n"),
    case("go-weak-crypto-hash", "a.go", Safe, "package a\n\nfunc f() { h := sha256.New(); _ = h }\n"),
    case("go-weak-crypto-hash", "a.go", Evasion, "package a\n\nfunc f(data []byte) { sum := sha1.Sum(data); _ = sum }\n"),
    case("go-weak-crypto-cipher", "a.go", Positive, "package a\n\nfunc f(key []byte) { block, _ := des.NewCipher(key); _ = block }\n"),
    case("go-weak-crypto-cipher", "a.go", Safe, "package a\n\nfunc f(key []byte) { block, _ := aes.NewCipher(key); _ = block }\n"),
    case("go-weak-crypto-cipher", "a.go", Evasion, "package a\n\nfunc f(key []byte) { c, _ := rc4.NewCipher(key); _ = c }\n"),
    case("go-tls-validation-disabled", "a.go", Positive, "package a\n\nfunc f() { cfg := &tls.Config{InsecureSkipVerify: true}; _ = cfg }\n"),
    case("go-tls-validation-disabled", "a.go", Safe, "package a\n\nfunc f() { cfg := &tls.Config{MinVersion: tls.VersionTLS12}; _ = cfg }\n"),
    case("go-tls-validation-disabled", "a.go", Evasion, "package a\n\nfunc f(cfg *tls.Config) { cfg.InsecureSkipVerify = true }\n"),
    case("go-insecure-random-context", "a.go", Positive, "package a\n\nfunc newSessionID() string { return strconv.Itoa(rand.Intn(1 << 30)) }\n"),
    case("go-insecure-random-context", "a.go", Safe, "package a\n\nfunc jitter() time.Duration { return time.Duration(rand.Intn(100)) }\n"),
    case("go-insecure-random-context", "a.go", Evasion, "package a\n\nfunc f() { token := rand.Int63(); _ = token }\n"),
    case("go-cors-wildcard-credentials", "a.go", Positive, "package a\n\nfunc f() { r.Use(cors.New(cors.Config{AllowOrigins: []string{\"*\"}, AllowCredentials: true})) }\n"),
    case("go-cors-wildcard-credentials", "a.go", Safe, "package a\n\nfunc f() { r.Use(cors.New(cors.Config{AllowOrigins: []string{\"https://app.example.org\"}, AllowCredentials: true})) }\n"),
    case("go-cors-wildcard-credentials", "a.go", Evasion, "package a\n\nfunc f() { r.Use(cors.New(cors.Config{AllowAllOrigins: true, AllowCredentials: true})) }\n"),
    case("go-insecure-cookie-flag", "a.go", Positive, "package a\n\nfunc f(w http.ResponseWriter, v string) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: v, HttpOnly: false}) }\n"),
    case("go-insecure-cookie-flag", "a.go", Safe, "package a\n\nfunc f(w http.ResponseWriter, v string) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: v, HttpOnly: true, Secure: true}) }\n"),
    case("go-insecure-cookie-flag", "a.go", Evasion, "package a\n\nfunc f() { c := http.Cookie{\n\tName:   \"sid\",\n\tSecure: false,\n}; _ = c }\n"),
    // ── C# ──────────────────────────────────────────────────────────────────
    case("cs-weak-crypto-hash", "A.cs", Positive, "class A { void F() { using var md5 = MD5.Create(); } }"),
    case("cs-weak-crypto-hash", "A.cs", Safe, "class A { void F() { using var sha = SHA256.Create(); } }"),
    case("cs-weak-crypto-hash", "A.cs", Evasion, "class A { void F() { var h = new SHA1Managed(); } }"),
    case("cs-weak-crypto-cipher", "A.cs", Positive, "class A { void F() { var des = DES.Create(); } }"),
    case("cs-weak-crypto-cipher", "A.cs", Safe, "class A { void F() { var aes = Aes.Create(); } }"),
    case("cs-weak-crypto-cipher", "A.cs", Evasion, "class A { void F(Aes aes) { aes.Mode = CipherMode.ECB; } }"),
    case("cs-tls-validation-disabled", "A.cs", Positive, "class A { void F(HttpClientHandler handler) { handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true; } }"),
    case("cs-tls-validation-disabled", "A.cs", Safe, "class A { void F(HttpClientHandler handler) { handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == SslPolicyErrors.None; } }"),
    case("cs-tls-validation-disabled", "A.cs", Evasion, "class A { void F(HttpClientHandler handler) { handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; } }"),
    case("cs-insecure-random-context", "A.cs", Positive, "class A { void F() { var tokenRng = new Random(); } }"),
    case("cs-insecure-random-context", "A.cs", Safe, "class A { void Shuffle() { var rng = new Random(); } }"),
    case("cs-insecure-random-context", "A.cs", Evasion, "class A { string GenerateResetCode() { return new Random().Next(100000, 999999).ToString(); } }"),
    case("cs-insecure-deserialization", "A.cs", Positive, "class A { void F() { var f = new BinaryFormatter(); } }"),
    case("cs-insecure-deserialization", "A.cs", Safe, "class A { Item F(string json) { return JsonSerializer.Deserialize<Item>(json); } }"),
    case("cs-insecure-deserialization", "A.cs", Evasion, "class A { void F() { var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }; } }"),
    case("cs-csrf-protection-disabled", "A.cs", Positive, "class A : Controller { [IgnoreAntiforgeryToken] public IActionResult Post() => Ok(); }"),
    case("cs-csrf-protection-disabled", "A.cs", Safe, "class A : Controller { [ValidateAntiForgeryToken] public IActionResult Post() => Ok(); }"),
    case("cs-csrf-protection-disabled", "A.cs", Evasion, "[IgnoreAntiforgeryToken(Order = 1001)]\npublic class ApiController : Controller {}"),
    case("cs-cors-wildcard-credentials", "A.cs", Positive, "class A { void F(CorsPolicyBuilder policy) { policy.AllowAnyOrigin().AllowCredentials(); } }"),
    case("cs-cors-wildcard-credentials", "A.cs", Safe, "class A { void F(CorsPolicyBuilder policy) { policy.WithOrigins(\"https://app.example.org\").AllowCredentials(); } }"),
    case("cs-cors-wildcard-credentials", "A.cs", Evasion, "class A { void F(CorsPolicyBuilder policy) { policy.SetIsOriginAllowed(_ => true).AllowCredentials(); } }"),
    case("cs-debug-mode-enabled", "A.cs", Positive, "class Startup { void Configure(IApplicationBuilder app) { app.UseDeveloperExceptionPage(); } }"),
    case("cs-debug-mode-enabled", "A.cs", Safe, "class Startup { void Configure(IApplicationBuilder app, IWebHostEnvironment env) { if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); } } }"),
    case("cs-debug-mode-enabled", "A.cs", Evasion, "class Startup { void Configure(IApplicationBuilder app) { app.UseDatabaseErrorPage(); } }"),
    case("cs-insecure-cookie-flag", "A.cs", Positive, "class A { void F() { var o = new CookieOptions { Secure = false }; } }"),
    case("cs-insecure-cookie-flag", "A.cs", Safe, "class A { void F() { var o = new CookieOptions { Secure = true, HttpOnly = true }; } }"),
    case("cs-insecure-cookie-flag", "A.cs", Evasion, "class A { void F(CookieAuthenticationOptions options) { options.Cookie.SecurePolicy = CookieSecurePolicy.None; } }"),
    case("cs-xxe-dtd-processing", "A.cs", Positive, "class A { void F(XmlReaderSettings settings) { settings.DtdProcessing = DtdProcessing.Parse; } }"),
    case("cs-xxe-dtd-processing", "A.cs", Safe, "class A { void F(XmlReaderSettings settings) { settings.DtdProcessing = DtdProcessing.Prohibit; } }"),
    case("cs-xxe-dtd-processing", "A.cs", Evasion, "class A { void F(XmlDocument doc) { doc.XmlResolver = new XmlUrlResolver(); } }"),
    // ── Rust ────────────────────────────────────────────────────────────────
    case("rust-weak-crypto-hash", "a.rs", Positive, "fn f(data: &[u8]) { let d = md5::compute(data); }"),
    case("rust-weak-crypto-hash", "a.rs", Safe, "fn f(data: &[u8]) { let d = Sha256::digest(data); }"),
    case("rust-weak-crypto-hash", "a.rs", Evasion, "fn f() { let mut h = Sha1::new(); }"),
    case("rust-weak-crypto-cipher", "a.rs", Positive, "fn f(key: &[u8]) { let c = Des::new_from_slice(key); }"),
    case("rust-weak-crypto-cipher", "a.rs", Safe, "fn f(key: &[u8]) { let c = Aes256Gcm::new_from_slice(key); }"),
    case("rust-weak-crypto-cipher", "a.rs", Evasion, "fn f(key: &[u8; 16]) { let enc = ecb::Encryptor::<Aes128>::new(key.into()); }"),
    case("rust-tls-validation-disabled", "a.rs", Positive, "fn f() { let c = Client::builder().danger_accept_invalid_certs(true).build(); }"),
    case("rust-tls-validation-disabled", "a.rs", Safe, "fn f() { let c = Client::builder().danger_accept_invalid_certs(false).build(); }"),
    case("rust-tls-validation-disabled", "a.rs", Evasion, "fn f(builder: &mut SslConnectorBuilder) { builder.set_verify(SslVerifyMode::NONE); }"),
    case("rust-insecure-cookie-flag", "a.rs", Positive, "fn f(v: String) { let c = Cookie::build((\"sid\", v)).secure(false).build(); }"),
    case("rust-insecure-cookie-flag", "a.rs", Safe, "fn f(v: String) { let c = Cookie::build((\"sid\", v)).secure(true).http_only(true).build(); }"),
    case("rust-insecure-cookie-flag", "a.rs", Evasion, "fn f(v: String) { let c = Cookie::build((\"sid\", v)).http_only(false).build(); }"),
    // ── C ───────────────────────────────────────────────────────────────────
    case("c-weak-crypto-hash", "a.c", Positive, "void f(const unsigned char *d, size_t n, unsigned char *out) { MD5(d, n, out); }"),
    case("c-weak-crypto-hash", "a.c", Safe, "void f(const unsigned char *d, size_t n, unsigned char *out) { SHA256(d, n, out); }"),
    case("c-weak-crypto-hash", "a.c", Evasion, "void f(EVP_MD_CTX *ctx) { EVP_DigestInit_ex(ctx, EVP_sha1(), NULL); }"),
    case("c-weak-crypto-cipher", "a.c", Positive, "void f(EVP_CIPHER_CTX *ctx) { EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv); }"),
    case("c-weak-crypto-cipher", "a.c", Safe, "void f(EVP_CIPHER_CTX *ctx) { EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv); }"),
    case("c-weak-crypto-cipher", "a.c", Evasion, "void f(EVP_CIPHER_CTX *ctx) { EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL); }"),
    case("c-tls-validation-disabled", "a.c", Positive, "void f(SSL_CTX *ctx) { SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); }"),
    case("c-tls-validation-disabled", "a.c", Safe, "void f(SSL_CTX *ctx) { SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); }"),
    case("c-tls-validation-disabled", "a.c", Evasion, "void f(CURL *h) { curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L); }"),
    case("c-insecure-random-context", "a.c", Positive, "void f(void) { int session_id = rand(); }"),
    case("c-insecure-random-context", "a.c", Safe, "int roll(void) { int dice = rand() % 6; return dice; }"),
    case("c-insecure-random-context", "a.c", Evasion, "unsigned gen_token(void) { return (unsigned)rand(); }"),
    case("c-dangerous-function-gets", "a.c", Positive, "void f(void) { char buf[64]; gets(buf); }"),
    case("c-dangerous-function-gets", "a.c", Safe, "void f(void) { char buf[64]; fgets(buf, sizeof buf, stdin); }"),
    case("c-dangerous-function-gets", "a.c", Evasion, "int f(char *line) { if (gets(line) == NULL) return -1; return 0; }"),
    case("c-buffer-overflow-unbounded-copy", "a.c", Positive, "void f(char *dst, const char *src) { strcpy(dst, src); }"),
    case("c-buffer-overflow-unbounded-copy", "a.c", Safe, "void f(char *dst, const char *src, size_t n) { snprintf(dst, n, \"%s\", src); }"),
    case("c-buffer-overflow-unbounded-copy", "a.c", Evasion, "void f(char *out, const char *a, const char *b) { sprintf(out, \"%s-%s\", a, b); }"),
    case("c-buffer-overflow-scanf", "a.c", Positive, "void f(void) { char name[64]; scanf(\"%s\", name); }"),
    case("c-buffer-overflow-scanf", "a.c", Safe, "void f(void) { char name[64]; scanf(\"%63s\", name); }"),
    case("c-buffer-overflow-scanf", "a.c", Evasion, "void f(const char *line) { int id; char name[64]; sscanf(line, \"%d %s\", &id, name); }"),
    case("c-format-string-variable", "a.c", Positive, "void f(const char *msg) { printf(msg); }"),
    case("c-format-string-variable", "a.c", Safe, "void f(const char *msg) { printf(\"%s\", msg); }"),
    case("c-format-string-variable", "a.c", Evasion, "void f(struct user *u) { fprintf(stderr, u->name); }"),
    // ── Fase 3: N4 risk patterns ────────────────────────────────────────────
    case("java-sql-dynamic-construction", "A.java", Positive, "class A { void f(Statement st, String id) throws Exception { st.executeQuery(\"SELECT * FROM t WHERE id = \" + id); } }"),
    case("java-sql-dynamic-construction", "A.java", Safe, "class A { void f(Statement st) throws Exception { st.executeQuery(\"SELECT * FROM t\"); } }"),
    case("java-sql-dynamic-construction", "A.java", Evasion, "class A { void f(Statement st, String id) throws Exception { st.executeUpdate(String.format(\"DELETE FROM t WHERE id = %s\", id)); } }"),
    case("py-sql-dynamic-construction", "a.py", Positive, "def f(cur, uid):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + uid)\n"),
    case("py-sql-dynamic-construction", "a.py", Safe, "def f(cur, uid):\n    cur.execute(\"SELECT * FROM t WHERE id = %s\", (uid,))\n"),
    case("py-sql-dynamic-construction", "a.py", Evasion, "def f(cur, uid):\n    cur.execute(f\"DELETE FROM t WHERE id = {uid}\")\n"),
    case("js-sql-dynamic-construction", "a.js", Positive, "function f(db, id) { return db.query(\"SELECT * FROM t WHERE id = \" + id); }"),
    case("js-sql-dynamic-construction", "a.js", Safe, "function f(db, id) { return db.query(\"SELECT * FROM t WHERE id = ?\", [id]); }"),
    case("js-sql-dynamic-construction", "a.js", Evasion, "function f(db, name) { return db.query(`UPDATE t SET name = '${name}' WHERE id = 1`); }"),
    case("go-sql-dynamic-construction", "a.go", Positive, "package a\n\nfunc f(db *sql.DB, id string) { db.Query(\"SELECT * FROM t WHERE id = \" + id) }\n"),
    case("go-sql-dynamic-construction", "a.go", Safe, "package a\n\nfunc f(db *sql.DB, id string) { db.Query(\"SELECT * FROM t WHERE id = $1\", id) }\n"),
    case("go-sql-dynamic-construction", "a.go", Evasion, "package a\n\nfunc f(ctx context.Context, db *sql.DB, id string) { db.ExecContext(ctx, fmt.Sprintf(\"DELETE FROM t WHERE id = %s\", id)) }\n"),
    case("cs-sql-dynamic-construction", "A.cs", Positive, "class A { void F(string id) { var c = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id); } }"),
    case("cs-sql-dynamic-construction", "A.cs", Safe, "class A { void F() { var c = new SqlCommand(\"SELECT * FROM t WHERE id = @id\"); } }"),
    case("cs-sql-dynamic-construction", "A.cs", Evasion, "class A { void F(Db db, string id) { db.Database.ExecuteSqlRaw($\"DELETE FROM t WHERE id = {id}\"); } }"),
    case("rust-sql-dynamic-construction", "a.rs", Positive, "fn f(conn: &Connection, id: &str) { conn.execute(&format!(\"DELETE FROM t WHERE id = {id}\"), []).ok(); }"),
    case("rust-sql-dynamic-construction", "a.rs", Safe, "fn f(conn: &Connection, id: &str) { conn.execute(\"DELETE FROM t WHERE id = ?1\", [id]).ok(); }"),
    case("rust-sql-dynamic-construction", "a.rs", Evasion, "fn f(id: &str) { let q = diesel::sql_query(format!(\"SELECT * FROM t WHERE id = {}\", id)); }"),
    case("java-error-swallowed-catch", "A.java", Positive, "class A { void f() { try { run(); } catch (Exception e) {} } }"),
    case("java-error-swallowed-catch", "A.java", Safe, "class A { void f() { try { run(); } catch (Exception e) { log.warn(\"failed\", e); } } }"),
    case("java-error-swallowed-catch", "A.java", Evasion, "class A { void f() { try { run(); } catch (IOException ignored) {\n\n} } }"),
    case("js-error-swallowed-catch", "a.js", Positive, "try { run(); } catch (e) {}"),
    case("js-error-swallowed-catch", "a.js", Safe, "try { run(); } catch (e) { logger.error(e); }"),
    case("js-error-swallowed-catch", "a.js", Evasion, "try { run(); } catch {\n}"),
    case("cs-error-swallowed-catch", "A.cs", Positive, "class A { void F() { try { Run(); } catch (Exception) {} } }"),
    case("cs-error-swallowed-catch", "A.cs", Safe, "class A { void F() { try { Run(); } catch (Exception e) { _log.LogError(e, \"x\"); } } }"),
    case("cs-error-swallowed-catch", "A.cs", Evasion, "class A { void F() { try { Run(); } catch {\n} } }"),
    case("py-error-swallowed-except", "a.py", Positive, "try:\n    run()\nexcept Exception:\n    pass\n"),
    case("py-error-swallowed-except", "a.py", Safe, "try:\n    run()\nexcept Exception as e:\n    log.warning(e)\n"),
    case("py-error-swallowed-except", "a.py", Evasion, "try:\n    run()\nexcept:\n    pass\n"),
    case("go-error-ignored-check", "a.go", Positive, "package a\n\nfunc f() { if err := run(); err != nil {} }\n"),
    case("go-error-ignored-check", "a.go", Safe, "package a\n\nfunc f() error { if err := run(); err != nil { return err }; return nil }\n"),
    case("go-error-ignored-check", "a.go", Evasion, "package a\n\nfunc f() {\n\terr := run()\n\tif err != nil {\n\t}\n}\n"),
    case("java-fail-open-catch", "A.java", Positive, "class A { boolean isAuthorized(User u) { try { return acl.check(u); } catch (Exception e) { return true; } } }"),
    case("java-fail-open-catch", "A.java", Safe, "class A { boolean isAuthorized(User u) { try { return acl.check(u); } catch (Exception e) { return false; } } }"),
    case("java-fail-open-catch", "A.java", Evasion, "class A { boolean hasPermission(String r) { try { return svc.allows(r); } catch (RuntimeException e) { log.warn(\"x\"); return true; } } }"),
    case("js-fail-open-catch", "a.js", Positive, "function canAccess(user) { try { return policy.check(user); } catch (e) { return true; } }"),
    case("js-fail-open-catch", "a.js", Safe, "function canAccess(user) { try { return policy.check(user); } catch (e) { return false; } }"),
    case("js-fail-open-catch", "a.js", Evasion, "const verifyToken = async (t) => { try { await jwt.verify(t); return true; } catch (err) { return true; } };"),
    case("py-fail-open-except", "a.py", Positive, "def is_admin(user):\n    try:\n        return lookup(user).admin\n    except Exception:\n        return True\n"),
    case("py-fail-open-except", "a.py", Safe, "def is_admin(user):\n    try:\n        return lookup(user).admin\n    except Exception:\n        return False\n"),
    case("py-fail-open-except", "a.py", Evasion, "def check_access(req):\n    try:\n        validate(req)\n    except KeyError:\n        log.warning(\"missing\")\n        return True\n"),
    case("cs-fail-open-catch", "A.cs", Positive, "class A { bool IsAuthorized(User u) { try { return Acl.Check(u); } catch (Exception) { return true; } } }"),
    case("cs-fail-open-catch", "A.cs", Safe, "class A { bool IsAuthorized(User u) { try { return Acl.Check(u); } catch (Exception) { return false; } } }"),
    case("cs-fail-open-catch", "A.cs", Evasion, "class A { bool ValidateLicense(string k) { try { return Lic.Check(k); } catch { return true; } } }"),
    case("java-timing-unsafe-compare", "A.java", Positive, "class A { boolean ok(String token, String expected) { return token.equals(expected); } }"),
    case("java-timing-unsafe-compare", "A.java", Safe, "class A { boolean ok(String token, String expected) { return MessageDigest.isEqual(token.getBytes(), expected.getBytes()); } }"),
    case("java-timing-unsafe-compare", "A.java", Evasion, "class A { boolean ok(String expectedSignature, String sig) { return expectedSignature.contentEquals(sig); } }"),
    case("py-timing-unsafe-compare", "a.py", Positive, "def ok(token, expected):\n    return token == expected\n"),
    case("py-timing-unsafe-compare", "a.py", Safe, "import hmac\n\ndef ok(token, expected):\n    return hmac.compare_digest(token, expected)\n"),
    case("py-timing-unsafe-compare", "a.py", Evasion, "def ok(request, computed_signature):\n    return request.headers[\"X-Signature\"] == computed_signature\n"),
    case("js-timing-unsafe-compare", "a.js", Positive, "function ok(token, expected) { return token === expected; }"),
    case("js-timing-unsafe-compare", "a.js", Safe, "function ok(token, expected) { return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected)); }"),
    case("js-timing-unsafe-compare", "a.js", Evasion, "function ok(req, computedHmac) { return req.headers['x-hub-signature'] == computedHmac; }"),
    case("go-timing-unsafe-compare", "a.go", Positive, "package a\n\nfunc ok(token, expected string) bool { return token == expected }\n"),
    case("go-timing-unsafe-compare", "a.go", Safe, "package a\n\nfunc ok(token, expected string) bool { return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 }\n"),
    case("go-timing-unsafe-compare", "a.go", Evasion, "package a\n\nfunc ok(hmac string, r *http.Request) bool { return hmac == r.Header.Get(\"X-Mac\") }\n"),
    case("cs-timing-unsafe-compare", "A.cs", Positive, "class A { bool Ok(string token, string expected) => token == expected; }"),
    case("cs-timing-unsafe-compare", "A.cs", Safe, "class A { bool Ok(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b); }"),
    case("cs-timing-unsafe-compare", "A.cs", Evasion, "class A { bool Ok(string apiKey) { return apiKey == _settings.ApiKey; } }"),
    case("rust-timing-unsafe-compare", "a.rs", Positive, "fn ok(token: &str, expected: &str) -> bool { token == expected }"),
    case("rust-timing-unsafe-compare", "a.rs", Safe, "fn ok(token: &[u8], expected: &[u8]) -> bool { constant_time_eq(token, expected) }"),
    case("rust-timing-unsafe-compare", "a.rs", Evasion, "fn ok(sig: &str, signature: &str) -> bool { sig == signature }"),
    case("c-timing-unsafe-compare", "a.c", Positive, "int ok(const char *token, const char *expected) { return strcmp(token, expected) == 0; }"),
    case("c-timing-unsafe-compare", "a.c", Safe, "int ok(const char *token, const char *expected, size_t n) { return CRYPTO_memcmp(token, expected, n) == 0; }"),
    case("c-timing-unsafe-compare", "a.c", Evasion, "int ok(const unsigned char *hmac, const unsigned char *computed) { return memcmp(hmac, computed, 32) == 0; }"),
    case("java-secret-in-log", "A.java", Positive, "class A { void f(String password) { log.info(\"pw=\" + password); } }"),
    case("java-secret-in-log", "A.java", Safe, "class A { void f(String username) { log.info(\"login for \" + username); } }"),
    case("java-secret-in-log", "A.java", Evasion, "class A { void f(String apiToken) { System.out.println(apiToken); } }"),
    case("py-secret-in-log", "a.py", Positive, "def f(password):\n    print(password)\n"),
    case("py-secret-in-log", "a.py", Safe, "def f(username):\n    logger.info(\"login %s\", username)\n"),
    case("py-secret-in-log", "a.py", Evasion, "def f(user):\n    logger.info(f\"token={user.api_token}\")\n"),
    case("js-secret-in-log", "a.js", Positive, "function f(token) { console.log(token); }"),
    case("js-secret-in-log", "a.js", Safe, "function f(userId) { console.log(userId); }"),
    case("js-secret-in-log", "a.js", Evasion, "function f(user) { logger.info(`login ${user.password}`); }"),
    case("go-secret-in-log", "a.go", Positive, "package a\n\nfunc f(password string) { log.Println(password) }\n"),
    case("go-secret-in-log", "a.go", Safe, "package a\n\nfunc f(username string) { log.Println(username) }\n"),
    case("go-secret-in-log", "a.go", Evasion, "package a\n\nfunc f(cfg Config) { fmt.Printf(\"%s\\n\", cfg.APIToken) }\n"),
    case("cs-secret-in-log", "A.cs", Positive, "class A { void F(string password) { Console.WriteLine(password); } }"),
    case("cs-secret-in-log", "A.cs", Safe, "class A { void F(string userName) { Console.WriteLine(userName); } }"),
    case("cs-secret-in-log", "A.cs", Evasion, "class A { void F(Settings settings) { _logger.LogInformation(\"key {Key}\", settings.ApiKey); } }"),
    case("java-weak-blacklist-validation", "A.java", Positive, "class A { String f(String path) { return path.replace(\"../\", \"\"); } }"),
    case("java-weak-blacklist-validation", "A.java", Safe, "class A { String f(String path) { return path.replace(\"-\", \"_\"); } }"),
    case("java-weak-blacklist-validation", "A.java", Evasion, "class A { void f(String name) { if (!name.contains(\"..\")) { open(name); } } }"),
    case("py-weak-blacklist-validation", "a.py", Positive, "def f(path):\n    return path.replace(\"../\", \"\")\n"),
    case("py-weak-blacklist-validation", "a.py", Safe, "def f(name):\n    return name.replace(\" \", \"_\")\n"),
    case("py-weak-blacklist-validation", "a.py", Evasion, "def f(path):\n    if \"..\" in path:\n        raise ValueError()\n"),
    case("js-weak-blacklist-validation", "a.js", Positive, "const clean = p.replace(/\\.\\.\\//g, '');"),
    case("js-weak-blacklist-validation", "a.js", Safe, "const clean = p.replace(/-/g, '_');"),
    case("js-weak-blacklist-validation", "a.js", Evasion, "html = html.replace('<script>', '');"),
    case("go-weak-blacklist-validation", "a.go", Positive, "package a\n\nfunc f(p string) string { return strings.ReplaceAll(p, \"../\", \"\") }\n"),
    case("go-weak-blacklist-validation", "a.go", Safe, "package a\n\nfunc f(p string) string { return filepath.Clean(p) }\n"),
    case("go-weak-blacklist-validation", "a.go", Evasion, "package a\n\nfunc f(p string) string { return strings.Replace(p, \"..\\\\\", \"\", -1) }\n"),
    case("cs-weak-blacklist-validation", "A.cs", Positive, "class A { string F(string path) => path.Replace(\"../\", \"\"); }"),
    case("cs-weak-blacklist-validation", "A.cs", Safe, "class A { string F(string path) => Path.GetFileName(path); }"),
    case("cs-weak-blacklist-validation", "A.cs", Evasion, "class A { string F(string html) => html.Replace(\"<script>\", \"\"); }"),
    case("java-unsafe-reflection-dynamic", "A.java", Positive, "class A { void f(String className) throws Exception { Class<?> c = Class.forName(className); } }"),
    case("java-unsafe-reflection-dynamic", "A.java", Safe, "class A { void f() throws Exception { Class<?> c = Class.forName(\"com.example.Plugin\"); } }"),
    case("java-unsafe-reflection-dynamic", "A.java", Evasion, "class A { void f(String name) throws Exception { Class<?> c = getClass().getClassLoader().loadClass(name); } }"),
    case("py-unsafe-reflection-dynamic", "a.py", Positive, "def f(module, action):\n    return getattr(module, action)()\n"),
    case("py-unsafe-reflection-dynamic", "a.py", Safe, "def f(module):\n    return getattr(module, \"run\")()\n"),
    case("py-unsafe-reflection-dynamic", "a.py", Evasion, "import importlib\n\ndef f(name):\n    return importlib.import_module(name)\n"),
    case("js-unsafe-reflection-dynamic", "a.js", Positive, "function load(name) { return require(name); }"),
    case("js-unsafe-reflection-dynamic", "a.js", Safe, "const fs = require('fs');"),
    case("js-unsafe-reflection-dynamic", "a.js", Evasion, "async function load(name) { return import(`./plugins/${name}.js`); }"),
    case("go-unsafe-reflection-dynamic", "a.go", Positive, "package a\n\nfunc f(svc any, action string) { m := reflect.ValueOf(svc).MethodByName(action); _ = m }\n"),
    case("go-unsafe-reflection-dynamic", "a.go", Safe, "package a\n\nfunc f(svc any) { m := reflect.ValueOf(svc).MethodByName(\"Run\"); _ = m }\n"),
    case("go-unsafe-reflection-dynamic", "a.go", Evasion, "package a\n\nfunc f(v reflect.Value, field string) { x := v.FieldByName(field); _ = x }\n"),
    case("cs-unsafe-reflection-dynamic", "A.cs", Positive, "class A { void F(string typeName) { var t = Type.GetType(typeName); } }"),
    case("cs-unsafe-reflection-dynamic", "A.cs", Safe, "class A { void F() { var t = Type.GetType(\"App.Plugin\"); } }"),
    case("cs-unsafe-reflection-dynamic", "A.cs", Evasion, "class A { void F(string path) { var asm = Assembly.LoadFrom(path); } }"),
    case("py-toctou-check-then-use", "a.py", Positive, "import os\n\ndef f(path):\n    if os.path.exists(path):\n        with open(path) as fh:\n            fh.read()\n"),
    case("py-toctou-check-then-use", "a.py", Safe, "def f(path):\n    try:\n        with open(path) as fh:\n            fh.read()\n    except FileNotFoundError:\n        return None\n"),
    case("py-toctou-check-then-use", "a.py", Evasion, "import os\n\ndef f(path):\n    if os.access(path, os.W_OK):\n        os.remove(path)\n"),
    case("java-toctou-check-then-use", "A.java", Positive, "class A { void f(File f) throws Exception { if (f.exists()) { new FileInputStream(f); } } }"),
    case("java-toctou-check-then-use", "A.java", Safe, "class A { void f(File f) throws Exception { try (InputStream in = new FileInputStream(f)) { } } }"),
    case("java-toctou-check-then-use", "A.java", Evasion, "class A { void f(Path p) throws Exception { if (Files.exists(p)) { Files.delete(p); } } }"),
    case("c-toctou-check-then-use", "a.c", Positive, "void f(const char *p) { if (access(p, W_OK) == 0) { FILE *fp = fopen(p, \"w\"); } }"),
    case("c-toctou-check-then-use", "a.c", Safe, "void f(const char *p) { FILE *fp = fopen(p, \"w\"); if (!fp) return; }"),
    case("c-toctou-check-then-use", "a.c", Evasion, "void f(const char *p) { struct stat st; if (stat(p, &st) == 0) unlink(p); }"),
    case("go-toctou-check-then-use", "a.go", Positive, "package a\n\nfunc f(p string) { if _, err := os.Stat(p); err == nil { os.Remove(p) } }\n"),
    case("go-toctou-check-then-use", "a.go", Safe, "package a\n\nfunc f(p string) { f, err := os.Open(p); _, _ = f, err }\n"),
    case("go-toctou-check-then-use", "a.go", Evasion, "package a\n\nfunc f(p string) {\n\tif _, err := os.Lstat(p); err == nil {\n\t\tdata, _ := os.ReadFile(p)\n\t\t_ = data\n\t}\n}\n"),
    case("any-suspicious-security-comment", "a.py", Positive, "# TODO: add authentication before release\ndef admin():\n    pass\n"),
    case("any-suspicious-security-comment", "a.py", Safe, "# TODO: refactor this loop\ndef admin():\n    pass\n"),
    case("any-suspicious-security-comment", "a.js", Evasion, "// FIXME xss: escape user names here\nrender(name);"),
    case("any-suspicious-security-line-comment", "A.java", Positive, "class A {\n    // TODO validate input before saving\n    void f() {}\n}"),
    case("any-suspicious-security-line-comment", "A.java", Safe, "class A {\n    // TODO: rename method\n    void f() {}\n}"),
    case("any-suspicious-security-line-comment", "a.rs", Evasion, "/* HACK: skip csrf check for the mobile app */\nfn f() {}"),
    case("py-bind-all-interfaces", "a.py", Positive, "app.run(host=\"0.0.0.0\", port=8080)\n"),
    case("py-bind-all-interfaces", "a.py", Safe, "app.run(host=\"127.0.0.1\", port=8080)\n"),
    case("py-bind-all-interfaces", "a.py", Evasion, "sock.bind((\"0.0.0.0\", 9000))\n"),
    case("js-bind-all-interfaces", "a.js", Positive, "app.listen(3000, \"0.0.0.0\");"),
    case("js-bind-all-interfaces", "a.js", Safe, "app.listen(3000, \"127.0.0.1\");"),
    case("js-bind-all-interfaces", "a.js", Evasion, "server.listen(8080, '0.0.0.0', () => {});"),
    case("go-bind-all-interfaces", "a.go", Positive, "package a\n\nfunc main() { http.ListenAndServe(\"0.0.0.0:8080\", nil) }\n"),
    case("go-bind-all-interfaces", "a.go", Safe, "package a\n\nfunc main() { http.ListenAndServe(\"127.0.0.1:8080\", nil) }\n"),
    case("go-bind-all-interfaces", "a.go", Evasion, "package a\n\nfunc main() { ln, _ := net.Listen(\"tcp\", \"0.0.0.0:9000\"); _ = ln }\n"),
    case("rust-bind-all-interfaces", "a.rs", Positive, "fn main() { let l = TcpListener::bind(\"0.0.0.0:8080\"); }"),
    case("rust-bind-all-interfaces", "a.rs", Safe, "fn main() { let l = TcpListener::bind(\"127.0.0.1:8080\"); }"),
    case("rust-bind-all-interfaces", "a.rs", Evasion, "fn main() { let s = HttpServer::new(app).bind((\"0.0.0.0\", 8080)); }"),
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
fn structural_corpus_precision_and_recall_per_rule_and_language() {
    let mut scores: BTreeMap<(&str, &str), Score> = BTreeMap::new();
    for (i, c) in CASES.iter().enumerate() {
        let fired = detect_grammar(Path::new(c.file))
            .map(|g| audit_file_ast(c.src, g))
            .unwrap_or_default()
            .iter()
            .any(|f| f.rule.id == c.rule);
        let ext = Path::new(c.file)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let score = scores.entry((c.rule, ext)).or_default();
        match (c.kind != Safe, fired) {
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

    let failures: Vec<String> = scores
        .iter()
        .filter_map(|((rule, ext), s)| {
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
            (precision < 0.95 || recall < 0.90).then(|| {
                format!(
                    "{rule} [{ext}] precision={precision:.2} recall={recall:.2}: {}",
                    s.misses.join("; ")
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "structural corpus gate failed:\n{}",
        failures.join("\n")
    );
}

/// Every structural rule has a positive, a safe and an evasion fixture.
#[test]
fn every_structural_rule_has_complete_fixtures() {
    for rule in STRUCTURAL_RULES {
        for kind in [Positive, Safe, Evasion] {
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
