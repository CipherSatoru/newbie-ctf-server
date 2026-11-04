import os, time, json, secrets, hashlib, hmac, io, zipfile, threading
from flask import Flask, request, jsonify, Response, g, send_file, redirect
from player_files import FILES

SALT = os.environ["CTF_SALT"]
ADMIN_KEY = os.environ["ADMIN_KEY"]
SECRET_PASSWORD = os.environ.get("SECRET_PASSWORD", "fsociety")
DEFAULT_MIN = int(os.environ.get("DURATION_MIN", "60"))
CH = {1:("Welcome",5),2:("Hidden",5),3:("Lost",10),4:("Needle",10),5:("Locked",10),
      6:("Odd One Out",15),7:("Encoded",15),8:("Mystery",15),9:("Run It",20),10:("Catch the Attacker",25)}
app = Flask(__name__)

class Store:
    """Postgres (Neon) when DATABASE_URL is set, else in-memory sqlite (local testing only)."""
    def __init__(self):
        self.dsn = os.environ.get("DATABASE_URL"); self.persistent = bool(self.dsn)
        self.t = threading.local(); self.lock = threading.RLock()
        if self.dsn:
            import psycopg2; self.pg = psycopg2
        else:
            import sqlite3
            self.mem = sqlite3.connect(os.environ.get("LOCAL_DB", ":memory:"), check_same_thread=False, isolation_level=None)
        idt = "BIGSERIAL PRIMARY KEY" if self.dsn else "INTEGER PRIMARY KEY AUTOINCREMENT"
        for s in ("CREATE TABLE IF NOT EXISTS kv(k TEXT NOT NULL, f TEXT NOT NULL, v TEXT, PRIMARY KEY(k,f))",
                  "CREATE TABLE IF NOT EXISTS lst(id %s, k TEXT NOT NULL, v TEXT)" % idt,
                  "CREATE TABLE IF NOT EXISTS rl(k TEXT PRIMARY KEY, ts DOUBLE PRECISION)"):
            self.q(s)
    def _conn(self):
        if not self.dsn: return self.mem
        c = getattr(self.t, "c", None)
        if c is None or c.closed:
            c = self.pg.connect(self.dsn, connect_timeout=15); c.autocommit = True; self.t.c = c
        return c
    def q(self, sql, args=(), fetch=False):
        if self.dsn: sql = sql.replace("?", "%s")
        for attempt in (0, 1):
            try:
                if not self.dsn: self.lock.acquire()
                try:
                    cur = self._conn().cursor(); cur.execute(sql, args)
                    out = cur.fetchall() if fetch else cur.rowcount; cur.close(); return out
                finally:
                    if not self.dsn: self.lock.release()
            except Exception:
                if attempt or not self.dsn: raise
                self.t.c = None
    def hget(self, k, f):
        r = self.q("SELECT v FROM kv WHERE k=? AND f=?", (k, f), True); return r[0][0] if r else None
    def hset(self, k, f, v):
        self.q("INSERT INTO kv(k,f,v) VALUES(?,?,?) ON CONFLICT(k,f) DO UPDATE SET v=excluded.v", (k, f, str(v)))
    def hsetnx(self, k, f, v):
        return self.q("INSERT INTO kv(k,f,v) VALUES(?,?,?) ON CONFLICT(k,f) DO NOTHING", (k, f, str(v))) == 1
    def hdel(self, k, f): self.q("DELETE FROM kv WHERE k=? AND f=?", (k, f))
    def hgetall(self, k): return {f: v for f, v in self.q("SELECT f,v FROM kv WHERE k=?", (k,), True)}
    def hgetall_many(self, keys):
        if not keys: return []
        rows = self.q("SELECT k,f,v FROM kv WHERE k IN (%s)" % ",".join("?" * len(keys)), tuple(keys), True)
        out = {k: {} for k in keys}
        for k, f, v in rows: out[k][f] = v
        return [out[k] for k in keys]
    def rpush(self, k, v): self.q("INSERT INTO lst(k,v) VALUES(?,?)", (k, v))
    def lrange(self, k): return [r[0] for r in self.q("SELECT v FROM lst WHERE k=? ORDER BY id", (k,), True)]
    def delete(self, keys):
        if not keys: return
        ph = ",".join("?" * len(keys))
        self.q("DELETE FROM kv WHERE k IN (%s)" % ph, tuple(keys)); self.q("DELETE FROM lst WHERE k IN (%s)" % ph, tuple(keys))
    def allow(self, key, ms=1500):
        now = time.time()
        return self.q("INSERT INTO rl(k,ts) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET ts=excluded.ts WHERE rl.ts < ?", (key, now, now - ms / 1000.0)) > 0
S = Store()

def norm(n): return " ".join(str(n).lower().split())
def mkflag(name, cid): return "flag{" + hashlib.sha256(f"{SALT}|{norm(name)}|{cid}".encode()).hexdigest()[:12] + "}"
def secure(): return request.headers.get("X-Forwarded-Proto", request.scheme) == "https"
def ipaddr(): return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()

def M():
    if "m" not in g: g.m = S.hgetall("meta")
    return g.m
def setmeta(k, v): S.hset("meta", k, v); g.pop("m", None)

def phase():
    m = M(); st = m.get("start")
    if not st: return "waiting"
    if m.get("done") == "1": return "ended"
    if m.get("mode") == "test": return "running"
    return "ended" if time.time() >= float(st) + float(m.get("dur", 0)) else "running"
def remaining():
    m = M(); st = m.get("start")
    if not st or m.get("mode") == "test": return None
    return max(0, int(float(st) + float(m.get("dur", 0)) - time.time()))
def is_test(): return M().get("mode") == "test"
def revealed():
    m = M(); return m.get("claimed") == "1" or m.get("reveal") == "1" or m.get("mode") == "test"

_bc = {"t": 0, "v": None}
def bust(): _bc["t"] = 0
def board():
    if _bc["v"] is not None and time.time() - _bc["t"] < 2: return _bc["v"]
    names = list(S.hgetall("players"))
    sols = S.hgetall_many(["solves:" + n for n in names])
    kinds = {}
    for a in S.lrange("attempts"):
        a = json.loads(a); kinds.setdefault(a["name"], []).append(a["kind"])
    st = float(M().get("start") or 0); rows = []
    for n, s in zip(names, sols):
        score = sum(CH[int(c)][1] for c in s); last = max([float(t) for t in s.values()] or [0])
        why = []
        if "decoy" in kinds.get(n, []): why.append("submitted a decoy flag (AI/copy-paste)")
        if "shared" in kinds.get(n, []): why.append("submitted another player's flag")
        if len(s) >= 6 and st and last - st < 600: why.append("solved 6+ challenges in under 10 min")
        rows.append({"name": n, "score": score, "solved": len(s), "last": last, "flags": why})
    rows.sort(key=lambda x: (-x["score"], x["last"] or 9e18))
    _bc["v"] = rows; _bc["t"] = time.time(); return rows
def winner():
    w = M().get("winner")
    if w: return w
    b = board(); return b[0]["name"] if b and b[0]["score"] > 0 else None

def me():
    tok = request.cookies.get("ctf_token")
    return S.hget("tokens", tok) if tok else None

@app.post("/api/setup")
def setup():
    T = "text/plain"
    if not S.allow("setup:" + ipaddr(), 1000): return Response("ERROR=Slow down, try again.\n", 429, mimetype=T)
    name = norm(request.form.get("name", "")); code = request.form.get("code", "").strip()
    if not (2 <= len(name) <= 30) or not name.isprintable(): return Response("ERROR=Name must be 2-30 characters.\n", 400, mimetype=T)
    cur = S.hget("players", name)
    if cur is None:
        code = secrets.token_hex(4)
        if not S.hsetnx("players", name, code): return Response("ERROR=Name already taken. Pick another name.\n", 409, mimetype=T)
        S.hset("tokens", code, name); bust()
    elif cur != code: return Response("ERROR=Name already taken. Pick another name.\n", 409, mimetype=T)
    out = ["CODE=" + code] + ["F%d=%s" % (c, mkflag(name, c)) for c in CH] + ["DECOY=" + mkflag(name, "decoy")]
    return Response("\n".join(out) + "\n", mimetype=T)

@app.post("/api/register")
def register():
    b = request.get_json(silent=True) or {}; name = norm(b.get("name", "")); code = str(b.get("code", "")).strip()
    if not name or not code or S.hget("players", name) != code:
        return jsonify(error="Wrong name or player code. Use exactly what setup.sh showed you."), 400
    resp = jsonify(ok=True, name=name)
    resp.set_cookie("ctf_token", code, max_age=86400 * 7, httponly=True, samesite="Lax", secure=secure())
    return resp

@app.post("/api/submit")
def submit():
    name = me()
    if not name: return jsonify(error="Log in first."), 401
    if phase() != "running": return jsonify(error="The CTF is not running."), 400
    if not S.allow("sub:" + name, 1500): return jsonify(error="Slow down."), 429
    b = request.get_json(silent=True) or {}
    try:
        cid = int(b.get("cid")); assert cid in CH
    except Exception: return jsonify(error="Pick a challenge."), 400
    s = str(b.get("flag", "")).strip()
    if S.hget("solves:" + name, str(cid)): return jsonify(error="Already solved."), 400
    kind = "wrong"
    if s == mkflag(name, "decoy"): kind = "decoy"
    elif s == mkflag(name, cid): kind = "ok"
    else:
        for o in S.hgetall("players"):
            if o != name and any(s == mkflag(o, c) for c in CH): kind = "shared"; break
    if kind != "ok":
        S.rpush("attempts", json.dumps({"name": name, "cid": cid, "kind": kind, "ts": time.time(), "ip": ipaddr()})); bust()
        return jsonify(ok=False, msg="Incorrect flag. Check it and try again.")
    S.hset("solves:" + name, str(cid), time.time()); bust()
    if not is_test() and len(S.hgetall("solves:" + name)) == len(CH) and S.hsetnx("meta", "winner", name):
        setmeta("done", 1)
    return jsonify(ok=True, msg="Correct! +%d points" % CH[cid][1])

@app.post("/api/claim")
def claim():
    name = me()
    if is_test() or not name or phase() != "ended" or winner() != name: return jsonify(error="You are not the winner."), 403
    setmeta("claimed", 1)
    return jsonify(ok=True, password=SECRET_PASSWORD)

@app.get("/api/state")
def state():
    name = me(); ph = phase()
    out = {"phase": ph, "mode": M().get("mode"), "remaining": remaining(), "revealed": revealed(),
           "challenges": [{"id": i, "title": t, "points": p} for i, (t, p) in CH.items()], "me": None}
    if name:
        solved = [int(c) for c in S.hgetall("solves:" + name)]
        out["me"] = {"name": name, "solved": solved, "score": sum(CH[c][1] for c in solved),
                     "is_winner": ph == "ended" and not is_test() and winner() == name}
    if revealed(): out["board"] = board()
    return jsonify(out)

@app.get("/download.zip")
def download():
    base = request.url_root.rstrip("/")
    if base.startswith("http://") and "localhost" not in base and "127.0.0.1" not in base: base = "https://" + base[7:]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, text in FILES.items():
            zi = zipfile.ZipInfo("newbie-ctf/" + path, date_time=(2026, 1, 1, 0, 0, 0))
            zi.external_attr = (0o755 if path.endswith(".sh") else 0o644) << 16; zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, text.replace("__SERVER__", base))
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name="newbie-ctf.zip")

# ---------------- admin ----------------
def admin_cookie(): return hashlib.sha256(("admin|" + ADMIN_KEY + "|" + SALT).encode()).hexdigest()
def is_admin(): return hmac.compare_digest(request.cookies.get("ctf_admin", ""), admin_cookie())
def set_admin(resp):
    resp.set_cookie("ctf_admin", admin_cookie(), max_age=86400 * 30, httponly=True, samesite="Lax", secure=secure()); return resp

@app.get("/admin")
def admin_page():
    k = request.args.get("key")
    if k and hmac.compare_digest(k, ADMIN_KEY): return set_admin(redirect("/admin"))
    return Response(ADMIN_PAGE, mimetype="text/html")

@app.post("/admin/login")
def admin_login():
    k = str((request.get_json(silent=True) or {}).get("key", ""))
    if not hmac.compare_digest(k, ADMIN_KEY): return jsonify(error="Wrong key"), 403
    return set_admin(jsonify(ok=True))

@app.get("/admin/data")
def admin_data():
    if not is_admin(): return jsonify(auth=False), 401
    sus = [a for a in (json.loads(x) for x in S.lrange("attempts")) if a["kind"] in ("decoy", "shared")]
    return jsonify(phase=phase(), mode=M().get("mode"), remaining=remaining(), winner=winner(), revealed=revealed(),
                   persistent=S.persistent, players=board(), suspicious=sus[-50:][::-1])

def wipe(everything):
    names = list(S.hgetall("players"))
    keys = ["meta", "attempts"] + ["solves:" + n for n in names]
    if everything: keys += ["players", "tokens"]
    S.delete(keys); g.pop("m", None); bust()

@app.post("/admin/act")
def admin_act():
    if not is_admin(): return jsonify(auth=False), 401
    b = request.get_json(silent=True) or {}; a = b.get("action"); msg = "done: " + str(a)
    if a == "start":
        wipe(False); mins = float(b.get("min") or DEFAULT_MIN)
        setmeta("mode", "contest"); setmeta("dur", mins * 60); setmeta("start", time.time())
    elif a == "start_test":
        wipe(False); setmeta("mode", "test"); setmeta("dur", 0); setmeta("start", time.time())
    elif a == "end": setmeta("done", 1)
    elif a == "reveal": setmeta("reveal", 1)
    elif a == "release":
        n = norm(b.get("name", "")); code = S.hget("players", n)
        if code:
            S.hdel("players", n); S.hdel("tokens", code); S.delete(["solves:" + n]); bust(); msg = "released " + n
        else: msg = "no such player"
    elif a == "reset": wipe(True)
    else: msg = "unknown action"
    return jsonify(ok=True, msg=msg)

CSS = """body{background:#0b0f0b;color:#39ff14;font-family:ui-monospace,Menlo,monospace;max-width:680px;margin:auto;padding:14px}
h1,h3{margin:8px 0}.card{border:1px solid #1f4d1f;border-radius:10px;padding:14px;margin:12px 0;background:#0f160f}
input,select,button,.btn{background:#050805;color:#39ff14;border:1px solid #39ff14;padding:11px;border-radius:8px;font:inherit;width:100%;box-sizing:border-box;margin-top:8px;display:block;text-align:center;text-decoration:none}
button,.btn{cursor:pointer;font-weight:bold}button:hover,.btn:hover{background:#39ff14;color:#000}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{border-bottom:1px solid #1f4d1f;padding:6px;text-align:left}
.dim{color:#6a9a6a;font-size:13px;margin-top:6px}.bad{color:#ff5555}.row{display:flex;justify-content:space-between}
.bar{background:#050805;border:1px solid #1f4d1f;border-radius:6px;height:10px;margin-top:8px}.bar i{display:block;height:100%;background:#39ff14;border-radius:6px}
.pill{text-align:center;font-size:1.6em;font-weight:bold;border:1px solid #39ff14;border-radius:10px;padding:12px;margin:12px 0}
.ch{display:flex;justify-content:space-between;padding:12px;border:1px solid #1f4d1f;border-radius:8px;margin-top:8px;cursor:pointer}
.ch.done{color:#556;text-decoration:line-through}.ch.sel{border-color:#39ff14;background:#13261a}
.toast{margin-top:10px;padding:10px;border-radius:8px;background:#1d1d08;color:#ff0}.sm{width:auto;display:inline-block;padding:4px 8px;margin:0}"""

PAGE = r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Newbie CTF</title><style>__CSS__</style></head><body><h1>&gt; NEWBIE CTF_</h1><div id=app>loading...</div><script>
let S=null,sel=null,toast='',V={nm:'',cd:'',fl:''};
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=s=>String(Math.floor(s/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0');
async function api(p,b){try{const r=await fetch(p,{method:b?'POST':'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});return await r.json()}catch(e){return {error:'Network error, try again.'}}}
function saved(){try{return JSON.parse(localStorage.getItem('ctf')||'null')}catch(e){return null}}
async function refresh(){
 let s=await api('/api/state'); if(s.error){toast=s.error;return render()}
 if(!s.me){const c=saved();if(c){const r=await api('/api/register',c);if(r.ok)s=await api('/api/state');else localStorage.removeItem('ctf')}}
 S=s;render()}
function pick(i){sel=i;toast='';render()}
async function reg(){const b={name:$('nm').value,code:$('cd').value};const r=await api('/api/register',b);
 if(r.ok){localStorage.setItem('ctf',JSON.stringify(b));toast='';V={nm:'',cd:'',fl:''}}else toast=r.error;await refresh()}
async function sub(){if(!sel){toast='Tap a challenge first.';return render()}const f=$('fl').value.trim();if(!f){toast='Paste your flag.';return render()}
 const r=await api('/api/submit',{cid:sel,flag:f});toast=(r.ok?'\u2705 ':'\u274C ')+(r.msg||r.error);V.fl='';if(r.ok)sel=null;await refresh()}
async function claim(){const r=await api('/api/claim',{});if(r.password){window.PW=r.password;toast=''}else toast=r.error;await refresh()}
function board(){return '<div class=card><h3>LEADERBOARD</h3><table><tr><th>#<th>Name<th>Pts<th>Solved<th>Flags</tr>'+(S.board||[]).map((r,i)=>'<tr><td>'+(i+1)+'<td>'+esc(r.name)+'<td>'+r.score+'<td>'+r.solved+'/10<td>'+(r.flags.length?'<span class=bad>&#9888; '+esc(r.flags.join('; '))+'</span>':'-')+'</tr>').join('')+'</table></div>'}
function render(){
 if(!S)return;const fid=document.activeElement&&document.activeElement.id;['nm','cd','fl'].forEach(i=>{if($(i))V[i]=$(i).value});
 const m=S.me;let h='';
 const pill=S.phase==='waiting'?'WAITING TO START':S.phase==='ended'?'FINISHED':S.mode==='test'?'TEST MODE':'<span id=tm>'+fmt(S.remaining||0)+'</span> LEFT';
 h+='<div class=pill>'+pill+'</div>';
 if(!m){
  h+='<div class=card><h3>1. Download</h3><a class=btn href="/download.zip">&#11015; Download challenges (.zip)</a><div class=dim>Needs Linux (Ubuntu, VM, WSL, Termux). Unzip, run <b>bash setup.sh</b>. It gives you a name and a player code.</div></div>';
  h+='<div class=card><h3>2. Log in</h3><input id=nm placeholder="your name" autocomplete=off autocapitalize=off><input id=cd placeholder="player code" autocomplete=off autocapitalize=off><button onclick=reg()>Log in</button><div class=dim>Use exactly the name and code that setup.sh showed.</div></div>';
 }else{
  const d=m.solved.length,t=S.challenges.length;
  h+='<div class=card><div class=row><b>'+esc(m.name)+'</b><b>'+m.score+' pts</b></div><div class=bar><i style="width:'+(d/t*100)+'%"></i></div><div class=dim>'+d+'/'+t+' solved</div></div>';
  if(S.phase==='waiting')h+='<div class=card>Waiting for the organizer to start. Stay on this page.</div>';
  if(S.phase==='running'){
   h+='<div class=card><h3>Challenges</h3>'+S.challenges.map(c=>{const ok=m.solved.includes(c.id);return '<div class="ch'+(ok?' done':'')+(sel===c.id?' sel':'')+'" '+(ok?'':'onclick=pick('+c.id+')')+'><span>'+c.id+'. '+esc(c.title)+(ok?' &#10004;':'')+'</span><span>'+c.points+' pts</span></div>'}).join('')+'</div>';
   const cur=S.challenges.find(c=>c.id===sel);
   h+='<div class=card><div class=dim>'+(cur?'Submitting for: <b>'+esc(cur.title)+'</b>':'Tap a challenge above')+'</div><input id=fl placeholder="flag{...}" autocomplete=off autocapitalize=off><button onclick=sub()>Submit flag</button></div>';
  }
  if(S.phase==='ended'&&m.is_winner&&!window.PW&&!S.revealed)h+='<div class=card><b>You are the WINNER!</b><button onclick=claim()>CLAIM SECRET CODE</button></div>';
  if(window.PW)h+='<div class="card pill">SECRET CODE<br><b>'+esc(window.PW)+'</b></div>';
 }
 if(S.phase==='ended'&&!S.revealed)h+='<div class=card>Time is up. The leaderboard appears once the winner claims their code.</div>';
 if(S.revealed)h+=board();
 if(toast)h+='<div class=toast>'+esc(toast)+'</div>';
 h+='<div class=dim style="text-align:center;margin-top:16px"><a style="color:#6a9a6a" href="/download.zip">download challenges</a></div>';
 $('app').innerHTML=h;
 ['nm','cd','fl'].forEach(i=>{if($(i))$(i).value=V[i]||''});if(fid&&$(fid))$(fid).focus()}
refresh();setInterval(refresh,5000);
setInterval(()=>{if(S&&S.remaining>0){S.remaining--;const t=$('tm');if(t&&S.phase==='running')t.textContent=fmt(S.remaining)}},1000);
</script></body></html>""".replace("__CSS__", CSS)

ADMIN_PAGE = r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>CTF Admin</title><style>__CSS__</style></head><body><h1>&gt; ADMIN_</h1><div id=app>loading...</div><script>
const $=id=>document.getElementById(id);let P=[],built=false;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=s=>String(Math.floor(s/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0');
async function api(p,b){const r=await fetch(p,{method:b?'POST':'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});if(r.status===401)return {auth:false};try{return await r.json()}catch(e){return {error:'bad response'}}}
function loginUI(m){built=false;$('app').innerHTML='<div class=card><h3>Admin login</h3><input id=k type=password placeholder="admin key"><button onclick=login()>Log in</button><div class=bad>'+(m||'')+'</div></div>'}
async function login(){const r=await api('/admin/login',{key:$('k').value});if(r.ok)load();else loginUI('Wrong key')}
function shell(){built=true;$('app').innerHTML='<div id=st class=card></div><div class=card><h3>Controls</h3>'+
 '<div class=dim>Contest length (minutes)</div><input id=min type=number value=60>'+
 '<button onclick="act(\'start\',{min:$(\'min\').value})">START CONTEST (clears scores)</button>'+
 '<button onclick="act(\'start_test\')">START TEST MODE (no timer, live leaderboard)</button>'+
 '<button onclick="act(\'end\')">STOP / END NOW</button>'+
 '<button onclick="act(\'reveal\')">FORCE REVEAL LEADERBOARD</button>'+
 '<div class=dim>Release a player name (lets them set up again)</div><input id=rn placeholder="name"><button onclick="act(\'release\',{name:$(\'rn\').value})">Release name</button>'+
 '<button onclick="act(\'reset\')" class=bad>RESET EVERYTHING</button><div id=msg class=dim></div>'+
 '<a class=btn href="/download.zip">Download player zip</a></div><div id=pl class=card></div><div id=su class=card></div>'}
function draw(d){P=d.players;
 $('st').innerHTML='<h3>Status</h3>'+(d.persistent?'':'<div class=bad>&#9888; No database connected: data will be lost!</div>')+
 '<div>Phase: <b>'+d.phase.toUpperCase()+'</b> &nbsp; Mode: <b>'+(d.mode||'-')+'</b></div><div>Time left: <b>'+(d.remaining==null?'-':fmt(d.remaining))+'</b></div>'+
 '<div>Winner: <b>'+esc(d.winner||'-')+'</b> &nbsp; Leaderboard public: <b>'+(d.revealed?'YES':'no')+'</b></div>';
 $('pl').innerHTML='<h3>Players ('+P.length+')</h3><table><tr><th>#<th>Name<th>Pts<th>Solved<th>Flags</tr>'+P.map((r,i)=>'<tr><td>'+(i+1)+'<td>'+esc(r.name)+'<td>'+r.score+'<td>'+r.solved+'/10<td class=bad>'+esc(r.flags.join('; '))+'</tr>').join('')+'</table>';
 $('su').innerHTML='<h3>Suspicious submissions</h3><table><tr><th>Name<th>Ch<th>Kind<th>IP</tr>'+d.suspicious.map(a=>'<tr><td>'+esc(a.name)+'<td>'+a.cid+'<td>'+a.kind+'<td>'+esc(a.ip)+'</tr>').join('')+'</table>'}
async function load(){const d=await api('/admin/data');if(d.auth===false)return loginUI();if(!built)shell();draw(d)}
async function act(a,x){if(a==='reset'&&!confirm('Delete ALL players and data?'))return;if(a==='end'&&!confirm('End the CTF now?'))return;
 const r=await api('/admin/act',Object.assign({action:a},x||{}));if(r.auth===false)return loginUI();$('msg').textContent=r.msg||r.error||'';load()}
load();setInterval(load,3000);
</script></body></html>""".replace("__CSS__", CSS)

@app.get("/")
def index(): return Response(PAGE, mimetype="text/html")
