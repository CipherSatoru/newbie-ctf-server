import os, time, json, secrets, hashlib, html, urllib.request
from flask import Flask, request, jsonify, Response

SALT = os.environ["CTF_SALT"]
ADMIN_KEY = os.environ["ADMIN_KEY"]
SECRET_PASSWORD = os.environ.get("SECRET_PASSWORD", "fsociety")
DEFAULT_MIN = int(os.environ.get("DURATION_MIN", "60"))
CH = {1:("Welcome",5),2:("Hidden",5),3:("Lost",10),4:("Needle",10),5:("Locked",10),
      6:("Odd One Out",15),7:("Encoded",15),8:("Mystery",15),9:("Run It",20),10:("Catch the Attacker",25)}
app = Flask(__name__)

class Store:
    def __init__(self):
        self.url = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
        self.tok = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
        self.persistent = bool(self.url and self.tok); self.h = {}; self.l = {}; self.rl = {}
    def _post(self, path, body):
        r = urllib.request.Request(self.url + path, json.dumps(body).encode(),
            {"Authorization": "Bearer " + self.tok, "Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(r, timeout=8).read())
    def cmd(self, *a): return self._post("", list(a))["result"]
    def hget(self, k, f):
        if self.persistent: return self.cmd("HGET", k, f)
        return self.h.get(k, {}).get(f)
    def hset(self, k, f, v):
        if self.persistent: self.cmd("HSET", k, f, str(v))
        else: self.h.setdefault(k, {})[f] = str(v)
    def hsetnx(self, k, f, v):
        if self.persistent: return bool(self.cmd("HSETNX", k, f, str(v)))
        d = self.h.setdefault(k, {})
        if f in d: return False
        d[f] = str(v); return True
    def hdel(self, k, f):
        if self.persistent: self.cmd("HDEL", k, f)
        else: self.h.get(k, {}).pop(f, None)
    def hgetall(self, k):
        if self.persistent:
            r = self.cmd("HGETALL", k) or []; return dict(zip(r[::2], r[1::2]))
        return dict(self.h.get(k, {}))
    def hgetall_many(self, keys):
        if not keys: return []
        if self.persistent:
            res = self._post("/pipeline", [["HGETALL", k] for k in keys])
            return [dict(zip((x["result"] or [])[::2], (x["result"] or [])[1::2])) for x in res]
        return [self.hgetall(k) for k in keys]
    def rpush(self, k, v):
        if self.persistent: self.cmd("RPUSH", k, v)
        else: self.l.setdefault(k, []).append(v)
    def lrange(self, k):
        return (self.cmd("LRANGE", k, 0, -1) or []) if self.persistent else list(self.l.get(k, []))
    def delete(self, keys):
        if not keys: return
        if self.persistent: self._post("/pipeline", [["DEL", k] for k in keys])
        else:
            for k in keys: self.h.pop(k, None); self.l.pop(k, None)
    def allow(self, key, ms=1500):
        if self.persistent: return self.cmd("SET", "rl:" + key, "1", "NX", "PX", ms) == "OK"
        t = time.time()
        if t - self.rl.get(key, 0) < ms / 1000: return False
        self.rl[key] = t; return True
S = Store()

def norm(n): return " ".join(str(n).lower().split())
def mkflag(name, cid): return "flag{" + hashlib.sha256(f"{SALT}|{norm(name)}|{cid}".encode()).hexdigest()[:12] + "}"
def meta(k): return S.hget("meta", k)

def phase():
    st = meta("start")
    if not st: return "waiting"
    if meta("done") == "1" or time.time() >= float(st) + float(meta("dur")): return "ended"
    return "running"
def remaining():
    st = meta("start")
    return max(0, int(float(st) + float(meta("dur")) - time.time())) if st else None

def board():
    names = list(S.hgetall("players"))
    sols = S.hgetall_many(["solves:" + n for n in names])
    kinds = {}
    for a in S.lrange("attempts"):
        a = json.loads(a); kinds.setdefault(a["name"], []).append(a["kind"])
    st = float(meta("start") or 0); rows = []
    for n, s in zip(names, sols):
        score = sum(CH[int(c)][1] for c in s); last = max([float(t) for t in s.values()] or [0])
        why = []
        if "decoy" in kinds.get(n, []): why.append("submitted a decoy flag (AI/copy-paste)")
        if "shared" in kinds.get(n, []): why.append("submitted another player's flag")
        if len(s) >= 6 and st and last - st < 600: why.append("solved 6+ challenges in under 10 min")
        rows.append({"name": n, "score": score, "solved": len(s), "last": last, "flags": why})
    return sorted(rows, key=lambda x: (-x["score"], x["last"] or 9e18))
def winner():
    w = meta("winner")
    if w: return w
    b = board(); return b[0]["name"] if b and b[0]["score"] > 0 else None
def revealed(): return meta("claimed") == "1" or meta("reveal") == "1"
def me():
    tok = request.cookies.get("ctf_token")
    return S.hget("tokens", tok) if tok else None

@app.post("/api/register")
def register():
    name = norm((request.json or {}).get("name", ""))
    if not (2 <= len(name) <= 30) or not name.isprintable(): return jsonify(error="Name must be 2-30 characters."), 400
    tok = request.cookies.get("ctf_token"); new = secrets.token_hex(16)
    if S.hsetnx("players", name, new):
        S.hset("tokens", new, name); resp = jsonify(ok=True, name=name)
        resp.set_cookie("ctf_token", new, max_age=86400 * 3, httponly=True, samesite="Lax", secure=True); return resp
    if tok and S.hget("tokens", tok) == name: return jsonify(ok=True, name=name)
    return jsonify(error="That name is already taken from another browser. Ask the organizer."), 409

@app.post("/api/submit")
def submit():
    name = me()
    if not name: return jsonify(error="Enter your name first."), 401
    if phase() != "running": return jsonify(error="The CTF is not running."), 400
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    if not S.allow(name): return jsonify(error="Slow down."), 429
    b = request.json or {}
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
        S.rpush("attempts", json.dumps({"name": name, "cid": cid, "kind": kind, "ts": time.time(), "ip": ip}))
        return jsonify(ok=False, msg="Incorrect flag. Check your name and the flag.")
    S.hset("solves:" + name, str(cid), time.time())
    if len(S.hgetall("solves:" + name)) == len(CH) and S.hsetnx("meta", "winner", name): S.hset("meta", "done", 1)
    return jsonify(ok=True, msg=f"Correct! +{CH[cid][1]} points")

@app.post("/api/claim")
def claim():
    name = me()
    if not name or phase() != "ended" or winner() != name: return jsonify(error="You are not the winner."), 403
    S.hset("meta", "claimed", 1)
    return jsonify(ok=True, password=SECRET_PASSWORD)

@app.get("/api/state")
def state():
    name = me(); ph = phase()
    out = {"phase": ph, "remaining": remaining(), "revealed": revealed(),
           "challenges": [{"id": i, "title": t, "points": p} for i, (t, p) in CH.items()], "me": None}
    if name:
        solved = [int(c) for c in S.hgetall("solves:" + name)]
        out["me"] = {"name": name, "solved": solved, "score": sum(CH[c][1] for c in solved),
                     "is_winner": ph == "ended" and winner() == name}
    if revealed(): out["board"] = board()
    return jsonify(out)

def wipe(everything):
    names = list(S.hgetall("players"))
    keys = ["meta", "attempts"] + ["solves:" + n for n in names]
    if everything: keys += ["players", "tokens"]
    S.delete(keys)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.values.get("key") != ADMIN_KEY: return "forbidden", 403
    msg = ""
    if request.method == "POST":
        a = request.form.get("action")
        if a == "start":
            wipe(False); S.hset("meta", "start", time.time()); S.hset("meta", "dur", float(request.form.get("min") or DEFAULT_MIN) * 60)
        elif a == "end": S.hset("meta", "done", 1)
        elif a == "reveal": S.hset("meta", "reveal", 1)
        elif a == "release":
            n = norm(request.form.get("name", "")); t = S.hget("players", n)
            if t: S.hdel("players", n); S.hdel("tokens", t)
        elif a == "reset": wipe(True)
        msg = "done: " + str(a)
    e = html.escape; k = e(ADMIN_KEY)
    rows = "".join("<tr><td>%s<td>%s<td>%s/10<td>%s</tr>" % (e(r["name"]), r["score"], r["solved"], e("; ".join(r["flags"]))) for r in board())
    bad = "".join("<tr><td>%s<td>%s<td>%s<td>%s</tr>" % (e(a["name"]), a["cid"], a["kind"], e(a["ip"]))
                  for a in (json.loads(x) for x in S.lrange("attempts")) if a["kind"] in ("decoy", "shared"))
    def form(inner): return '<form method=post style="display:inline"><input type=hidden name=key value="%s">%s</form> ' % (k, inner)
    forms = (form('<input type=hidden name=action value=start>Minutes <input name=min value="%d" size=3><button>START (clears scores)</button>' % DEFAULT_MIN)
        + form('<input type=hidden name=action value=end><button>END NOW</button>')
        + form('<input type=hidden name=action value=reveal><button>FORCE REVEAL LEADERBOARD</button>')
        + form('<input type=hidden name=action value=release>Release name <input name=name><button>release</button>')
        + form('<input type=hidden name=action value=reset><button>RESET ALL</button>'))
    warn = "" if S.persistent else '<p style="color:red"><b>WARNING: no Redis connected, data will be lost. Add Upstash Redis in Vercel Storage.</b></p>'
    return ('<body style="font-family:monospace;background:#111;color:#0f0;padding:20px"><h2>Admin</h2>%s<p>%s</p>'
        '<p>phase: <b>%s</b> | remaining: %ss | winner: %s | revealed: %s</p>%s'
        '<h3>Leaderboard (live)</h3><table border=1 cellpadding=4><tr><th>name<th>pts<th>solved<th>flags</tr>%s</table>'
        '<h3>Suspicious submissions</h3><table border=1 cellpadding=4><tr><th>name<th>ch<th>kind<th>ip</tr>%s</table></body>'
        % (warn, msg, phase(), remaining(), e(str(winner())), revealed(), forms, rows, bad))

PAGE = r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Newbie CTF</title><style>
body{background:#0b0f0b;color:#39ff14;font-family:ui-monospace,Menlo,monospace;max-width:640px;margin:auto;padding:16px}
.card{border:1px solid #1f4d1f;border-radius:8px;padding:14px;margin:12px 0;background:#0f160f}
input,select,button{background:#050805;color:#39ff14;border:1px solid #39ff14;padding:10px;border-radius:6px;font:inherit;width:100%;box-sizing:border-box;margin-top:8px}
button{cursor:pointer;font-weight:bold}button:hover{background:#39ff14;color:#000}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #1f4d1f;padding:6px;text-align:left}
.big{font-size:2em;text-align:center}.msg{margin-top:8px;color:#ff0}
</style></head><body><h1>&gt; NEWBIE CTF_</h1><div id=app>loading...</div><script>
let S=null,msg='';
async function api(p,b){const r=await fetch(p,{method:b?'POST':'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});return r.json()}
const fmt=s=>String(Math.floor(s/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0');
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function refresh(){S=await api('/api/state');render()}
async function reg(){const n=document.getElementById('nm').value;
 if(!document.getElementById('ok').checked){msg='Tick the box to confirm.';return render()}
 const r=await api('/api/register',{name:n});msg=r.error||'';refresh()}
async function sub(){const r=await api('/api/submit',{cid:document.getElementById('cid').value,flag:document.getElementById('fl').value});msg=r.error||r.msg;refresh()}
async function claim(){const r=await api('/api/claim',{});if(r.password){msg='';window.PW=r.password}else msg=r.error;refresh()}
function board(){return '<div class=card><h2>LEADERBOARD</h2><table><tr><th>#<th>Name<th>Pts<th>Solved<th>Flags</tr>'+
 (S.board||[]).map((r,i)=>'<tr><td>'+(i+1)+'<td>'+esc(r.name)+'<td>'+r.score+'<td>'+r.solved+'/10<td>'+(r.flags.length?'<span style="color:#f55">&#9888; '+esc(r.flags.join('; '))+'</span>':'-')+'</tr>').join('')+'</table></div>'}
function render(){
 const typing=document.activeElement&&(document.activeElement.id==='fl'||document.activeElement.id==='nm');
 if(typing&&!msg)return;
 let h='';const m=S.me;
 if(S.phase==='waiting')h+='<div class=card>The CTF has not started yet. Stay on this page.</div>';
 if(S.phase==='running')h+='<div class="card big">'+fmt(S.remaining)+'</div>';
 if(S.phase==='ended')h+='<div class=card><b>TIME IS UP.</b></div>';
 if(!m&&S.phase!=='ended'){h+='<div class=card><b>Enter your name</b><br>It MUST be exactly the name you typed in setup.sh. Double-check the spelling (nickname or real name, whichever you used).<input id=nm placeholder="your name" autocomplete=off><label style="display:block;margin-top:8px"><input type=checkbox id=ok style="width:auto"> I used exactly this name in setup.sh</label><button onclick=reg()>Enter</button></div>'}
 if(m){h+='<div class=card>Player: <b>'+esc(m.name)+'</b> | Score: <b>'+m.score+'</b></div>';
  if(S.phase==='running'){h+='<div class=card><b>Submit flag</b><select id=cid>'+S.challenges.map(c=>'<option value='+c.id+(m.solved.includes(c.id)?' disabled':'')+'>'+c.id+'. '+esc(c.title)+' ('+c.points+' pts)'+(m.solved.includes(c.id)?' ✔':'')+'</option>').join('')+'</select><input id=fl placeholder="flag{...}" autocomplete=off><button onclick=sub()>Submit</button></div>'}
  if(S.phase==='ended'&&m.is_winner&&!window.PW&&!S.revealed)h+='<div class=card>You are the WINNER! <button onclick=claim()>CLAIM SECRET CODE</button></div>';
  if(window.PW)h+='<div class="card big">SECRET CODE:<br><b>'+esc(window.PW)+'</b></div>'}
 if(S.phase==='ended'&&!S.revealed)h+='<div class=card>Waiting for the winner to claim their code. The leaderboard appears once they do.</div>';
 if(S.revealed)h+=board();
 if(msg)h+='<div class=msg>'+esc(msg)+'</div>';
 document.getElementById('app').innerHTML=h;msg=''}
refresh();setInterval(refresh,4000);
setInterval(()=>{if(S&&S.remaining>0){S.remaining--;const t=document.querySelector('.big');if(t&&S.phase==='running')t.textContent=fmt(S.remaining)}},1000);
</script></body></html>"""

@app.get("/")
def index(): return Response(PAGE, mimetype="text/html")
