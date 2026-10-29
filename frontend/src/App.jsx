import { useCallback, useEffect, useRef, useState } from "react";
import { api, shortAddr, fmtSeconds, fmtSpeed } from "./api";

/* ---------------- shared bits ---------------- */

function Toast({ toast }) {
  return <div id="toast" className={toast ? "show" + (toast.err ? " err" : "") : ""}>{toast?.msg}</div>;
}

function Toggle({ on, onClick, label }) {
  return (
    <div
      className={"switch" + (on ? " on" : "")}
      role="switch"
      tabIndex={0}
      aria-checked={on}
      aria-label={label}
      onClick={onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
    />
  );
}

function CopyBtn({ value, notify }) {
  return (
    <button
      className="ghost"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          notify("地址已复制");
        } catch {
          notify("复制失败，请手动选择", true);
        }
      }}
    >
      复制
    </button>
  );
}

function Addr({ value, notify }) {
  const [open, setOpen] = useState(false);
  if (!value) return <span className="pending">地址分配中…</span>;
  return (
    <>
      <code className={open ? "open" : ""} title={value} onClick={() => setOpen(!open)}>
        {open ? value : shortAddr(value)}
      </code>
      <CopyBtn value={value} notify={notify} />
    </>
  );
}

/* ---------------- services ---------------- */

const emptyForm = { id: "", name: "", target: "", basic_user: "", basic_pass: "", rate_limit: "", address_id: "__new" };

function Services({ data, reload, notify }) {
  const [form, setForm] = useState(null);
  const [probe, setProbe] = useState({ text: "", cls: "" });
  const [busy, setBusy] = useState(false);
  const probeTimer = useRef(null);
  const probeSeq = useRef(0);

  const unbound = data.addresses.filter((a) => !a.service_id);

  const open = (svc) => {
    if (svc) {
      setForm({
        id: svc.id,
        name: svc.name,
        target: svc.target,
        basic_user: svc.basic_user || "",
        basic_pass: "",
        rate_limit: svc.rate_limit || "",
        address_id: svc.address_id || "",
      });
    } else {
      setForm({ ...emptyForm });
    }
    setProbe({ text: "", cls: "" });
    if (svc) runProbe(svc.target);
  };

  const runProbe = (target) => {
    clearTimeout(probeTimer.current);
    if (!target) return setProbe({ text: "", cls: "" });
    probeTimer.current = setTimeout(async () => {
      const seq = ++probeSeq.current;
      setProbe({ text: "检测中…", cls: "" });
      try {
        const r = await api("/probe", { method: "POST", body: JSON.stringify({ target }) });
        if (seq !== probeSeq.current) return;
        if (r.ok) setProbe({ text: "可达" + (r.ms >= 5 ? ` ${r.ms}ms` : ""), cls: "ok" });
        else setProbe({ text: "不可达：" + (r.error || "").replace(/^dial tcp /, ""), cls: "bad" });
      } catch (err) {
        if (seq === probeSeq.current) setProbe({ text: err.message, cls: "bad" });
      }
    }, 420);
  };

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      const payload = {
        name: form.name.trim(),
        target: form.target.trim(),
        basic_user: form.basic_user.trim(),
        rate_limit: Number(form.rate_limit || 0),
      };
      if (form.basic_pass) payload.basic_pass = form.basic_pass;
      if (form.address_id !== "__new") payload.address_id = form.address_id;

      let r;
      if (form.id) {
        r = await api(`/services/${form.id}`, { method: "PATCH", body: JSON.stringify(payload) });
      } else {
        if (payload.address_id === undefined) delete payload.address_id;
        r = await api("/services", { method: "POST", body: JSON.stringify(payload) });
      }
      setForm(null);
      notify(r.warning || (form.id ? "已保存" : "已创建"), !!r.warning);
      await reload();
    } catch (err) {
      notify(err.message, true);
    } finally {
      setBusy(false);
    }
  };

  const patch = async (svc, body, msg) => {
    try {
      const r = await api(`/services/${svc.id}`, { method: "PATCH", body: JSON.stringify(body) });
      notify(r.warning || msg, !!r.warning);
      await reload();
    } catch (err) {
      notify(err.message, true);
    }
  };

  const remove = async (svc) => {
    if (!confirm(`删除服务 ${svc.name}？\n\n地址会留在「地址库」里，可以再绑给别的服务。`)) return;
    try {
      const r = await api(`/services/${svc.id}`, { method: "DELETE" });
      notify(r.warning || "服务已删除，地址已保留", !!r.warning);
      await reload();
    } catch (err) {
      notify(err.message, true);
    }
  };

  const addressOptions = (() => {
    const opts = [];
    if (!form?.id) opts.push({ value: "__new", label: "自动分配新地址" });
    else opts.push({ value: "", label: "不绑定（暂停发布）" });
    unbound.forEach((a) => opts.push({ value: a.id, label: `${a.address}${a.label ? " · " + a.label : ""}` }));
    return opts;
  })();

  return (
    <div>
      <div className="toolbar">
        <span className="spacer" />
        <button className="primary" onClick={() => open(null)}>新增服务</button>
      </div>

      <section className="card">
        {data.services.length === 0 ? (
          <div className="empty">
            <p>还没有服务。给内网的一个端口分配一个 .onion 地址。</p>
            <button className="primary" onClick={() => open(null)}>新增服务</button>
          </div>
        ) : (
          data.services.map((s) => (
            <div className={"row" + (s.enabled ? "" : " off")} key={s.id}>
              <div style={{ minWidth: 0 }}>
                <div className="name">{s.name}</div>
                <div className="addr">
                  {s.address ? <Addr value={s.address} notify={notify} /> : <span className="pending">无地址（未绑定）</span>}
                </div>
                <div className="meta">
                  <span>→ <b>{s.target}</b></span>
                  {s.basic_user ? <span className="tag">auth</span> : null}
                  {s.rate_limit ? <span><b>{s.rate_limit}</b>/min</span> : null}
                </div>
              </div>
              <div className="actions">
                <Toggle
                  on={s.enabled}
                  label={s.enabled ? "停用" : "启用"}
                  onClick={() => patch(s, { enabled: !s.enabled }, s.enabled ? "已停用" : "已启用")}
                />
                <button className="ghost" onClick={() => open(s)}>编辑</button>
                <button className="ghost danger" onClick={() => remove(s)}>删除</button>
              </div>
            </div>
          ))
        )}
      </section>

      {form && (
        <form className="sheet" onSubmit={submit}>
          <h2>{form.id ? "编辑服务" : "新增服务"}</h2>
          <div className="grid">
            <div>
              <label>名称</label>
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="nextcloud" required maxLength={60} />
            </div>
            <div>
              <label>目标</label>
              <input
                value={form.target}
                onChange={(e) => {
                  setForm({ ...form, target: e.target.value });
                  runProbe(e.target.value.trim());
                }}
                placeholder="10.0.0.10:8080"
                spellCheck={false}
                required
              />
              <div className={"hint " + probe.cls}>{probe.text}</div>
            </div>
            <div>
              <label>Basic Auth 用户</label>
              <input
                value={form.basic_user}
                onChange={(e) => setForm({ ...form, basic_user: e.target.value })}
                placeholder={form.id && form.basic_user ? "清空可关闭" : "可选"}
                spellCheck={false}
              />
            </div>
            <div>
              <label>Basic Auth 密码</label>
              <input
                type="password"
                value={form.basic_pass}
                onChange={(e) => setForm({ ...form, basic_pass: e.target.value })}
                placeholder={form.id && form.basic_user ? "留空则不修改" : "可选"}
                autoComplete="new-password"
              />
            </div>
            <div>
              <label>限速（每分钟请求数）</label>
              <input
                type="number"
                min="0"
                max="100000"
                value={form.rate_limit}
                onChange={(e) => setForm({ ...form, rate_limit: e.target.value })}
                placeholder="不限"
              />
            </div>
            <div>
              <label>地址</label>
              <select value={form.address_id} onChange={(e) => setForm({ ...form, address_id: e.target.value })}>
                {addressOptions.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          </div>
          <footer>
            <button type="button" className="ghost" onClick={() => setForm(null)}>取消</button>
            <button className="primary" type="submit" disabled={busy}>{form.id ? "保存" : "创建"}</button>
          </footer>
        </form>
      )}
    </div>
  );
}

/* ---------------- address library ---------------- */

function Addresses({ data, reload, notify }) {
  const [editing, setEditing] = useState(null);
  const [label, setLabel] = useState("");

  const rename = async (a) => {
    try {
      await api(`/addresses/${a.id}`, { method: "PATCH", body: JSON.stringify({ label }) });
      setEditing(null);
      notify("标签已更新");
      await reload();
    } catch (err) {
      notify(err.message, true);
    }
  };

  const unbind = async (a) => {
    try {
      const r = await api(`/addresses/${a.id}/unbind`, { method: "POST" });
      notify(r.warning || "已解绑", !!r.warning);
      await reload();
    } catch (err) {
      notify(err.message, true);
    }
  };

  const remove = async (a) => {
    if (!confirm(`从地址库删除 ${a.address}？\n\n私钥会被丢弃，这个地址永久无法恢复。`)) return;
    try {
      await api(`/addresses/${a.id}`, { method: "DELETE" });
      notify("已从地址库删除");
      await reload();
    } catch (err) {
      notify(err.message, true);
    }
  };

  return (
    <div>
      <div className="toolbar"><span>未绑定的地址不会发布到 Tor</span></div>
      <section className="card">
        {data.addresses.length === 0 ? (
          <div className="empty"><p>地址库是空的。新增服务或采纳一个靓号后会出现在这里。</p></div>
        ) : (
          data.addresses.map((a) => (
            <div className="row" key={a.id}>
              <div style={{ minWidth: 0 }}>
                <div className="addr" style={{ marginTop: 0 }}>
                  <Addr value={a.address} notify={notify} />
                </div>
                <div className="meta">
                  {editing === a.id ? (
                    <>
                      <input
                        style={{ width: 180, padding: "4px 8px", fontSize: 12 }}
                        value={label}
                        autoFocus
                        maxLength={60}
                        onChange={(e) => setLabel(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") rename(a);
                          if (e.key === "Escape") setEditing(null);
                        }}
                      />
                      <button className="ghost" onClick={() => rename(a)}>保存</button>
                      <button className="ghost" onClick={() => setEditing(null)}>取消</button>
                    </>
                  ) : (
                    <>
                      <span>{a.label || "未命名"}</span>
                      <button className="ghost" onClick={() => { setEditing(a.id); setLabel(a.label || ""); }}>重命名</button>
                      {a.source === "vanity" ? <span className="tag vanity">靓号 {a.vanity}</span> : null}
                      {a.service_name ? <span>绑定 → <b>{a.service_name}</b></span> : <span>未绑定</span>}
                    </>
                  )}
                </div>
              </div>
              <div className="actions">
                {a.service_id ? <button className="ghost" onClick={() => unbind(a)}>解绑</button> : null}
                <button className="ghost danger" onClick={() => remove(a)} disabled={!!a.service_id} title={a.service_id ? "先解绑" : ""}>删除</button>
              </div>
            </div>
          ))
        )}
      </section>
    </div>
  );
}

/* ---------------- vanity search ---------------- */

function Vanity({ notify, onAdopted }) {
  const [jobs, setJobs] = useState([]);
  const [workers, setWorkers] = useState(0);
  const [prefix, setPrefix] = useState("");
  const [want, setWant] = useState(1);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const d = await api("/vanity");
      setJobs(d.jobs || []);
      setWorkers(d.workers || 0);
    } catch {
      /* ignore transient errors while polling */
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 1200);
    return () => clearInterval(id);
  }, [load]);

  const start = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      const d = await api("/vanity", { method: "POST", body: JSON.stringify({ prefix, want: Number(want) }) });
      setJobs(d.jobs || []);
      notify("已开始搜索 " + prefix);
    } catch (err) {
      notify(err.message, true);
    } finally {
      setBusy(false);
    }
  };

  const stop = async (job) => {
    try {
      const d = await api(`/vanity/${job.id}/stop`, { method: "POST" });
      setJobs(d.jobs || []);
      notify("已停止");
    } catch (err) {
      notify(err.message, true);
    }
  };

  const adopt = async (job, index) => {
    try {
      await api(`/vanity/${job.id}/adopt`, { method: "POST", body: JSON.stringify({ index }) });
      notify("已加入地址库");
      onAdopted?.();
    } catch (err) {
      notify(err.message, true);
    }
  };

  return (
    <div>
      <form className="sheet" style={{ marginTop: 0 }} onSubmit={start}>
        <h2>前缀靓号</h2>
        <div className="grid">
          <div>
            <label>前缀（a-z、2-7，最长 7 位）</label>
            <input value={prefix} onChange={(e) => setPrefix(e.target.value.toLowerCase())} placeholder="shop" spellCheck={false} required />
            <div className="hint">
              {prefix ? `长度 ${prefix.length}：约 ${Math.pow(32, prefix.length).toLocaleString()} 种组合` : ""}
            </div>
          </div>
          <div>
            <label>要几个</label>
            <input type="number" min="1" max="20" value={want} onChange={(e) => setWant(e.target.value)} />
            <div className="hint">后台并行搜索，占用 {workers} 个 CPU 核心</div>
          </div>
        </div>
        <footer>
          <button className="primary" type="submit" disabled={busy || jobs.some((j) => j.state === "running")}>开始搜索</button>
        </footer>
      </form>

      {jobs.length === 0 ? (
        <p className="hint" style={{ marginTop: 14 }}>
          任务只保存在内存里，重启面板会清空。找到结果后请立刻「加入地址库」。
        </p>
      ) : null}
      {jobs.map((job) => {
        const pct = job.key_space ? Math.min(100, (job.tested / job.key_space) * 100) : 0;
        return (
          <section className="card" key={job.id} style={{ marginTop: 16 }}>
            <div className="row" style={{ borderBottom: "none" }}>
              <div style={{ minWidth: 0 }}>
                <div className="name">.{job.prefix} <span className="tag">{job.state === "running" ? "搜索中" : job.state === "done" ? "已完成" : "已停止"}</span></div>
                <div className="meta">
                  <span>已试 <b>{job.tested.toLocaleString()}</b></span>
                  <span><b>{fmtSpeed(job.speed)}</b>/s</span>
                  {job.state === "running" ? <span>预计 <b>{fmtSeconds(job.eta)}</b></span> : null}
                  <span>找到 <b>{job.found.length}</b>/{job.want}</span>
                </div>
                <div className="progress"><span style={{ width: pct + "%" }} /></div>
              </div>
              <div className="actions">
                {job.state === "running" ? <button className="ghost" onClick={() => stop(job)}>停止</button> : null}
              </div>
            </div>
            {job.found.map((f, i) => (
              <div className="result" key={f.onion_id} style={{ padding: "9px 16px" }}>
                <code>{f.onion_id}.onion</code>
                <span className="spacer" />
                <CopyBtn value={f.onion_id + ".onion"} notify={notify} />
                <button className="ghost" onClick={() => adopt(job, i)}>加入地址库</button>
              </div>
            ))}
          </section>
        );
      })}
    </div>
  );
}

/* ---------------- app shell ---------------- */

export default function App() {
  const [authed, setAuthed] = useState(null);
  const [tab, setTab] = useState("services");
  const [data, setData] = useState({ services: [], addresses: [] });
  const [status, setStatus] = useState(null);
  const [toast, setToast] = useState(null);
  const [pw, setPw] = useState("");
  const toastTimer = useRef(null);

  const notify = useCallback((msg, err = false) => {
    setToast({ msg, err });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 3600);
  }, []);

  const reload = useCallback(async () => {
    const d = await api("/services");
    setData({ services: d.services || [], addresses: d.addresses || [] });
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api("/status"));
    } catch {
      /* keep last known state */
    }
  }, []);

  useEffect(() => {
    const onUnauth = () => setAuthed(false);
    window.addEventListener("og:unauthorized", onUnauth);
    api("/session")
      .then((s) => setAuthed(!!s.authenticated))
      .catch(() => setAuthed(false));
    return () => window.removeEventListener("og:unauthorized", onUnauth);
  }, []);

  useEffect(() => {
    if (!authed) return;
    reload().catch((e) => notify(e.message, true));
    refreshStatus();
    const id = setInterval(refreshStatus, 10000);
    return () => clearInterval(id);
  }, [authed, reload, refreshStatus, notify]);

  const login = async (e) => {
    e.preventDefault();
    try {
      await api("/login", { method: "POST", body: JSON.stringify({ password: pw }) });
      setPw("");
      setAuthed(true);
    } catch (err) {
      notify(err.message, true);
    }
  };

  const logout = async () => {
    try {
      await api("/logout", { method: "POST" });
    } catch {
      /* ignore */
    }
    setAuthed(false);
  };

  if (authed === null) return <div className="wrap" />;

  if (!authed) {
    return (
      <div className="login">
        <form onSubmit={login}>
          <h2>登录面板</h2>
          <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="密码" autoComplete="current-password" />
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button className="primary" type="submit">进入</button>
          </div>
        </form>
        <Toast toast={toast} />
      </div>
    );
  }

  const torOk = status?.tor_ok;
  const ready = torOk && (status?.tor_bootstrap ?? 100) >= 100;
  const torDot = !torOk ? "bad" : ready ? "ok" : "warn";
  const torLabel = !torOk ? "tor" : ready ? "tor" : `tor ${status?.tor_bootstrap ?? 0}%`;

  return (
    <div className="wrap">
      <header className="top">
        <h1>洋葱网关</h1>
        <nav className="menu" aria-label="主导航">
          <button className={tab === "services" ? "active" : ""} onClick={() => setTab("services")}>
            服务<span className="count">{data.services.length}</span>
          </button>
          <button className={tab === "addresses" ? "active" : ""} onClick={() => setTab("addresses")}>
            地址库<span className="count">{data.addresses.length}</span>
          </button>
          <button className={tab === "vanity" ? "active" : ""} onClick={() => setTab("vanity")}>
            靓号
          </button>
        </nav>
        <span className="spacer" />
        <div className="dots">
          <span className={"dot " + torDot} title={status?.tor_version || status?.tor_error || ""}><i />{torLabel}</span>
          <span className={"dot " + (status?.caddy_ok ? "ok" : "bad")} title={status?.caddy_error || ""}><i />caddy</span>
          <button className="ghost" onClick={logout}>退出</button>
        </div>
      </header>

      {status && (!torOk || !status.caddy_ok || !ready) && (
        <div id="banner" className={status.caddy_ok && torOk ? "" : "bad"}>
          <span>
            {!status.caddy_ok
              ? "Caddy 配置下发失败：" + (status.caddy_error || "")
              : !torOk
              ? "Tor 不可达：" + (status.tor_error || "控制端口无响应")
              : `Tor 网络连接中（${status.tor_bootstrap}%）`}
          </span>
          {torOk && !ready ? <span className="bar"><span style={{ width: (status.tor_bootstrap || 0) + "%" }} /></span> : null}
        </div>
      )}

      {tab === "services" && <Services data={data} reload={reload} notify={notify} />}
      {tab === "addresses" && <Addresses data={data} reload={reload} notify={notify} />}
      {tab === "vanity" && <Vanity notify={notify} onAdopted={reload} />}

      <Toast toast={toast} />
    </div>
  );
}
