const jsonOr = (r) => r.json().catch(() => ({}));

export async function api(path, opts = {}) {
  const res = await fetch(`/api${path}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await jsonOr(res);
  if (res.status === 401) {
    window.dispatchEvent(new Event("og:unauthorized"));
    throw new Error("需要登录");
  }
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

export const shortAddr = (a) =>
  !a || a.length <= 26 ? a || "" : `${a.slice(0, 8)}…${a.slice(-12)}`;

export const fmtSeconds = (s) => {
  if (!s || !isFinite(s)) return "—";
  if (s < 60) return `${Math.round(s)} 秒`;
  if (s < 3600) return `${Math.round(s / 60)} 分钟`;
  if (s < 86400) return `${(s / 3600).toFixed(1)} 小时`;
  return `${(s / 86400).toFixed(1)} 天`;
};

export const fmtSpeed = (n) => {
  if (!n) return "0";
  if (n < 1000) return `${Math.round(n)}`;
  if (n < 1e6) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1e6).toFixed(1)}M`;
};
