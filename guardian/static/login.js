document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = document.getElementById("err");
  err.textContent = "";
  const r = await fetch("/api/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: document.getElementById("pw").value }),
  });
  if (r.ok) {
    // Assigning the same URL (e.g. one ending in #/overview) does not reload, so reload explicitly.
    if (location.pathname === "/login") location.replace("/"); else location.reload();
    return;
  }
  const j = await r.json().catch(() => ({}));
  err.textContent = r.status === 429 ? "Too many attempts. Wait 5 minutes and try again." : (j.detail || "Login failed");
});
