// Apply the saved theme before first paint (dark by default, like Grafana).
try { const t = localStorage.getItem("guardian-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* storage blocked */ }
