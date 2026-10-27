(() => {
  "use strict";
  const status = document.getElementById("refresh-status");
  const canvas = document.getElementById("tf-network-canvas");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function renderDnsEvents(events) {
    const tbody = document.getElementById("dns-event-rows");
    const count = document.getElementById("dns-event-count");
    if (!tbody) return;

    const rows = Array.isArray(events) ? events.slice(-100).reverse() : [];
    if (count) count.textContent = rows.length + " EVENTS";
    tbody.replaceChildren();

    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "empty";
      td.textContent = "No DNS metadata captured yet. Start the DNS monitor.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const event of rows) {
      const tr = document.createElement("tr");
      const values = [
        event.timestamp_utc,
        event.event_type,
        event.domain,
        event.query_type,
        event.source_ip,
        event.destination_ip
      ];
      values.forEach((value, index) => {
        const td = document.createElement("td");
        const safeValue = String(value ?? "—");
        if (index === 1) {
          const tag = document.createElement("span");
          tag.className = "tag";
          tag.textContent = safeValue;
          td.appendChild(tag);
        } else {
          td.textContent = safeValue;
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    }
  }

  async function refreshDashboard() {
    if (!status) return;
    try {
      const response = await fetch("/api/dashboard", {
        headers: {"Accept": "application/json"},
        credentials: "same-origin",
        cache: "no-store"
      });
      if (response.status === 401 || response.redirected) {
        status.textContent = "Session expired; reload to sign in.";
        return;
      }
      if (!response.ok) throw new Error("Refresh failed");
      const data = await response.json();
      renderDnsEvents(data.network_events);
      for (const [id, value] of [
        ["incident-count", data.incident_count],
        ["alert-count", data.alert_count],
        ["host-count", data.host_count],
        ["source-count", data.source_count]
      ]) {
        const node = document.getElementById(id);
        if (node) {
          const next = String(value ?? 0);
          if (node.textContent !== next) {
            node.textContent = next;
            node.classList.remove("tf-value-updated");
            void node.offsetWidth;
            node.classList.add("tf-value-updated");
          }
        }
      }
      status.textContent = "Last refreshed " + new Date().toLocaleTimeString();
    } catch (_) {
      status.textContent = "Refresh unavailable; showing last loaded data.";
    }
  }

  if (status) window.setInterval(refreshDashboard, 15000);

  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  let width = 0, height = 0, frame = 0, raf = 0;
  const nodes = Array.from({length: 34}, (_, i) => ({
    x: .05 + Math.random() * .9,
    y: .08 + Math.random() * .84,
    phase: Math.random() * Math.PI * 2,
    size: i % 7 === 0 ? 2.7 : 1.3
  }));
  const signals = Array.from({length: 12}, (_, i) => ({
    from: (i * 3) % nodes.length,
    to: (i * 7 + 9) % nodes.length,
    phase: Math.random()
  }));

  function resize() {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(1, rect.width);
    height = Math.max(1, rect.height);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }
  function draw() {
    ctx.clearRect(0, 0, width, height);
    const t = frame * .012;
    nodes.forEach((a, i) => {
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = (a.x - b.x) * width;
        const dy = (a.y - b.y) * height;
        const dist = Math.hypot(dx, dy);
        if (dist < Math.min(width * .19, 115)) {
          ctx.beginPath();
          ctx.moveTo(a.x * width, a.y * height);
          ctx.lineTo(b.x * width, b.y * height);
          ctx.strokeStyle = `rgba(44, 157, 224, ${.13 * (1 - dist / Math.min(width * .19, 115))})`;
          ctx.lineWidth = .7;
          ctx.stroke();
        }
      }
    });
    signals.forEach((s, i) => {
      const a = nodes[s.from], b = nodes[s.to];
      const pulse = (t * .22 + s.phase) % 1;
      ctx.beginPath();
      ctx.moveTo(a.x * width, a.y * height);
      ctx.lineTo(b.x * width, b.y * height);
      ctx.strokeStyle = i % 3 === 0 ? "rgba(167,139,250,.32)" : "rgba(57,217,255,.34)";
      ctx.lineWidth = 1;
      ctx.stroke();
      const x = (a.x + (b.x - a.x) * pulse) * width;
      const y = (a.y + (b.y - a.y) * pulse) * height;
      ctx.beginPath();
      ctx.arc(x, y, 2, 0, Math.PI * 2);
      ctx.fillStyle = i % 3 === 0 ? "#b8a0ff" : "#55e5ff";
      ctx.shadowBlur = 10;
      ctx.shadowColor = ctx.fillStyle;
      ctx.fill();
      ctx.shadowBlur = 0;
    });
    nodes.forEach((n) => {
      const pulse = .5 + .5 * Math.sin(t + n.phase);
      ctx.beginPath();
      ctx.arc(n.x * width, n.y * height, n.size + pulse * .6, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(91, 216, 255, ${.45 + pulse * .5})`;
      ctx.fill();
    });
    if (!reducedMotion) {
      frame++;
      raf = window.requestAnimationFrame(draw);
    }
  }
  if (reducedMotion) {
    resize();
  } else {
    resize();
    if ("ResizeObserver" in window) {
      new ResizeObserver(resize).observe(canvas);
    } else {
      window.addEventListener("resize", resize);
    }
  }
})();
