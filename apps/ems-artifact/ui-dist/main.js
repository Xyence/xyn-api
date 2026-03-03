const assetsBody = document.getElementById("assets-body");
const form = document.getElementById("asset-form");
const errorEl = document.getElementById("error");
const refreshBtn = document.getElementById("refresh");

function showError(message) {
  if (!errorEl) return;
  if (!message) {
    errorEl.hidden = true;
    errorEl.textContent = "";
    return;
  }
  errorEl.hidden = false;
  errorEl.textContent = message;
}

function renderAssets(items) {
  if (!assetsBody) return;
  assetsBody.innerHTML = "";
  for (const item of items || []) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.name || "-"}</td>
      <td>${item.type || "-"}</td>
      <td>${item.location || "-"}</td>
      <td>${item.status || "-"}</td>
      <td>${item.created_at || "-"}</td>
    `;
    assetsBody.appendChild(row);
  }
}

async function loadAssets() {
  showError("");
  try {
    const response = await fetch("/api/apps/ems/assets", { credentials: "include" });
    if (!response.ok) throw new Error(`load failed (${response.status})`);
    const payload = await response.json();
    renderAssets(payload.items || []);
  } catch (error) {
    showError(String(error));
  }
}

if (form) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showError("");
    const formData = new FormData(form);
    const payload = {
      name: String(formData.get("name") || "").trim(),
      type: String(formData.get("type") || "").trim(),
      location: String(formData.get("location") || "").trim(),
      status: String(formData.get("status") || "").trim() || "active",
    };
    try {
      const response = await fetch("/api/apps/ems/assets", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(`create failed (${response.status})`);
      form.reset();
      await loadAssets();
    } catch (error) {
      showError(String(error));
    }
  });
}

if (refreshBtn) {
  refreshBtn.addEventListener("click", () => {
    void loadAssets();
  });
}

void loadAssets();
