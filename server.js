const express = require("express");
const path = require("path");

const {
  saveScan,
  getScanHistory,
} = require("./services/database");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -----------------------------
// Helper Functions
// -----------------------------

function isValidIPv4(ip) {
  const parts = ip.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;

    const number = Number(part);

    return number >= 0 && number <= 255;
  });
}

function isValidDomain(domain) {
  const domainRegex =
    /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

  return domainRegex.test(domain);
}

function isValidTarget(target) {
  return isValidIPv4(target) || isValidDomain(target);
}

function generateFindings(target) {
  const findings = [];

  const normalizedTarget = target.toLowerCase();

  if (target.length % 2 === 0) {
    findings.push({
      title: "Open SSH Service",
      severity: "medium",
      description:
        "SSH appears to be accessible and should be reviewed for unnecessary exposure.",
      remediation:
        "Restrict SSH access using firewall rules, VPN access, allowlists, and strong authentication.",
    });
  }

  if (
    normalizedTarget.includes("admin") ||
    target.length > 12
  ) {
    findings.push({
      title: "Weak Authentication Controls",
      severity: "high",
      description:
        "The target may have authentication controls that require additional hardening.",
      remediation:
        "Enable multi-factor authentication, strong password policies, account lockout protections, and least privilege.",
    });
  }

  if (
    normalizedTarget.includes("test") ||
    normalizedTarget.includes("dev")
  ) {
    findings.push({
      title: "Development Environment Exposed",
      severity: "critical",
      description:
        "A development or testing environment may be publicly exposed.",
      remediation:
        "Remove public exposure, restrict access, disable debugging features, and separate development infrastructure from production.",
    });
  }

  if (!normalizedTarget.startsWith("secure")) {
    findings.push({
      title: "Security Headers Missing",
      severity: "medium",
      description:
        "Recommended web security headers may not be fully configured.",
      remediation:
        "Configure headers such as Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and other appropriate protections.",
    });
  }

  if (findings.length === 0) {
    findings.push({
      title: "No Major Issues Detected",
      severity: "low",
      description:
        "The simulated assessment did not identify major security concerns.",
      remediation:
        "Continue monitoring the environment and regularly review security configurations.",
    });
  }

  return findings;
}

function calculateRisk(findings) {
  const severityScores = {
    low: 10,
    medium: 30,
    high: 60,
    critical: 100,
  };

  let riskScore = 0;

  findings.forEach((finding) => {
    riskScore += severityScores[finding.severity] || 0;
  });

  riskScore = Math.min(riskScore, 100);

  let riskLevel = "LOW";
  let grade = "A";

  if (riskScore >= 90) {
    riskLevel = "CRITICAL";
    grade = "F";
  } else if (riskScore >= 60) {
    riskLevel = "HIGH";
    grade = "D";
  } else if (riskScore >= 40) {
    riskLevel = "MEDIUM";
    grade = "C";
  } else if (riskScore >= 20) {
    riskLevel = "MEDIUM";
    grade = "B";
  }

  return {
    riskScore,
    riskLevel,
    grade,
  };
}

// -----------------------------
// API Routes
// -----------------------------

app.get("/api/health", (req, res) => {
  res.json({
    status: "online",
    service: "AegisLayer",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/scan", (req, res) => {
  const target = String(req.query.target || "")
    .trim()
    .toLowerCase();

  if (!target) {
    return res.status(400).json({
      error: "Target is required.",
    });
  }

  if (!isValidTarget(target)) {
    return res.status(400).json({
      error:
        "Please enter a valid domain or IPv4 address.",
    });
  }

  const findings = generateFindings(target);

  const {
    riskScore,
    riskLevel,
    grade,
  } = calculateRisk(findings);

  const scanResult = {
    target,
    riskScore,
    riskLevel,
    grade,
    findings,
    createdAt: new Date().toISOString(),
  };

  try {
    const id = saveScan(scanResult);

    res.json({
      id,
      ...scanResult,
    });
  } catch (error) {
    console.error("Database save error:", error);

    res.status(500).json({
      error: "Unable to save scan.",
    });
  }
});

app.get("/api/history", (req, res) => {
  try {
    const history = getScanHistory(10);

    res.json(history);
  } catch (error) {
    console.error("History error:", error);

    res.status(500).json({
      error: "Unable to load scan history.",
    });
  }
});

// -----------------------------
// Dashboard
// -----------------------------

app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  />

  <title>AegisLayer Security Dashboard</title>

  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family:
        Inter,
        Arial,
        Helvetica,
        sans-serif;

      background: #070b14;
      color: #f4f7fb;
      min-height: 100vh;
    }

    .layout {
      display: flex;
      min-height: 100vh;
    }

    .sidebar {
      width: 240px;
      background: #0b1220;
      border-right: 1px solid #1d2939;
      padding: 26px 18px;
    }

    .logo {
      font-size: 24px;
      font-weight: 800;
      margin-bottom: 6px;
    }

    .logo span {
      color: #66e3ff;
    }

    .subtitle {
      color: #8c9bad;
      font-size: 12px;
      margin-bottom: 40px;
    }

    .nav-item {
      padding: 12px 14px;
      border-radius: 8px;
      margin-bottom: 8px;
      color: #aab7c8;
    }

    .nav-item.active {
      background: #121d30;
      color: #ffffff;
    }

    .main {
      flex: 1;
      padding: 32px;
      max-width: 1400px;
      margin: auto;
      width: 100%;
    }

    h1 {
      font-size: 30px;
      margin-bottom: 8px;
    }

    .description {
      color: #8c9bad;
      margin-bottom: 28px;
    }

    .scanner {
      background: #0d1524;
      border: 1px solid #1f2a3a;
      border-radius: 14px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .scanner h2 {
      margin-bottom: 16px;
    }

    .scan-row {
      display: flex;
      gap: 12px;
    }

    input {
      flex: 1;
      padding: 14px 16px;

      border-radius: 8px;
      border: 1px solid #263349;

      background: #080e19;
      color: white;

      font-size: 15px;
      outline: none;
    }

    input:focus {
      border-color: #3ca9ff;
    }

    button {
      padding: 14px 22px;
      border: none;
      border-radius: 8px;

      background: #207cff;
      color: white;

      font-weight: 700;
      cursor: pointer;
    }

    button:hover {
      background: #3b8dff;
    }

    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .status {
      margin-top: 14px;
      color: #8c9bad;
      font-size: 14px;
      min-height: 20px;
    }

    .cards {
      display: grid;

      grid-template-columns:
        repeat(3, 1fr);

      gap: 16px;
      margin-bottom: 24px;
    }

    .card {
      background: #0d1524;
      border: 1px solid #1f2a3a;
      border-radius: 12px;
      padding: 22px;
    }

    .label {
      color: #8c9bad;
      font-size: 13px;
      margin-bottom: 10px;
    }

    .value {
      font-size: 30px;
      font-weight: 800;
    }

    .section {
      background: #0d1524;
      border: 1px solid #1f2a3a;
      border-radius: 12px;
      padding: 22px;
      margin-bottom: 24px;
    }

    .section h2 {
      margin-bottom: 18px;
    }

    .finding {
      background: #09111e;
      border: 1px solid #1b283b;
      border-radius: 9px;
      padding: 16px;
      margin-bottom: 12px;
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }

    .finding-title {
      font-weight: 700;
    }

    .severity {
      padding: 4px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
    }

    .critical {
      background: rgba(255, 65, 65, 0.15);
      color: #ff5656;
    }

    .high {
      background: rgba(255, 132, 55, 0.15);
      color: #ff943e;
    }

    .medium {
      background: rgba(255, 209, 84, 0.15);
      color: #ffd154;
    }

    .low {
      background: rgba(80, 224, 146, 0.15);
      color: #50e092;
    }

    .finding p {
      color: #a8b4c4;
      line-height: 1.6;
      font-size: 14px;
    }

    .remediation {
      margin-top: 9px;
    }

    .remediation strong {
      color: white;
    }

    .history-item {
      display: grid;

      grid-template-columns:
        2fr 1fr 1fr 1fr;

      gap: 10px;

      background: #09111e;
      border: 1px solid #1b283b;

      padding: 13px;
      border-radius: 8px;

      margin-bottom: 8px;

      align-items: center;
    }

    .history-target {
      font-weight: 700;
    }

    .muted {
      color: #8c9bad;
    }

    .empty {
      color: #8c9bad;
      padding: 15px 0;
    }

    @media (max-width: 850px) {
      .sidebar {
        display: none;
      }

      .main {
        padding: 20px;
      }

      .cards {
        grid-template-columns: 1fr;
      }

      .scan-row {
        flex-direction: column;
      }

      .history-item {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>

<body>

<div class="layout">

  <aside class="sidebar">

    <div class="logo">
      Aegis<span>Layer</span>
    </div>

    <div class="subtitle">
      Cybersecurity Risk Intelligence
    </div>

    <div class="nav-item active">
      Security Dashboard
    </div>

    <div class="nav-item">
      Scan History
    </div>

    <div class="nav-item">
      Risk Intelligence
    </div>

  </aside>

  <main class="main">

    <h1>Security Dashboard</h1>

    <div class="description">
      Analyze domains and IPv4 addresses using the
      AegisLayer risk intelligence engine.
    </div>

    <div class="scanner">

      <h2>Run Security Assessment</h2>

      <div class="scan-row">

        <input
          id="targetInput"
          type="text"
          placeholder="example.com or 192.168.1.1"
        />

        <button
          id="scanButton"
          onclick="runScan()"
        >
          Scan Target
        </button>

      </div>

      <div
        id="status"
        class="status"
      ></div>

    </div>

    <div class="cards">

      <div class="card">

        <div class="label">
          Risk Score
        </div>

        <div
          id="riskScore"
          class="value"
        >
          --
        </div>

      </div>

      <div class="card">

        <div class="label">
          Risk Level
        </div>

        <div
          id="riskLevel"
          class="value"
        >
          --
        </div>

      </div>

      <div class="card">

        <div class="label">
          Security Grade
        </div>

        <div
          id="grade"
          class="value"
        >
          --
        </div>

      </div>

    </div>

    <div class="section">

      <h2>Security Findings</h2>

      <div id="findings">

        <div class="empty">
          Run a scan to display security findings.
        </div>

      </div>

    </div>

    <div class="section">

      <h2>Recent Scan History</h2>

      <div id="history">

        <div class="empty">
          Loading scan history...
        </div>

      </div>

    </div>

  </main>

</div>

<script>

  async function runScan() {

    const input =
      document.getElementById("targetInput");

    const button =
      document.getElementById("scanButton");

    const status =
      document.getElementById("status");

    const target =
      input.value.trim();

    if (!target) {

      status.textContent =
        "Enter a domain or IPv4 address.";

      return;
    }

    button.disabled = true;

    button.textContent =
      "Scanning...";

    status.textContent =
      "Running security assessment...";

    try {

      const response =
        await fetch(
          "/api/scan?target=" +
          encodeURIComponent(target)
        );

      const data =
        await response.json();

      if (!response.ok) {

        throw new Error(
          data.error ||
          "Scan failed."
        );
      }

      document.getElementById(
        "riskScore"
      ).textContent =
        data.riskScore + "/100";

      document.getElementById(
        "riskLevel"
      ).textContent =
        data.riskLevel;

      document.getElementById(
        "grade"
      ).textContent =
        data.grade;

      renderFindings(
        data.findings
      );

      status.textContent =
        "Assessment completed successfully.";

      loadHistory();

    } catch (error) {

      status.textContent =
        error.message;

    } finally {

      button.disabled = false;

      button.textContent =
        "Scan Target";

    }
  }

  function renderFindings(findings) {

    const container =
      document.getElementById("findings");

    container.innerHTML = "";

    findings.forEach((finding) => {

      const element =
        document.createElement("div");

      element.className =
        "finding";

      element.innerHTML = \`

        <div class="finding-header">

          <div class="finding-title">
            \${escapeHTML(finding.title)}
          </div>

          <div class="severity \${finding.severity}">
            \${finding.severity.toUpperCase()}
          </div>

        </div>

        <p>
          \${escapeHTML(finding.description)}
        </p>

        <p class="remediation">

          <strong>
            Recommendation:
          </strong>

          \${escapeHTML(finding.remediation)}

        </p>

      \`;

      container.appendChild(
        element
      );
    });
  }

  async function loadHistory() {

    const container =
      document.getElementById("history");

    try {

      const response =
        await fetch("/api/history");

      const history =
        await response.json();

      if (!response.ok) {

        throw new Error(
          "Unable to load history."
        );
      }

      if (!history.length) {

        container.innerHTML =
          '<div class="empty">No scans saved yet.</div>';

        return;
      }

      container.innerHTML = "";

      history.forEach((scan) => {

        const element =
          document.createElement("div");

        element.className =
          "history-item";

        const date =
          new Date(
            scan.createdAt
          ).toLocaleString();

        element.innerHTML = \`

          <div>

            <div class="history-target">
              \${escapeHTML(scan.target)}
            </div>

            <div class="muted">
              \${escapeHTML(date)}
            </div>

          </div>

          <div>
            Score:
            <strong>
              \${scan.riskScore}
            </strong>
          </div>

          <div>
            \${escapeHTML(scan.riskLevel)}
          </div>

          <div>
            Grade:
            <strong>
              \${escapeHTML(scan.grade)}
            </strong>
          </div>

        \`;

        container.appendChild(
          element
        );
      });

    } catch (error) {

      container.innerHTML =
        '<div class="empty">Unable to load history.</div>';

    }
  }

  function escapeHTML(value) {

    const div =
      document.createElement("div");

    div.textContent =
      String(value);

    return div.innerHTML;
  }

  document
    .getElementById("targetInput")
    .addEventListener(
      "keydown",
      function(event) {

        if (event.key === "Enter") {
          runScan();
        }

      }
    );

  loadHistory();

</script>

</body>
</html>
  `);
});
// -----------------------------
// Start Server
// -----------------------------

app.listen(PORT, () => {
  console.log("");
  console.log("🛡️ AegisLayer is running");
  console.log(`🌐 Dashboard: http://localhost:${PORT}`);
  console.log(`❤️ Health: http://localhost:${PORT}/api/health`);
  console.log("");
});
