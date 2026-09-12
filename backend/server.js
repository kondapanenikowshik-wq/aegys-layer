const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
require("dotenv").config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    project: "Aegys Layer",
    status: "running",
    message: "Cybersecurity backend is online"
  });
});
app.post("/scan-url", (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      error: "URL is required"
    });
  }

  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch {
    return res.status(400).json({
      error: "Invalid URL"
    });
  }

  const suspiciousKeywords = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "password",
    "signin",
    "wallet",
    "confirm"
  ];

  const suspiciousTlds = [
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".gq",
    ".tk"
  ];

  const matchedKeywords = suspiciousKeywords.filter((word) =>
    url.toLowerCase().includes(word)
  );

  const reasons = [];
  let score = 0;

  const usesHttps = parsedUrl.protocol === "https:";

  if (!usesHttps) {
    score += 25;
    reasons.push("URL does not use HTTPS");
  }

  if (matchedKeywords.length > 0) {
    score += Math.min(matchedKeywords.length * 10, 40);
    reasons.push(`Suspicious keywords detected: ${matchedKeywords.join(", ")}`);
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  const suspiciousTld = suspiciousTlds.find((tld) =>
    hostname.endsWith(tld)
  );

  if (suspiciousTld) {
    score += 20;
    reasons.push(`Suspicious top-level domain detected: ${suspiciousTld}`);
  }

  const ipAddressPattern = /^\d{1,3}(\.\d{1,3}){3}$/;

  if (ipAddressPattern.test(hostname)) {
    score += 25;
    reasons.push("URL uses an IP address instead of a domain name");
  }

  if (url.length > 100) {
    score += 10;
    reasons.push("URL is unusually long");
  }

  if (hostname.includes("xn--")) {
    score += 20;
    reasons.push("Possible punycode/domain spoofing detected");
  }

  score = Math.min(score, 100);

  let risk = "low";

  if (score >= 60) {
    risk = "high";
  } else if (score >= 30) {
    risk = "medium";
  }

  res.json({
    url,
    hostname,
    risk,
    riskScore: score,
    usesHttps,
    matchedKeywords,
    reasons
  });
});
const PORT = 3000;

app.listen(PORT, () => {
  console.log(`Aegys Layer running on http://localhost:${PORT}`);
});