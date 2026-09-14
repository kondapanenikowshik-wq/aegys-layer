const Database = require("better-sqlite3");
const path = require("path");

const dbPath = path.join(__dirname, "..", "data", "aegislayer.db");
const db = new Database(dbPath);

db.prepare(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    riskScore INTEGER NOT NULL,
    riskLevel TEXT NOT NULL,
    grade TEXT NOT NULL,
    findings TEXT NOT NULL,
    createdAt TEXT NOT NULL
  )
`).run();

function saveScan(scan) {
  const stmt = db.prepare(`
    INSERT INTO scans (
      target,
      riskScore,
      riskLevel,
      grade,
      findings,
      createdAt
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    scan.target,
    scan.riskScore,
    scan.riskLevel,
    scan.grade,
    JSON.stringify(scan.findings),
    scan.createdAt
  );

  return result.lastInsertRowid;
}

function getScanHistory(limit = 10) {
  const rows = db.prepare(`
    SELECT *
    FROM scans
    ORDER BY id DESC
    LIMIT ?
  `).all(limit);

  return rows.map((row) => ({
    ...row,
    findings: JSON.parse(row.findings),
  }));
}

module.exports = {
  saveScan,
  getScanHistory,
};