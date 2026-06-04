#!/usr/bin/env node
import { Buffer } from "node:buffer";
import fs from "node:fs";

const DEFAULT_SM20_API_URL = "http://s4devapp.daqo.com:8000/sap/zplm_userdata?sap-client=302";

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    const key = item.slice(2).replaceAll("-", "_");
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      result[key] = true;
    } else {
      result[key] = next;
      index += 1;
    }
  }
  return result;
}

function normalizeDate(value) {
  return String(value || "").replaceAll("-", "");
}

function normalizeTime(value, fallback) {
  return String(value || fallback).replaceAll(":", "");
}

function unique(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function loadUsers(args) {
  const values = [];
  if (args.user) {
    values.push(args.user);
  }
  if (args.users) {
    values.push(...String(args.users).split(/[,\n\r;，；]+/));
  }
  if (args.users_file) {
    const text = fs.readFileSync(args.users_file, "utf8");
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) {
        values.push(...parsed);
      } else {
        throw new Error("users file JSON must be an array");
      }
    } catch (error) {
      if (error instanceof SyntaxError) {
        values.push(...text.split(/[,\n\r;，；]+/));
      } else {
        throw error;
      }
    }
  }
  return unique(values);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const user = process.env.SAP_USER;
  const password = process.env.SAP_PASSWORD;
  if (!user || !password) {
    throw new Error("SAP_USER and SAP_PASSWORD are required in environment.");
  }
  const queryDate = normalizeDate(args.date);
  const dateFrom = normalizeDate(args.date_from) || queryDate;
  const dateTo = normalizeDate(args.date_to) || queryDate;
  if (!dateFrom || !dateTo) {
    throw new Error("Use --date or both --date-from and --date-to.");
  }

  const dataIn = {
    DATEFROM: dateFrom,
    TIMEFROM: normalizeTime(args.time_from, "000000"),
    DATETO: dateTo,
    TIMETO: normalizeTime(args.time_to, "235959"),
  };
  const users = loadUsers(args);
  if (users.length > 0) {
    dataIn.USERS = users.map((userid) => ({ USERID: userid }));
  }

  const form = new FormData();
  form.set("data_in", JSON.stringify(dataIn));
  const response = await fetch(args.url || process.env.SAP_SM20_API_URL || DEFAULT_SM20_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`,
      Accept: "application/json, text/plain",
    },
    body: form,
  });
  const responseText = await response.text();
  if (!response.ok) {
    throw new Error(`SAP API failed: HTTP ${response.status} ${responseText.slice(0, 1000)}`);
  }
  if (!responseText.trim()) {
    process.stdout.write("[]\n");
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    parsed = { raw: responseText };
  }
  if (args.max_rows && Array.isArray(parsed)) {
    const maxRows = Math.max(1, Math.min(1000000, Number.parseInt(args.max_rows, 10) || parsed.length));
    parsed = parsed.slice(0, maxRows);
  }
  process.stdout.write(`${JSON.stringify(parsed)}\n`);
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
