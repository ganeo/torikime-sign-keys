#!/usr/bin/env node
// トリキメサインの PDF を、当社のサービスを使わずに確かめるスクリプト。
// 必要なのは Node.js(20 以上)だけ。ほかの道具は要りません。
//
//   node verify.mjs 契約書.pdf [public-keys.json]
//
// 1. PDF に添付された contract.json を正規化(RFC 8785)して SHA-256 で要約し、
//    signature-record.json の contract_sha256 と同じかを確かめる
// 2. signature-record.json を、signature.txt(当社の署名)と当社の公開鍵で、Ed25519 の署名として確かめる
// 3. 署名した時刻に、その鍵を使っていたか(使った期間・漏れた時刻)を、公開鍵の一覧で確かめる
//
// 添付をうまく取り出せないとき(ほかのソフトで保存し直した PDF など)は、PDF を開くソフトや
// poppler の pdfdetach などで3つの添付を取り出し、README の OpenSSL の手順で確かめてください。

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inflateSync } from "node:zlib";

/** RFC 8785(JSON Canonicalization Scheme)の考え方で、JSON を決まった形の文字列にする */
export function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("number must be finite");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
  }
  throw new Error(`cannot canonicalize ${typeof value}`);
}

function decodePdfString(raw) {
  if (raw.startsWith("<")) {
    const hex = raw.slice(1, -1).replace(/\s+/g, "");
    const bytes = Buffer.from(hex.length % 2 ? `${hex}0` : hex, "hex");
    if (bytes[0] === 0xfe && bytes[1] === 0xff) {
      const swapped = Buffer.from(bytes.subarray(2));
      swapped.swap16();
      return swapped.toString("utf16le");
    }
    return bytes.toString("latin1");
  }
  return raw
    .slice(1, -1)
    .replace(/\\([nrtbf()\\])/g, (_, c) => ({ n: "\n", r: "\r", t: "\t", b: "\b", f: "\f" })[c] ?? c);
}

/** PDF に添付されたファイルを取り出す(トリキメサインの PDF の形を前提にした、小さな読み取り) */
export function extractAttachments(pdf) {
  const bytes = Buffer.from(pdf);
  const text = bytes.toString("latin1");
  const starts = [...text.matchAll(/(\d+) 0 obj\b/g)].map((m) => ({ id: Number(m[1]), at: m.index }));
  const objects = new Map();
  starts.forEach((o, i) => objects.set(o.id, { at: o.at, end: starts[i + 1]?.at ?? text.length }));
  const body = (id) => {
    const o = objects.get(id);
    return o ? text.slice(o.at, o.end) : "";
  };

  const files = new Map();
  for (const [, o] of objects) {
    const spec = text.slice(o.at, o.end);
    if (!/\/Type\s*\/Filespec/.test(spec)) continue;
    const name = /\/UF\s*(<[0-9A-Fa-f\s]*>|\((?:\\.|[^\\)])*\))/.exec(spec) ?? /\/F\s*(<[0-9A-Fa-f\s]*>|\((?:\\.|[^\\)])*\))/.exec(spec);
    const ref = /\/EF\s*<<\s*\/F\s+(\d+)\s+0\s+R/.exec(spec);
    if (!name || !ref) continue;
    const stream = body(Number(ref[1]));
    const length = /\/Length\s+(\d+)/.exec(stream);
    const start = /stream\r?\n/.exec(stream);
    if (!length || !start) continue;
    const from = objects.get(Number(ref[1])).at + start.index + start[0].length;
    let data = bytes.subarray(from, from + Number(length[1]));
    if (/\/Filter\s*\/FlateDecode/.test(stream.slice(0, start.index))) data = inflateSync(data);
    files.set(decodePdfString(name[1]), new Uint8Array(data));
  }
  return files;
}

function keyCheck(keyList, keyId, signedAt) {
  const key = (keyList?.keys ?? []).find((k) => k.key_id === keyId && k.algorithm === "Ed25519");
  if (!key) return { key: null, check: "unknown" };
  const t = Date.parse(signedAt);
  if (Number.isNaN(t) || t < Date.parse(key.valid_from) || (key.valid_until && t > Date.parse(key.valid_until))) {
    return { key, check: "outside_period" };
  }
  if (key.status === "compromised") return { key, check: t >= Date.parse(key.compromised_at) ? "compromised" : "ok" };
  return { key, check: "ok" };
}

/** PDF を確かめ、結果(ok)と、人が読む説明の行を返す */
export function verifyPdf(pdf, keyList) {
  const lines = [];
  const files = extractAttachments(pdf);
  const get = (n) => (files.has(n) ? new TextDecoder().decode(files.get(n)) : null);
  const contractText = get("contract.json");
  const recordText = get("signature-record.json");
  const signature = get("signature.txt");
  if (contractText === null || recordText === null || signature === null) {
    return { ok: false, lines: ["× 添付(contract.json・signature-record.json・signature.txt)が見つかりません。トリキメサインの PDF ではないか、ほかのソフトで保存し直されています。"] };
  }
  const record = JSON.parse(recordText);
  let ok = true;

  const hash = createHash("sha256").update(canonicalize(JSON.parse(contractText)), "utf8").digest("hex");
  if (hash === record.contract_sha256) lines.push("○ 中身が署名のときと同じ(contract_sha256 が一致)");
  else {
    ok = false;
    lines.push("× 中身が署名のときと違います(contract_sha256 が一致しない)");
  }

  const isCanonical = canonicalize(record) === recordText;
  const { key, check } = keyCheck(keyList, record.key_id, record.counterparty?.signed_at);
  if (!key) {
    ok = false;
    lines.push(`× 公開鍵の一覧に、鍵 ${record.key_id} がありません`);
  } else {
    const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.public_key }, format: "jwk" });
    const sig = Buffer.from(signature.trim(), "base64url");
    if (isCanonical && verify(null, Buffer.from(recordText, "utf8"), publicKey, sig)) {
      lines.push(`○ トリキメサインが署名した記録(鍵 ${record.key_id} で確かめた)`);
    } else {
      ok = false;
      lines.push("× 署名が合いません");
    }
    if (check === "outside_period") {
      ok = false;
      lines.push("× 鍵を使っていた期間の外の署名です");
    } else if (check === "compromised") {
      ok = false;
      lines.push("× 漏れたと分かったあとに、その鍵で署名されています");
    }
  }
  lines.unshift(ok ? "書き換えられていません。" : "確かめられませんでした。");
  lines.push(`記録の番号:${record.id}  署名した日時:${record.counterparty?.signed_at}`);
  return { ok, lines };
}

// コマンドとして動かしたとき
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [pdfPath, keysPath] = process.argv.slice(2);
  if (!pdfPath) {
    console.error("使い方:node verify.mjs 契約書.pdf [public-keys.json]");
    process.exit(2);
  }
  const keyList = JSON.parse(readFileSync(keysPath ?? join(dirname(fileURLToPath(import.meta.url)), "public-keys.json"), "utf8"));
  const result = verifyPdf(readFileSync(pdfPath), keyList);
  console.log(result.lines.join("\n"));
  process.exit(result.ok ? 0 : 1);
}
