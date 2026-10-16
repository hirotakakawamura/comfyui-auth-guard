// comfyui-auth-guard client example (Node.js 18+): npm install jose ws
// env: COMFY_URL, COMFY_PRIVKEY, COMFY_AUD, INPUT_IMAGE
import { SignJWT, importPKCS8 } from "jose";
import WebSocket from "ws";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const URL_ = process.env.COMFY_URL ?? "http://127.0.0.1:8188";
const AUD = process.env.COMFY_AUD ?? "comfyui";
const key = await importPKCS8(await readFile(process.env.COMFY_PRIVKEY ?? "keys/private.pem", "utf8"), "EdDSA");

// New token for EVERY request (jti is single-use)
async function auth() {
  const t = await new SignJWT({ scope: "generate" })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
    .setSubject("webapp-user-1").setAudience(AUD)
    .setIssuedAt().setExpirationTime("60s").setJti(randomUUID())
    .sign(key);
  return { Authorization: `Bearer ${t}` };
}
async function call(path, init = {}) {
  const r = await fetch(URL_ + path, { ...init, headers: { ...(init.headers ?? {}), ...(await auth()) } });
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${await r.text()}`);
  return r;
}

console.log("system_stats:", (await call("/system_stats")).status);

const fd = new FormData();
fd.append("image", new Blob([await readFile(process.env.INPUT_IMAGE ?? "input.png")], { type: "image/png" }), "auth_guard_test_node.png");
fd.append("overwrite", "true");
const up = await (await call("/upload/image", { method: "POST", body: fd })).json();
console.log("uploaded:", up);

const { ticket } = await (await call("/auth/ws-ticket", { method: "POST" })).json();
const clientId = randomUUID();
const ws = new WebSocket(`${URL_.replace(/^http/, "ws")}/ws?clientId=${clientId}&ticket=${ticket}`);
await new Promise((res, rej) => { ws.once("open", res); ws.once("error", rej); });

const workflow = {
  "1": { class_type: "LoadImage", inputs: { image: up.name } },
  "2": { class_type: "SaveImage", inputs: { images: ["1", 0], filename_prefix: "authguard_node" } },
};
const { prompt_id } = await (await call("/prompt", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ prompt: workflow, client_id: clientId }),
})).json();
console.log("prompt_id:", prompt_id);

await new Promise((res, rej) => ws.on("message", (data, isBinary) => {
  if (isBinary) return;
  const m = JSON.parse(data.toString());
  if (m.type === "executing" && m.data.node === null && m.data.prompt_id === prompt_id) res();
  if (m.type === "execution_error") rej(new Error(JSON.stringify(m)));
}));
ws.close();

const hist = await (await call(`/history/${prompt_id}`)).json();
const img = hist[prompt_id].outputs["2"].images[0];
const v = await call("/view?" + new URLSearchParams(img));
console.log("view:", v.status, v.headers.get("content-type"), (await v.arrayBuffer()).byteLength, "bytes");
