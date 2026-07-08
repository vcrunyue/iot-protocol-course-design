const HEADER_1 = 0xaa;
const HEADER_2 = 0x55;
const FOOTER_1 = 0x55;
const FOOTER_2 = 0xaa;
const MAX_DATA_LEN = 255;

const historyRecords = [];

export function copyBytes(bytes) {
  return new Uint8Array(bytes);
}

export function checksum(bytes) {
  let sum = 0;
  for (const byte of bytes) {
    sum ^= byte;
  }
  return sum;
}

export function xorTransform(bytes, key) {
  const result = new Uint8Array(bytes.length);
  const normalizedKey = key & 0xff;
  for (let i = 0; i < bytes.length; i += 1) {
    result[i] = bytes[i] ^ normalizedKey;
  }
  return result;
}

export function caesarTransform(bytes, shift) {
  const result = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) {
    result[i] = ((bytes[i] + shift) % 256 + 256) % 256;
  }
  return result;
}

export function encryptBytes(bytes, method, key) {
  return method === "xor" ? xorTransform(bytes, key) : caesarTransform(bytes, key);
}

export function decryptBytes(bytes, method, key) {
  return method === "xor" ? xorTransform(bytes, key) : caesarTransform(bytes, -key);
}

export function buildFrame(payload) {
  const frame = new Uint8Array(payload.length + 6);
  frame[0] = HEADER_1;
  frame[1] = HEADER_2;
  frame[2] = payload.length;
  frame.set(payload, 3);
  frame[3 + payload.length] = checksum(payload);
  frame[4 + payload.length] = FOOTER_1;
  frame[5 + payload.length] = FOOTER_2;
  return frame;
}

export function parseFrame(frame) {
  if (!frame || frame.length < 6) {
    return { ok: false, error: "解析失败: 帧长度不足。" };
  }
  if (frame[0] !== HEADER_1 || frame[1] !== HEADER_2) {
    return { ok: false, error: "解析失败: 帧头错误。" };
  }
  if (frame[frame.length - 2] !== FOOTER_1 || frame[frame.length - 1] !== FOOTER_2) {
    return { ok: false, error: "解析失败: 帧尾错误。" };
  }

  const length = frame[2];
  if (length + 6 !== frame.length) {
    return { ok: false, error: "解析失败: 长度字段不匹配。" };
  }

  const payload = frame.slice(3, 3 + length);
  const frameChecksum = frame[3 + length];
  const checksumPassed = checksum(payload) === frameChecksum;
  return {
    ok: true,
    length,
    payload,
    checksum: frameChecksum,
    checksumPassed,
  };
}

export function injectError(frame) {
  const changed = copyBytes(frame);
  const byteIndex = Math.floor(Math.random() * changed.length);
  const bitIndex = Math.floor(Math.random() * 8);
  changed[byteIndex] ^= 1 << bitIndex;
  return changed;
}

export function simulateTransmission(payload, probabilityPercent) {
  const sentFrame = buildFrame(payload);
  const shouldChange = probabilityPercent > 0 && Math.random() * 100 <= probabilityPercent;
  return {
    sentFrame,
    receivedFrame: shouldChange ? injectError(sentFrame) : copyBytes(sentFrame),
    changed: shouldChange,
  };
}

export function frameToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).toUpperCase().padStart(2, "0"))
    .join(" ");
}

function readFormNumber(element, fallback) {
  const value = Number.parseInt(element.value, 10);
  if (Number.isNaN(value)) return fallback;
  return value;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function decodePayload(payload, method, key) {
  const decrypted = decryptBytes(payload, method, key);
  return new TextDecoder().decode(decrypted);
}

function createOutputLine(label, value) {
  return `<div class="output-line"><span>${label}</span><code>${value}</code></div>`;
}

function renderSendPanel() {
  return `
    <form class="send-form" id="send-form">
      <label>
        <span>请输入要发送的文本</span>
        <input id="message" name="message" maxlength="${MAX_DATA_LEN}" autocomplete="off" autofocus>
      </label>
      <div class="form-grid">
        <label>
          <span>选择加密方式</span>
          <select id="method" name="method">
            <option value="xor">1. XOR</option>
            <option value="caesar">2. 凯撒</option>
          </select>
        </label>
        <label>
          <span>密钥 / 偏移量 (0-255)</span>
          <input id="key" name="key" type="number" min="0" max="255" value="18">
        </label>
        <label>
          <span>是否模拟干扰</span>
          <select id="interference" name="interference">
            <option value="no">1. 否</option>
            <option value="yes">2. 是</option>
          </select>
        </label>
        <label>
          <span>干扰概率百分比</span>
          <input id="rate" name="rate" type="number" min="0" max="100" value="0">
        </label>
      </div>
      <button type="submit">发送数据</button>
    </form>
    <div class="result-block" id="send-result">
      <p class="muted">填写数据后点击发送，结果会显示在这里。</p>
    </div>
  `;
}

function renderMenuOutput(target) {
  target.innerHTML = `
    <p>===== 轻量级物联网加密通信协议 =====</p>
    <p>1. 发送数据</p>
    <p>2. 查看历史</p>
    <p>3. 协议说明</p>
    <p>4. 退出</p>
  `;
}

function renderHistory(target) {
  if (historyRecords.length === 0) {
    target.innerHTML = `<p>========== 通信历史 ==========</p><p>暂无记录。</p>`;
    return;
  }

  target.innerHTML = `
    <p>========== 通信历史 ==========</p>
    ${historyRecords
      .map(
        (record) => `
          <section class="history-item">
            <p>编号: ${record.id}</p>
            <p>原文: ${record.original}</p>
            <p>密文: ${record.encryptedHex}</p>
            <p>解密: ${record.decrypted || "未解密"}</p>
            <p>校验: ${record.checksumPassed ? "通过" : "失败"}</p>
            <p>干扰: ${record.interference ? "是" : "否"}</p>
          </section>
        `,
      )
      .join("")}
  `;
}

function renderProtocolInfo(target) {
  target.innerHTML = `
    <p>协议帧格式:</p>
    <pre>| 帧头(2B)   | 长度(1B) | 数据载荷(NB) | 校验和(1B) | 帧尾(2B)   |
| AA 55      | N        | 加密后数据   | XOR结果    | 55 AA      |</pre>
    <p>发送顺序: 原文 -> 加密 -> 计算校验和 -> 封装 -> 传输 -> 校验 -> 解密</p>
  `;
}

function handleSend(event) {
  event.preventDefault();

  const result = document.querySelector("#send-result");
  const messageInput = document.querySelector("#message");
  const methodInput = document.querySelector("#method");
  const keyInput = document.querySelector("#key");
  const interferenceInput = document.querySelector("#interference");
  const rateInput = document.querySelector("#rate");

  const message = messageInput.value;
  const bytes = new TextEncoder().encode(message);
  if (bytes.length > MAX_DATA_LEN) {
    result.innerHTML = `<p class="error">输入过长，最多 255 字节。</p>`;
    return;
  }

  const method = methodInput.value;
  const key = clamp(readFormNumber(keyInput, 0), 0, 255);
  const rate = interferenceInput.value === "yes" ? clamp(readFormNumber(rateInput, 0), 0, 100) : 0;
  keyInput.value = String(key);
  rateInput.value = String(rate);

  const encrypted = encryptBytes(bytes, method, key);
  const transmission = simulateTransmission(encrypted, rate);
  const parsed = parseFrame(transmission.receivedFrame);
  const methodName = method === "xor" ? "XOR" : "Caesar";

  let decrypted = "";
  let statusText = "";
  let checksumPassed = false;
  if (!parsed.ok) {
    statusText = parsed.error;
  } else if (!parsed.checksumPassed) {
    statusText = "校验失败: 数据可能被干扰。";
  } else {
    checksumPassed = true;
    decrypted = decodePayload(parsed.payload, method, key);
    statusText = `校验通过，解密结果: ${decrypted}`;
  }

  historyRecords.unshift({
    id: historyRecords.length + 1,
    original: message || "(空)",
    encryptedHex: frameToHex(encrypted),
    decrypted,
    checksumPassed,
    interference: transmission.changed,
  });

  result.innerHTML = `
    ${createOutputLine("加密方式:", methodName)}
    ${createOutputLine("加密载荷:", frameToHex(encrypted) || "(空)")}
    ${createOutputLine("发送帧:", frameToHex(transmission.sentFrame))}
    ${createOutputLine("接收帧:", frameToHex(transmission.receivedFrame))}
    ${createOutputLine("实际发生干扰:", transmission.changed ? "是" : "否")}
    <p class="${checksumPassed ? "success" : "error"}">${statusText}</p>
  `;
}

function initializeTerminal() {
  const output = document.querySelector("#terminal-output");
  const buttons = document.querySelectorAll("[data-action]");

  renderMenuOutput(output);

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.dataset.action;
      if (action === "send") {
        output.innerHTML = renderSendPanel();
        document.querySelector("#send-form").addEventListener("submit", handleSend);
        document.querySelector("#message").focus();
      }
      if (action === "history") renderHistory(output);
      if (action === "protocol") renderProtocolInfo(output);
      if (action === "exit") {
        historyRecords.length = 0;
        output.innerHTML = `<p>程序已退出。</p>`;
      }
    });
  });
}

if (typeof document !== "undefined") {
  initializeTerminal();
}
