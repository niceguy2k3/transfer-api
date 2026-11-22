// ============================================================
// CLOUDFLARE WORKER - MULTI-API ROUTER v2 (RESPONSES API PRO)
// Hỗ trợ: /v1/responses, /v1/chat/completions, /v1/messages, /v1/models
// ============================================================

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*"
};

const CONFIG = {
  MAX_RETRY_KEYS: 10,
  TRANSIENT_RETRIES: 2,          // Số lần retry khi gặp 429/502/503/504
  RETRY_BASE_DELAY_MS: 500,      // 500ms -> 1500ms
  CONNECT_TIMEOUT_MS: 25000,     // Timeout chờ header đầu tiên (không cắt stream đang chảy)
  MODELS_TIMEOUT_MS: 6000,
  MODELS_CACHE_TTL_MS: 60000,    // Cache danh sách /v1/models 60s trong isolate
  MIN_AVAILABLE_TOKENS: 100,
  // Các upstream chỉ hỗ trợ /v1/responses và yêu cầu chuẩn Codex
  RESPONSES_ONLY_UPSTREAMS: ["xingchiapi"],
  // Ép gửi stream=true lên upstream nhóm Responses-only rồi tự gom JSON nếu client cần non-stream
  FORCE_STREAM_ON_RESPONSES_ONLY: true,
  DEFAULT_INSTRUCTIONS: "You are a helpful coding assistant.",
  DEFAULT_CODEX_UA: "codex_cli_rs/0.104.0 (Windows 10; x86_64)",
  DEFAULT_ORIGINATOR: "codex_cli_rs"
};

const ALLOWED_CLIENT_UA_REGEX = /(codex|claude|cursor|kilo|cline|roo|opencode|trae|copilot|grok|qoder|hermes|zcode)/i;

// Cache nhẹ trong RAM của Worker isolate cho /v1/models
let modelsCache = { expiresAt: 0, payload: null };

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    let subPath = normalizeSubPath(url.pathname);

    // ---- 1. ĐỌC UPSTREAM_CONFIG ----
    const configResult = parseUpstreamConfig(env.UPSTREAM_CONFIG);
    if (configResult.error) {
      return jsonResponse({ error: { message: configResult.error, type: "config_error" } }, 500);
    }
    const upstreamConfig = configResult.data;

    // ---- 2. HEALTH / STATUS ENDPOINT (/) ----
    if (subPath === "" || subPath === "v1" || subPath === "health") {
      return jsonResponse({
        status: "online",
        version: "2.0",
        colo: request.cf?.colo || "unknown",
        country: request.cf?.country || "unknown",
        auth_protected: Boolean(env.WORKER_AUTH_KEY),
        upstreams: upstreamConfig.map(u => ({
          name: u.name,
          apiType: isResponsesOnlyUpstream(u) ? "responses" : (u.apiType || "chat"),
          keys_count: Array.isArray(u.keys) ? u.keys.length : 0
        })),
        endpoints: ["/v1/responses", "/v1/chat/completions", "/v1/messages", "/v1/models"]
      });
    }

    // ---- 3. BẢO VỆ WORKER BẰNG WORKER_AUTH_KEY (TUỲ CHỌN) ----
    const clientKey = extractClientApiKey(request);
    if (env.WORKER_AUTH_KEY) {
      const allowedAuthKeys = String(env.WORKER_AUTH_KEY)
        .split(",")
        .map(k => k.trim())
        .filter(Boolean);
      if (!clientKey || !allowedAuthKeys.includes(clientKey)) {
        return jsonResponse({
          error: { message: "Unauthorized: Invalid Worker API Key", type: "authentication_error" }
        }, 401);
      }
    }

    // ---- 4. ROUTE /v1/models (CÓ CACHE + CLEAN HEADER) ----
    if ((subPath === "models" || subPath.endsWith("/models")) && request.method === "GET") {
      const bypassCache = url.searchParams.get("refresh") === "1";
      if (!bypassCache && modelsCache.payload && Date.now() < modelsCache.expiresAt) {
        return jsonResponse(modelsCache.payload);
      }

      const fetchPromises = upstreamConfig.map(async (upstream) => {
        const keys = Array.isArray(upstream.keys) ? upstream.keys.filter(Boolean) : [];
        if (keys.length === 0) return fallbackStaticModels(upstream, upstreamConfig.length);

        const randomKey = keys[Math.floor(Math.random() * keys.length)];
        const targetModelsUrl = `${upstream.baseUrl.replace(/\/+$/, "")}/models`;
        const headers = buildCleanHeaders(request.headers, randomKey, false);

        try {
          const res = await fetchWithConnectTimeout(targetModelsUrl, {
            method: "GET",
            headers
          }, CONFIG.MODELS_TIMEOUT_MS);

          if (res.ok) {
            const rawData = await res.json();
            const rawList = Array.isArray(rawData)
              ? rawData
              : (rawData && Array.isArray(rawData.data) ? rawData.data : []);
            return rawList
              .filter(m => m && m.id)
              .map(m => {
                const baseId = String(m.id).replace(/\s*\(.*?\)/g, "").trim();
                const displayId = upstreamConfig.length > 1 ? `${baseId} (${upstream.name})` : baseId;
                return { ...m, id: displayId, owned_by: upstream.name };
              });
          }
        } catch (e) {}

        return fallbackStaticModels(upstream, upstreamConfig.length);
      });

      const results = await Promise.allSettled(fetchPromises);
      const finalModels = [];
      for (const r of results) {
        if (r.status === "fulfilled" && Array.isArray(r.value)) {
          finalModels.push(...r.value);
        }
      }

      const uniqueModels = Array.from(new Map(finalModels.map(item => [item.id, item])).values());
      const payload = { object: "list", data: uniqueModels };
      if (uniqueModels.length > 0) {
        modelsCache = { expiresAt: Date.now() + CONFIG.MODELS_CACHE_TTL_MS, payload };
      }
      return jsonResponse(payload);
    }

    // ---- 5. PHÂN LOẠI ROUTE & PARSE BODY ----
    const isNativeResponsesRoute = subPath === "responses" || subPath === "v1/responses";
    const isChatCompletionsRoute = subPath === "chat/completions" || subPath === "v1/chat/completions";
    const isAnthropicRoute = subPath === "messages" || subPath.includes("anthropic");

    const httpMethod = request.method;
    let rawBodyText = "";
    let bodyJson = null;
    let requestedModel = "";
    let realModelName = "";
    let detectedUpstreamName = "";

    if (httpMethod !== "GET" && httpMethod !== "HEAD") {
      rawBodyText = await request.text();
      if (rawBodyText) {
        try {
          bodyJson = JSON.parse(rawBodyText);
          if (bodyJson.model) {
            requestedModel = String(bodyJson.model);
            const upstreamMatch = requestedModel.match(/\((.*?)\)/);
            if (upstreamMatch && upstreamMatch[1]) {
              detectedUpstreamName = upstreamMatch[1].trim();
            }
            realModelName = requestedModel.replace(/\s*\(.*?\)/g, "").trim();
            bodyJson.model = realModelName;
          }
        } catch (e) {
          bodyJson = null;
        }
      }
    }

    // ---- 6. CHỌN UPSTREAM ----
    let activeUpstream = selectUpstream(upstreamConfig, detectedUpstreamName, realModelName);
    const isResponsesOnly = isResponsesOnlyUpstream(activeUpstream);
    const useResponsesUpstream = isNativeResponsesRoute || isResponsesOnly;

    // ---- 7. CHUẨN HOÁ & CHUYỂN ĐỔI PAYLOAD ----
    let targetSubPath = subPath;
    let clientStreamRequested = Boolean(bodyJson && bodyJson.stream);
    let upstreamStreamForced = false;
    let responseMode = "passthrough"; // passthrough | responses_to_chat | responses_to_anthropic | chat_to_anthropic | responses_sse_to_json
    let outgoingPayloadObj = null;
    let outgoingBodyText = rawBodyText;

    if (bodyJson && httpMethod === "POST") {
      if (isNativeResponsesRoute) {
        targetSubPath = "responses";
        outgoingPayloadObj = normalizeNativeResponsesPayload(bodyJson, isResponsesOnly);
        if (isResponsesOnly && CONFIG.FORCE_STREAM_ON_RESPONSES_ONLY && !clientStreamRequested) {
          outgoingPayloadObj.stream = true;
          upstreamStreamForced = true;
          responseMode = "responses_sse_to_json";
        }
      } else if (isChatCompletionsRoute && useResponsesUpstream) {
        targetSubPath = "responses";
        responseMode = "responses_to_chat";
        outgoingPayloadObj = convertChatToResponsesPayload(bodyJson, isResponsesOnly);
        if (isResponsesOnly && CONFIG.FORCE_STREAM_ON_RESPONSES_ONLY && !clientStreamRequested) {
          outgoingPayloadObj.stream = true;
          upstreamStreamForced = true;
        }
      } else if (isAnthropicRoute && useResponsesUpstream) {
        targetSubPath = "responses";
        responseMode = "responses_to_anthropic";
        clientStreamRequested = bodyJson.stream !== undefined ? Boolean(bodyJson.stream) : false;
        const shouldStreamUpstream = clientStreamRequested || (isResponsesOnly && CONFIG.FORCE_STREAM_ON_RESPONSES_ONLY);
        upstreamStreamForced = !clientStreamRequested && shouldStreamUpstream;
        outgoingPayloadObj = convertAnthropicToResponsesPayload(bodyJson, shouldStreamUpstream, isResponsesOnly);
      } else if (isAnthropicRoute) {
        targetSubPath = "chat/completions";
        responseMode = "chat_to_anthropic";
        clientStreamRequested = bodyJson.stream !== undefined ? Boolean(bodyJson.stream) : false;
        outgoingPayloadObj = convertAnthropicToOpenAIPayload(bodyJson, clientStreamRequested);
      } else {
        outgoingPayloadObj = bodyJson;
      }

      if (outgoingPayloadObj) {
        outgoingBodyText = JSON.stringify(outgoingPayloadObj);
      }
    }

    // ---- 8. CHUẨN BỊ DANH SÁCH KEY (XOAY VÒNG NGẪU NHIÊN) ----
    const baseUrlClean = activeUpstream.baseUrl.replace(/\/+$/, "");
    const targetUrl = `${baseUrlClean}/${targetSubPath}${url.search}`;

    let candidateKeys = Array.isArray(activeUpstream.keys) ? activeUpstream.keys.filter(Boolean) : [];
    // Chỉ dùng clientKey nếu upstream không cấu hình key sẵn VÀ không bật WORKER_AUTH_KEY
    if (candidateKeys.length === 0 && clientKey && !env.WORKER_AUTH_KEY) {
      candidateKeys = [clientKey];
    }

    if (candidateKeys.length === 0) {
      return jsonResponse({
        error: { message: `Upstream '${activeUpstream.name}' chưa có API key!`, type: "config_error" }
      }, 500);
    }

    candidateKeys = rotateFromRandomStart(candidateKeys).slice(0, CONFIG.MAX_RETRY_KEYS);

    // ---- 9. GỬI REQUEST + FAILOVER + RETRY BACKOFF ----
    const bodyBuffer = outgoingBodyText ? new TextEncoder().encode(outgoingBodyText) : null;
    const { response, lastErrorResponse } = await executeWithFailoverAndRetry({
      targetUrl,
      method: httpMethod,
      incomingHeaders: request.headers,
      bodyBuffer,
      candidateKeys,
      upstreamName: activeUpstream.name
    });

    if (!response) {
      if (lastErrorResponse) {
        const errHeaders = new Headers(lastErrorResponse.headers);
        applyCors(errHeaders);
        return new Response(lastErrorResponse.body, {
          status: lastErrorResponse.status,
          headers: errHeaders
        });
      }
      return jsonResponse({
        error: {
          message: `Không thể kết nối tới '${activeUpstream.name}' cho model '${realModelName}'.`,
          type: "upstream_error"
        }
      }, 502);
    }

    const resContentType = (response.headers.get("content-type") || "").toLowerCase();
    const isEventStream = resContentType.includes("text/event-stream");
    const includeUsage = Boolean(bodyJson?.stream_options?.include_usage);

    // ---- 10. TRẢ KẾT QUẢ THEO ĐÚNG ĐỊNH DẠNG CLIENT ----

    // 10A. Client gọi /v1/responses với stream=false nhưng upstream bị ép stream=true
    if (responseMode === "responses_sse_to_json") {
      if (isEventStream) {
        const assembled = await collectResponsesFromSSE(response, realModelName);
        return jsonResponse(assembled, 200);
      }
      return passthroughResponse(response, false);
    }

    // 10B. Client gọi /v1/chat/completions -> dịch ngược từ /v1/responses
    if (responseMode === "responses_to_chat") {
      if (clientStreamRequested && isEventStream) {
        return streamResponsesToChatCompletions(response, realModelName, includeUsage);
      }
      const respObj = isEventStream
        ? await collectResponsesFromSSE(response, realModelName)
        : await response.json();
      return jsonResponse(convertResponsesJsonToChatCompletion(respObj, realModelName), response.status);
    }

    // 10C. Client gọi Claude Code (/v1/messages) -> dịch ngược từ /v1/responses
    if (responseMode === "responses_to_anthropic") {
      if (clientStreamRequested && isEventStream) {
        return streamResponsesToAnthropic(response, realModelName);
      }
      const respObj = isEventStream
        ? await collectResponsesFromSSE(response, realModelName)
        : await response.json();
      return jsonResponse(convertResponsesJsonToAnthropic(respObj, realModelName), response.status);
    }

    // 10D. Client gọi /v1/messages trên upstream OpenAI /v1/chat/completions thường
    if (responseMode === "chat_to_anthropic") {
      if (clientStreamRequested && isEventStream) {
        return streamChatCompletionsToAnthropic(response, realModelName);
      }
      const chatObj = await response.json();
      return jsonResponse(convertChatJsonToAnthropic(chatObj, realModelName), response.status);
    }

    // 10E. Passthrough nguyên bản (Codex CLI /v1/responses...)
    return passthroughResponse(response, isEventStream);
  }
};

// ============================================================
// CORE: FAILOVER, RETRY & TIMEOUT
// ============================================================

async function executeWithFailoverAndRetry({ targetUrl, method, incomingHeaders, bodyBuffer, candidateKeys, upstreamName }) {
  let lastErrorResponse = null;
  const maxAttempts = Math.max(candidateKeys.length, CONFIG.TRANSIENT_RETRIES + 1);
  let transientCount = 0;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const apiKey = candidateKeys[attempt % candidateKeys.length];
    const upstreamHeaders = buildCleanHeaders(incomingHeaders, apiKey, bodyBuffer !== null);

    try {
      const res = await fetchWithConnectTimeout(targetUrl, {
        method,
        headers: upstreamHeaders,
        body: bodyBuffer,
        redirect: "follow"
      }, CONFIG.CONNECT_TIMEOUT_MS);

      if (res.ok) {
        const ct = (res.headers.get("content-type") || "").toLowerCase();
        let shouldSkipKey = false;

        if (ct.includes("application/json")) {
          try {
            const clonedText = await res.clone().text();
            if (clonedText.startsWith("{")) {
              const data = JSON.parse(clonedText);
              if (data.availableTokens !== undefined && data.availableTokens < CONFIG.MIN_AVAILABLE_TOKENS) {
                shouldSkipKey = true;
                lastErrorResponse = res;
              }
              const errCode = typeof data.error === "string" ? data.error : data.error?.code;
              if (errCode === "insufficient_quota" || errCode === "QUOTA_EXCEEDED") {
                shouldSkipKey = true;
                lastErrorResponse = res;
              }
            }
          } catch (e) {}
        }

        if (!shouldSkipKey) {
          return { response: res, lastErrorResponse };
        }
        continue;
      }

      lastErrorResponse = res;

      // Lỗi do payload sai hoặc model không tồn tại -> dừng ngay, không retry vô ích
      if (res.status === 400 || res.status === 404 || res.status === 422) {
        break;
      }

      // Lỗi auth/key -> nếu chỉ có 1 key thì dừng luôn, nếu nhiều key thì đổi key ngay
      if (res.status === 401 || res.status === 403) {
        if (attempt + 1 >= candidateKeys.length) break;
        continue;
      }

      // Lỗi tạm thời (408, 429, 500, 502, 503, 504) -> đổi key hoặc chờ backoff rồi thử lại
      if ([408, 429, 500, 502, 503, 504].includes(res.status)) {
        transientCount++;
        if (transientCount > CONFIG.TRANSIENT_RETRIES && attempt + 1 >= candidateKeys.length) {
          break;
        }
        // Nếu đã quay vòng về cùng 1 key thì mới delay backoff
        if (attempt + 1 >= candidateKeys.length) {
          const delay = CONFIG.RETRY_BASE_DELAY_MS * Math.pow(3, transientCount - 1) + Math.floor(Math.random() * 200);
          await sleep(Math.min(delay, 4000));
        }
        continue;
      }

      break;
    } catch (err) {
      console.error(`[Failover:${upstreamName}] attempt ${attempt + 1} error:`, err?.message || err);
      transientCount++;
      if (transientCount > CONFIG.TRANSIENT_RETRIES && attempt + 1 >= candidateKeys.length) {
        break;
      }
      await sleep(CONFIG.RETRY_BASE_DELAY_MS * transientCount);
    }
  }

  return { response: null, lastErrorResponse };
}

async function fetchWithConnectTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("Connect timeout")), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer); // Header đã về -> giữ nguyên stream không bị cắt ngang
    return res;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// ============================================================
// HELPERS: ROUTING, HEADERS & CONFIG
// ============================================================

function normalizeSubPath(pathname) {
  let p = pathname || "/";
  if (p.startsWith("/api/")) p = p.slice(4);
  if (p.startsWith("/v1/")) p = p.slice(3);
  if (p.startsWith("/")) p = p.slice(1);
  return p.replace(/\/+$/, "");
}

function parseUpstreamConfig(envConfig) {
  if (!envConfig) {
    return { error: "Chưa cấu hình biến UPSTREAM_CONFIG ngoài Cloudflare Dashboard!" };
  }
  try {
    const cleanJsonStr = envConfig.replace(/[\u201C\u201D]/g, '"').trim();
    const parsed = JSON.parse(cleanJsonStr);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      return { error: "UPSTREAM_CONFIG phải là mảng JSON không rỗng!" };
    }
    return { data: parsed };
  } catch (e) {
    return { error: "Lỗi cú pháp JSON trong biến UPSTREAM_CONFIG!" };
  }
}

function isResponsesOnlyUpstream(upstream) {
  if (!upstream) return false;
  return (
    upstream.apiType === "responses" ||
    CONFIG.RESPONSES_ONLY_UPSTREAMS.includes(String(upstream.name || "").toLowerCase())
  );
}

function selectUpstream(upstreamConfig, detectedName, realModelName) {
  if (detectedName) {
    const found = upstreamConfig.find(u => String(u.name || "").toLowerCase() === detectedName.toLowerCase());
    if (found) return found;
  }
  if (realModelName) {
    const byModel = upstreamConfig.find(u =>
      Array.isArray(u.models) && u.models.some(m => String(m).toLowerCase() === realModelName.toLowerCase())
    );
    if (byModel) return byModel;
  }
  return upstreamConfig[0];
}

function fallbackStaticModels(upstream, totalUpstreams) {
  if (!Array.isArray(upstream.models) || upstream.models.length === 0) return [];
  return upstream.models.map(id => ({
    id: totalUpstreams > 1 ? `${id} (${upstream.name})` : id,
    object: "model",
    owned_by: upstream.name
  }));
}

function buildCleanHeaders(incomingHeaders, apiKey, hasBody = true) {
  const headers = new Headers();
  const skip = new Set([
    "host",
    "authorization",
    "x-api-key",
    "anthropic-api-key",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "cf-ew-via",
    "cdn-loop",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "content-length",
    "accept-encoding",
    "connection"
  ]);

  for (const [key, value] of incomingHeaders.entries()) {
    if (!skip.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  }

  const ua = headers.get("User-Agent") || "";
  if (!ALLOWED_CLIENT_UA_REGEX.test(ua)) {
    headers.set("User-Agent", CONFIG.DEFAULT_CODEX_UA);
    if (!headers.has("originator")) {
      headers.set("originator", CONFIG.DEFAULT_ORIGINATOR);
    }
  }

  headers.set("Authorization", `Bearer ${apiKey}`);
  headers.set("Accept-Encoding", "identity");
  if (hasBody && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return headers;
}

function passthroughResponse(response, isEventStream) {
  const outHeaders = new Headers(response.headers);
  applyCors(outHeaders);
  if (isEventStream) {
    outHeaders.set("Cache-Control", "no-cache, no-transform");
    outHeaders.set("Connection", "keep-alive");
  }
  return new Response(response.body, { status: response.status, headers: outHeaders });
}

function applyCors(headers) {
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    headers.set(k, v);
  }
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS }
  });
}

function extractClientApiKey(request) {
  const auth = request.headers.get("authorization") || "";
  if (/^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, "").trim();
  const xKey = request.headers.get("x-api-key") || request.headers.get("anthropic-api-key");
  return xKey ? xKey.trim() : "";
}

function rotateFromRandomStart(arr) {
  if (arr.length <= 1) return [...arr];
  const offset = Math.floor(Math.random() * arr.length);
  return [...arr.slice(offset), ...arr.slice(0, offset)];
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// REQUEST CONVERTERS -> /v1/responses
// ============================================================

function normalizeNativeResponsesPayload(body, strictCodex) {
  const payload = { ...body };
  if (strictCodex) {
    if (payload.store === undefined) payload.store = false;
    if (!payload.instructions) payload.instructions = CONFIG.DEFAULT_INSTRUCTIONS;
    if (typeof payload.input === "string") {
      payload.input = [
        {
          type: "message",
          role: "user",
          content: [{ type: "input_text", text: payload.input }]
        }
      ];
    }
  }
  return payload;
}

function convertChatToResponsesPayload(chat, strictCodex) {
  const instructionsParts = [];
  const input = [];

  for (const msg of chat.messages || []) {
    if (msg.role === "system" || msg.role === "developer") {
      const text = extractPlainText(msg.content);
      if (text) instructionsParts.push(text);
      continue;
    }

    if (msg.role === "tool") {
      input.push({
        type: "function_call_output",
        call_id: msg.tool_call_id || `call_${Math.random().toString(36).slice(2, 10)}`,
        output: typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content ?? "")
      });
      continue;
    }

    if (msg.role === "assistant") {
      const text = extractPlainText(msg.content);
      if (text) {
        input.push({
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text }]
        });
      }
      if (Array.isArray(msg.tool_calls)) {
        for (const tc of msg.tool_calls) {
          input.push({
            type: "function_call",
            call_id: tc.id || `call_${Math.random().toString(36).slice(2, 10)}`,
            name: tc.function?.name || tc.name || "",
            arguments: typeof tc.function?.arguments === "string"
              ? tc.function.arguments
              : JSON.stringify(tc.function?.arguments || {})
          });
        }
      }
      continue;
    }

    // role === "user"
    if (Array.isArray(msg.content)) {
      const parts = msg.content.map(part => {
        if (part.type === "text") return { type: "input_text", text: part.text || "" };
        if (part.type === "image_url") {
          return {
            type: "input_image",
            image_url: typeof part.image_url === "string" ? part.image_url : part.image_url?.url
          };
        }
        return { type: "input_text", text: JSON.stringify(part) };
      });
      input.push({ type: "message", role: "user", content: parts });
    } else {
      input.push({
        type: "message",
        role: "user",
        content: [{ type: "input_text", text: String(msg.content ?? "") }]
      });
    }
  }

  const payload = {
    model: chat.model,
    input: input.length > 0 ? input : [{ type: "message", role: "user", content: [{ type: "input_text", text: "" }] }],
    stream: Boolean(chat.stream)
  };

  if (strictCodex) {
    payload.store = false;
    payload.instructions = instructionsParts.length > 0 ? instructionsParts.join("\n\n") : CONFIG.DEFAULT_INSTRUCTIONS;
  } else if (instructionsParts.length > 0) {
    payload.instructions = instructionsParts.join("\n\n");
  }

  if (chat.temperature !== undefined) payload.temperature = chat.temperature;
  if (chat.top_p !== undefined) payload.top_p = chat.top_p;

  const maxOut = chat.max_completion_tokens ?? chat.max_tokens;
  if (maxOut !== undefined && maxOut !== null) {
    payload.max_output_tokens = maxOut;
  }

  if (Array.isArray(chat.tools) && chat.tools.length > 0) {
    payload.tools = chat.tools.map(t => {
      if (t.type === "function" && t.function) {
        return {
          type: "function",
          name: t.function.name,
          description: t.function.description,
          parameters: t.function.parameters
        };
      }
      return t;
    });
  }

  if (chat.tool_choice !== undefined) {
    if (typeof chat.tool_choice === "object" && chat.tool_choice?.type === "function" && chat.tool_choice?.function?.name) {
      payload.tool_choice = { type: "function", name: chat.tool_choice.function.name };
    } else {
      payload.tool_choice = chat.tool_choice;
    }
  }

  if (chat.reasoning !== undefined) payload.reasoning = chat.reasoning;
  if (chat.reasoning_effort !== undefined && !payload.reasoning) {
    payload.reasoning = { effort: chat.reasoning_effort };
  }

  return payload;
}

function convertAnthropicToResponsesPayload(anth, stream, strictCodex) {
  const input = [];

  for (const msg of anth.messages || []) {
    const role = msg.role === "assistant" ? "assistant" : "user";

    if (typeof msg.content === "string") {
      input.push({
        type: "message",
        role,
        content: [{ type: role === "assistant" ? "output_text" : "input_text", text: msg.content }]
      });
      continue;
    }

    if (Array.isArray(msg.content)) {
      const contentParts = [];
      const flushParts = () => {
        if (contentParts.length > 0) {
          input.push({ type: "message", role, content: [...contentParts] });
          contentParts.length = 0;
        }
      };

      for (const block of msg.content) {
        if (block.type === "text" && block.text) {
          contentParts.push({ type: role === "assistant" ? "output_text" : "input_text", text: block.text });
        } else if (block.type === "image" && block.source?.type === "base64") {
          contentParts.push({
            type: "input_image",
            image_url: `data:${block.source.media_type || "image/png"};base64,${block.source.data}`
          });
        } else if (block.type === "tool_use") {
          flushParts();
          input.push({
            type: "function_call",
            call_id: block.id || `call_${Math.random().toString(36).slice(2, 10)}`,
            name: block.name || "",
            arguments: typeof block.input === "string" ? block.input : JSON.stringify(block.input || {})
          });
        } else if (block.type === "tool_result") {
          flushParts();
          input.push({
            type: "function_call_output",
            call_id: block.tool_use_id || `call_${Math.random().toString(36).slice(2, 10)}`,
            output: extractPlainText(block.content)
          });
        }
      }
      flushParts();
    }
  }

  const payload = {
    model: anth.model,
    input: input.length > 0 ? input : [{ type: "message", role: "user", content: [{ type: "input_text", text: "" }] }],
    stream: Boolean(stream)
  };

  const sysText = extractPlainText(anth.system);
  if (strictCodex) {
    payload.store = false;
    payload.instructions = sysText || CONFIG.DEFAULT_INSTRUCTIONS;
  } else if (sysText) {
    payload.instructions = sysText;
  }

  if (anth.temperature !== undefined) payload.temperature = anth.temperature;
  if (anth.max_tokens !== undefined) payload.max_output_tokens = anth.max_tokens;

  if (Array.isArray(anth.tools) && anth.tools.length > 0) {
    payload.tools = anth.tools.map(t => ({
      type: "function",
      name: t.name,
      description: t.description || "",
      parameters: t.input_schema || { type: "object", properties: {} }
    }));
  }

  if (anth.tool_choice) {
    if (anth.tool_choice.type === "auto") payload.tool_choice = "auto";
    else if (anth.tool_choice.type === "any") payload.tool_choice = "required";
    else if (anth.tool_choice.type === "tool" && anth.tool_choice.name) {
      payload.tool_choice = { type: "function", name: anth.tool_choice.name };
    }
  }

  return payload;
}

function convertAnthropicToOpenAIPayload(anth, stream) {
  const messages = [];
  const sysText = extractPlainText(anth.system);
  if (sysText) messages.push({ role: "system", content: sysText });

  for (const msg of anth.messages || []) {
    if (typeof msg.content === "string") {
      messages.push({ role: msg.role, content: msg.content });
      continue;
    }
    if (Array.isArray(msg.content)) {
      const textParts = [];
      const toolCalls = [];
      const toolResults = [];

      for (const block of msg.content) {
        if (block.type === "text" && block.text) textParts.push(block.text);
        else if (block.type === "tool_use") {
          toolCalls.push({
            id: block.id,
            type: "function",
            function: { name: block.name, arguments: JSON.stringify(block.input || {}) }
          });
        } else if (block.type === "tool_result") {
          toolResults.push({
            role: "tool",
            tool_call_id: block.tool_use_id,
            content: extractPlainText(block.content)
          });
        }
      }

      if (textParts.length > 0 || toolCalls.length > 0) {
        const m = { role: msg.role, content: textParts.join("\n") || null };
        if (toolCalls.length > 0) m.tool_calls = toolCalls;
        messages.push(m);
      }
      messages.push(...toolResults);
    }
  }

  const payload = {
    model: anth.model,
    messages,
    stream: Boolean(stream)
  };
  if (anth.temperature !== undefined) payload.temperature = anth.temperature;
  if (anth.max_tokens !== undefined) payload.max_tokens = anth.max_tokens;
  if (Array.isArray(anth.tools) && anth.tools.length > 0) {
    payload.tools = anth.tools.map(t => ({
      type: "function",
      function: { name: t.name, description: t.description || "", parameters: t.input_schema || {} }
    }));
  }
  return payload;
}

function extractPlainText(content) {
  if (content === null || content === undefined) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map(c => (typeof c === "string" ? c : (c?.text ?? (typeof c?.content === "string" ? c.content : ""))))
      .filter(Boolean)
      .join("\n");
  }
  return String(content);
}

// ============================================================
// SSE COLLECTOR (GOM /v1/responses STREAM -> JSON KHI CLIENT CẦN NON-STREAM)
// ============================================================

async function collectResponsesFromSSE(response, fallbackModel) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let completedResponse = null;
  let accumulatedText = "";
  let model = fallbackModel;
  const callsById = new Map();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line.startsWith("data:")) continue;
      const dataStr = line.slice(5).trim();
      if (!dataStr || dataStr === "[DONE]") continue;

      let evt;
      try {
        evt = JSON.parse(dataStr);
      } catch (e) {
        continue;
      }

      if (evt.response?.model) model = evt.response.model;
      if (evt.type === "response.completed" && evt.response) {
        completedResponse = evt.response;
      } else if (evt.type === "response.output_text.delta" && evt.delta) {
        accumulatedText += evt.delta;
      } else if (evt.type === "response.output_item.added" && evt.item?.type === "function_call") {
        callsById.set(evt.item.id || evt.item.call_id, {
          type: "function_call",
          id: evt.item.id,
          call_id: evt.item.call_id || evt.item.id,
          name: evt.item.name || "",
          arguments: evt.item.arguments || ""
        });
      } else if (evt.type === "response.function_call_arguments.delta" && evt.delta) {
        const entry = callsById.get(evt.item_id);
        if (entry) entry.arguments += evt.delta;
      } else if (evt.type === "response.output_item.done" && evt.item?.type === "function_call") {
        callsById.set(evt.item.id || evt.item.call_id, evt.item);
      }
    }
  }

  if (completedResponse) return completedResponse;

  const output = [];
  if (accumulatedText) {
    output.push({
      type: "message",
      role: "assistant",
      content: [{ type: "output_text", text: accumulatedText }]
    });
  }
  for (const call of callsById.values()) output.push(call);

  return {
    id: `resp_${Date.now()}`,
    object: "response",
    created_at: Math.floor(Date.now() / 1000),
    status: "completed",
    model,
    output_text: accumulatedText,
    output,
    usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 }
  };
}

// ============================================================
// RESPONSE CONVERTERS: /v1/responses -> CHAT COMPLETIONS
// ============================================================

function convertResponsesJsonToChatCompletion(data, fallbackModel) {
  let contentText = typeof data.output_text === "string" ? data.output_text : "";
  const toolCalls = [];

  if (Array.isArray(data.output)) {
    const textParts = [];
    for (const item of data.output) {
      if (item.type === "message" && Array.isArray(item.content)) {
        for (const c of item.content) {
          if (c.type === "output_text" || c.type === "text") textParts.push(c.text || "");
        }
      } else if (item.type === "function_call") {
        toolCalls.push({
          id: item.call_id || item.id || `call_${toolCalls.length}`,
          type: "function",
          function: {
            name: item.name || "",
            arguments: typeof item.arguments === "string" ? item.arguments : JSON.stringify(item.arguments || {})
          }
        });
      }
    }
    if (!contentText && textParts.length > 0) contentText = textParts.join("");
  }

  const message = { role: "assistant", content: contentText || (toolCalls.length ? null : "") };
  if (toolCalls.length > 0) message.tool_calls = toolCalls;

  return {
    id: data.id || `chatcmpl_${Date.now()}`,
    object: "chat.completion",
    created: data.created_at || Math.floor(Date.now() / 1000),
    model: data.model || fallbackModel,
    choices: [{ index: 0, message, finish_reason: toolCalls.length > 0 ? "tool_calls" : "stop" }],
    usage: {
      prompt_tokens: data.usage?.input_tokens || 0,
      completion_tokens: data.usage?.output_tokens || 0,
      total_tokens: data.usage?.total_tokens || 0
    }
  };
}

function streamResponsesToChatCompletions(response, fallbackModel, includeUsage = false) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  (async () => {
    const chatId = `chatcmpl_${Date.now()}`;
    const created = Math.floor(Date.now() / 1000);
    let model = fallbackModel;
    let buffer = "";
    let hasToolCall = false;
    let sentFinish = false;
    let finalUsage = null;
    const toolIndexByItemId = new Map();
    let nextToolIndex = 0;

    const sendChunk = async (delta, finishReason = null, usage = null) => {
      const chunk = {
        id: chatId,
        object: "chat.completion.chunk",
        created,
        model,
        choices: delta !== null ? [{ index: 0, delta, finish_reason: finishReason }] : []
      };
      if (usage) chunk.usage = usage;
      await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
    };

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith("data:")) continue;
          const dataStr = line.slice(5).trim();
          if (!dataStr || dataStr === "[DONE]") continue;

          let evt;
          try {
            evt = JSON.parse(dataStr);
          } catch (e) {
            continue;
          }

          if (evt.response?.model) model = evt.response.model;

          if (evt.type === "response.output_text.delta" && evt.delta) {
            await sendChunk({ content: evt.delta });
          } else if (evt.type === "response.reasoning_summary_text.delta" && evt.delta) {
            await sendChunk({ reasoning_content: evt.delta });
          } else if (evt.type === "response.output_item.added" && evt.item?.type === "function_call") {
            hasToolCall = true;
            const idx = nextToolIndex++;
            toolIndexByItemId.set(evt.item.id || evt.item.call_id, idx);
            await sendChunk({
              tool_calls: [{
                index: idx,
                id: evt.item.call_id || evt.item.id,
                type: "function",
                function: { name: evt.item.name || "", arguments: "" }
              }]
            });
          } else if (evt.type === "response.function_call_arguments.delta" && evt.delta) {
            const idx = toolIndexByItemId.get(evt.item_id) ?? 0;
            await sendChunk({
              tool_calls: [{ index: idx, function: { arguments: evt.delta } }]
            });
          } else if (evt.type === "response.completed" || evt.type === "response.incomplete") {
            if (evt.response?.usage) {
              finalUsage = {
                prompt_tokens: evt.response.usage.input_tokens || 0,
                completion_tokens: evt.response.usage.output_tokens || 0,
                total_tokens: evt.response.usage.total_tokens || 0
              };
            }
            sentFinish = true;
            await sendChunk({}, hasToolCall ? "tool_calls" : "stop");
          } else if (evt.type === "response.failed" || evt.type === "error") {
            const msg = evt.response?.error?.message || evt.error?.message || "Upstream response failed";
            await sendChunk({ content: `\n[Error: ${msg}]` }, "stop");
            sentFinish = true;
          }
        }
      }

      if (!sentFinish) {
        await sendChunk({}, hasToolCall ? "tool_calls" : "stop");
      }
      if (includeUsage && finalUsage) {
        await sendChunk(null, null, finalUsage);
      }
      await writer.write(encoder.encode("data: [DONE]\n\n"));
    } catch (e) {
      console.error("Responses -> Chat stream error:", e);
    } finally {
      await writer.close();
    }
  })();

  const headers = new Headers();
  applyCors(headers);
  headers.set("Content-Type", "text/event-stream; charset=utf-8");
  headers.set("Cache-Control", "no-cache, no-transform");
  headers.set("Connection", "keep-alive");

  return new Response(readable, { status: 200, headers });
}

// ============================================================
// RESPONSE CONVERTERS: /v1/responses & /v1/chat -> ANTHROPIC
// ============================================================

function convertResponsesJsonToAnthropic(data, fallbackModel) {
  const content = [];
  let hasToolUse = false;

  if (Array.isArray(data.output)) {
    for (const item of data.output) {
      if (item.type === "message" && Array.isArray(item.content)) {
        for (const c of item.content) {
          if ((c.type === "output_text" || c.type === "text") && c.text) {
            content.push({ type: "text", text: c.text });
          }
        }
      } else if (item.type === "function_call") {
        hasToolUse = true;
        let parsedInput = {};
        try {
          parsedInput = typeof item.arguments === "string" ? JSON.parse(item.arguments || "{}") : (item.arguments || {});
        } catch (e) {}
        content.push({
          type: "tool_use",
          id: item.call_id || item.id || `toolu_${Date.now()}`,
          name: item.name || "",
          input: parsedInput
        });
      }
    }
  }

  if (content.length === 0 && typeof data.output_text === "string" && data.output_text) {
    content.push({ type: "text", text: data.output_text });
  }
  if (content.length === 0) content.push({ type: "text", text: "" });

  return {
    id: data.id || `msg_${Date.now()}`,
    type: "message",
    role: "assistant",
    model: data.model || fallbackModel,
    content,
    stop_reason: hasToolUse ? "tool_use" : "end_turn",
    stop_sequence: null,
    usage: {
      input_tokens: data.usage?.input_tokens || 0,
      output_tokens: data.usage?.output_tokens || 0
    }
  };
}

function streamResponsesToAnthropic(response, fallbackModel) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  (async () => {
    const msgId = `msg_${Date.now()}`;
    let buffer = "";
    let currentBlockIndex = -1;
    let currentBlockType = null;
    let hasToolUse = false;
    let outputTokens = 0;

    const emit = async (event, data) => {
      await writer.write(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
    };

    const closeCurrentBlock = async () => {
      if (currentBlockIndex >= 0 && currentBlockType !== null) {
        await emit("content_block_stop", { type: "content_block_stop", index: currentBlockIndex });
        currentBlockType = null;
      }
    };

    try {
      await emit("message_start", {
        type: "message_start",
        message: {
          id: msgId,
          type: "message",
          role: "assistant",
          content: [],
          model: fallbackModel,
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 0, output_tokens: 0 }
        }
      });

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith("data:")) continue;
          const dataStr = line.slice(5).trim();
          if (!dataStr || dataStr === "[DONE]") continue;

          let evt;
          try {
            evt = JSON.parse(dataStr);
          } catch (e) {
            continue;
          }

          if (evt.type === "response.output_text.delta" && evt.delta) {
            if (currentBlockType !== "text") {
              await closeCurrentBlock();
              currentBlockIndex++;
              currentBlockType = "text";
              await emit("content_block_start", {
                type: "content_block_start",
                index: currentBlockIndex,
                content_block: { type: "text", text: "" }
              });
            }
            await emit("content_block_delta", {
              type: "content_block_delta",
              index: currentBlockIndex,
              delta: { type: "text_delta", text: evt.delta }
            });
          } else if (evt.type === "response.output_item.added" && evt.item?.type === "function_call") {
            hasToolUse = true;
            await closeCurrentBlock();
            currentBlockIndex++;
            currentBlockType = "tool_use";
            await emit("content_block_start", {
              type: "content_block_start",
              index: currentBlockIndex,
              content_block: {
                type: "tool_use",
                id: evt.item.call_id || evt.item.id || `toolu_${Date.now()}`,
                name: evt.item.name || "",
                input: {}
              }
            });
          } else if (evt.type === "response.function_call_arguments.delta" && evt.delta && currentBlockType === "tool_use") {
            await emit("content_block_delta", {
              type: "content_block_delta",
              index: currentBlockIndex,
              delta: { type: "input_json_delta", partial_json: evt.delta }
            });
          } else if (evt.type === "response.output_item.done" && evt.item?.type === "function_call") {
            await closeCurrentBlock();
          } else if (evt.type === "response.completed") {
            outputTokens = evt.response?.usage?.output_tokens || 0;
          }
        }
      }

      if (currentBlockIndex < 0) {
        currentBlockIndex = 0;
        currentBlockType = "text";
        await emit("content_block_start", {
          type: "content_block_start",
          index: 0,
          content_block: { type: "text", text: "" }
        });
        await emit("content_block_delta", {
          type: "content_block_delta",
          index: 0,
          delta: { type: "text_delta", text: " " }
        });
      }

      await closeCurrentBlock();
      await emit("message_delta", {
        type: "message_delta",
        delta: { stop_reason: hasToolUse ? "tool_use" : "end_turn", stop_sequence: null },
        usage: { output_tokens: outputTokens }
      });
      await emit("message_stop", { type: "message_stop" });
    } catch (e) {
      console.error("Responses -> Anthropic stream error:", e);
    } finally {
      await writer.close();
    }
  })();

  const headers = new Headers();
  applyCors(headers);
  headers.set("Content-Type", "text/event-stream; charset=utf-8");
  headers.set("Cache-Control", "no-cache, no-transform");

  return new Response(readable, { status: 200, headers });
}

function convertChatJsonToAnthropic(chat, fallbackModel) {
  const msg = chat.choices?.[0]?.message || {};
  const content = [];
  if (msg.content) content.push({ type: "text", text: msg.content });
  if (Array.isArray(msg.tool_calls)) {
    for (const tc of msg.tool_calls) {
      let input = {};
      try { input = JSON.parse(tc.function?.arguments || "{}"); } catch (e) {}
      content.push({ type: "tool_use", id: tc.id, name: tc.function?.name || "", input });
    }
  }
  if (content.length === 0) content.push({ type: "text", text: "" });
  return {
    id: chat.id || `msg_${Date.now()}`,
    type: "message",
    role: "assistant",
    model: chat.model || fallbackModel,
    content,
    stop_reason: msg.tool_calls?.length ? "tool_use" : "end_turn",
    stop_sequence: null,
    usage: {
      input_tokens: chat.usage?.prompt_tokens || 0,
      output_tokens: chat.usage?.completion_tokens || 0
    }
  };
}

function streamChatCompletionsToAnthropic(response, fallbackModel) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  (async () => {
    const emit = async (event, data) => {
      await writer.write(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
    };
    let buffer = "";
    try {
      await emit("message_start", {
        type: "message_start",
        message: { id: `msg_${Date.now()}`, type: "message", role: "assistant", content: [], model: fallbackModel, stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } }
      });
      await emit("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith("data:")) continue;
          const dataStr = line.slice(5).trim();
          if (!dataStr || dataStr === "[DONE]") continue;
          try {
            const parsed = JSON.parse(dataStr);
            const delta = parsed.choices?.[0]?.delta?.content;
            if (delta) {
              await emit("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: delta } });
            }
          } catch (e) {}
        }
      }

      await emit("content_block_stop", { type: "content_block_stop", index: 0 });
      await emit("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 0 } });
      await emit("message_stop", { type: "message_stop" });
    } catch (e) {
    } finally {
      await writer.close();
    }
  })();

  const headers = new Headers();
  applyCors(headers);
  headers.set("Content-Type", "text/event-stream; charset=utf-8");
  headers.set("Cache-Control", "no-cache, no-transform");
  return new Response(readable, { status: 200, headers });
}
