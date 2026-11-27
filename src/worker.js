// ============================================================================
// Cloudflare Worker AI Gateway v3.0
// - Full Protocol Translation: OpenAI Responses <-> Chat Completions <-> Anthropic Messages
// - Smart Key Health, Circuit Breaker & EWMA TTFB (Global via Durable Object)
// - First-Chunk SSE Peek (Fake 200 OK error detection & seamless failover)
// - Sticky Key Routing (Prompt Caching affinity)
// - Cross-Upstream Failover & Model Aliasing
// - Auto-Sanitize Payload & Thinking/Reasoning Bidirectional Mapping
// - Stream Cancellation (no leaked tokens on client Stop), Idle Timeout & Heartbeat
// - Virtual Keys with RPM Limiting + Built-in /admin Dashboard
// ============================================================================

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*"
};

const CONFIG = {
  VERSION: "3.0.0",
  MAX_RETRY_KEYS_PER_UPSTREAM: 6,
  TRANSIENT_RETRIES: 2,
  RETRY_BASE_DELAY_MS: 400,
  CONNECT_TIMEOUT_MS: 25000,
  FIRST_CHUNK_TIMEOUT_MS: 30000,
  STREAM_IDLE_TIMEOUT_MS: 45000,
  HEARTBEAT_INTERVAL_MS: 15000,
  MODELS_TIMEOUT_MS: 6000,
  MODELS_CACHE_TTL_MS: 60000,
  STATE_SYNC_TTL_MS: 3000,
  MIN_AVAILABLE_TOKENS: 100,
  COOLDOWN_AUTH_OR_QUOTA_MS: 20 * 60 * 1000, // 20 phút cho 401/403/quota
  COOLDOWN_RATE_LIMIT_DEFAULT_MS: 60 * 1000, // 60 giây cho 429 không có Retry-After
  COOLDOWN_TRANSIENT_BASE_MS: 25 * 1000,     // 25 giây cho 5xx/timeout, tăng dần
  EWMA_ALPHA: 0.3,
  MAX_RECENT_LOGS: 100,
  RESPONSES_ONLY_UPSTREAMS: ["xingchiapi"],
  FORCE_STREAM_ON_RESPONSES_ONLY: true,
  DEFAULT_INSTRUCTIONS: "You are a helpful coding assistant.",
  DEFAULT_CODEX_UA: "codex_cli_rs/0.104.0 (Windows 10; x86_64)",
  DEFAULT_ORIGINATOR: "codex_cli_rs"
};

const ALLOWED_CLIENT_UA_REGEX = /(codex|claude|cursor|kilo|cline|roo|opencode|trae|copilot|grok|qoder|hermes|zcode)/i;
const REASONING_MODEL_REGEX = /(^|\/)(o1|o3|o4|gpt-5|codex|deepseek-reasoner|deepseek-r1|qwq)/i;
const SANITIZE_400_REGEX = /(unsupported parameter|unknown parameter|not supported with this model|does not support|invalid_request_error|temperature|top_p|reasoning|max_tokens|max_completion_tokens|stream_options)/i;

// Local isolate mirror (giảm độ trễ đọc DO xuống ~0ms)
let modelsCache = { expiresAt: 0, payload: null };
const localState = {
  syncedAt: 0,
  keyHealth: {},
  stats: { requests: 0, success: 0, errors: 0, failovers: 0, inputTokens: 0, outputTokens: 0, cachedTokens: 0 },
  virtualKeys: {},
  logs: []
};

// ============================================================================
// MAIN WORKER FETCH HANDLER
// ============================================================================
export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const rawPath = url.pathname.replace(/\/+$/, "") || "/";

    // 1. Admin Dashboard & Admin API
    if (rawPath === "/admin" || rawPath.startsWith("/admin/")) {
      return handleAdminRoute(request, env, url, rawPath);
    }

    const subPath = normalizeSubPath(url.pathname);
    const configResult = parseUpstreamConfig(env.UPSTREAM_CONFIG);
    if (configResult.error) {
      return jsonResponse({ error: { message: configResult.error, type: "config_error" } }, 500);
    }
    const upstreamConfig = configResult.data;
    const modelAliases = parseModelAliases(env.MODEL_ALIASES);

    // 2. Health endpoint
    if (subPath === "" || subPath === "v1" || subPath === "health") {
      return jsonResponse({
        status: "online",
        version: CONFIG.VERSION,
        colo: request.cf?.colo || "unknown",
        country: request.cf?.country || "unknown",
        auth_protected: Boolean(env.WORKER_AUTH_KEY),
        durable_object: Boolean(env.GATEWAY_STATE),
        kv_cache: Boolean(env.GATEWAY_KV),
        aliases_count: Object.keys(modelAliases).length,
        upstreams: upstreamConfig.map((u) => ({
          name: u.name,
          apiType: resolveApiType(u),
          priority: u.priority ?? 100,
          keys_count: Array.isArray(u.keys) ? u.keys.length : 0,
          fallbacks: u.fallbackUpstreams || []
        })),
        endpoints: ["/v1/responses", "/v1/chat/completions", "/v1/messages", "/v1/models", "/admin"]
      });
    }

    // Đồng bộ nhẹ state từ Durable Object (không block quá lâu)
    await syncLocalStateFromDO(env, false);

    // 3. Authentication (Master Key hoặc Virtual Key + RPM limit)
    const clientKey = extractClientApiKey(request);
    const authResult = await authenticateRequest(clientKey, env);
    if (!authResult.ok) {
      return jsonResponse({
        error: { message: authResult.message, type: authResult.type }
      }, authResult.status);
    }

    // 4. Models list (with Isolate + KV Cache + Aliases)
    if ((subPath === "models" || subPath.endsWith("/models")) && request.method === "GET") {
      return handleModelsRoute(request, env, ctx, url, upstreamConfig, modelAliases);
    }

    // 5. Parse incoming request
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
            requestedModel = String(bodyJson.model).trim();
            const resolvedAlias = resolveModelAlias(requestedModel, modelAliases);
            const upstreamMatch = resolvedAlias.match(/\((.*?)\)/);
            if (upstreamMatch && upstreamMatch[1]) {
              detectedUpstreamName = upstreamMatch[1].trim();
            }
            realModelName = resolvedAlias.replace(/\s*\(.*?\)/g, "").trim();
            bodyJson.model = realModelName;
          }
        } catch {
          bodyJson = null;
        }
      }
    }

    // 6. Build Cross-Upstream Failover Chain & Sticky Hash
    const candidateUpstreams = buildCandidateUpstreams(upstreamConfig, detectedUpstreamName, realModelName);
    const stickyHash = computeStickyHash(bodyJson, authResult.keyLabel);
    const clientStreamRequested = Boolean(bodyJson && bodyJson.stream);
    const includeUsage = Boolean(bodyJson?.stream_options?.include_usage);

    // 7. Execute Cross-Upstream + Key Failover + First-Chunk Peek + 400 Auto-Sanitize
    const reqStartTime = Date.now();
    const execResult = await executeAcrossUpstreams({
      candidateUpstreams,
      subPath,
      urlSearch: url.search,
      httpMethod,
      incomingHeaders: request.headers,
      rawBodyText,
      bodyJson,
      realModelName,
      isNativeResponsesRoute,
      isChatCompletionsRoute,
      isAnthropicRoute,
      clientStreamRequested,
      clientKey,
      env,
      ctx,
      stickyHash
    });

    if (!execResult.ok) {
      recordRequestLog(env, ctx, {
        ts: Date.now(),
        model: realModelName || requestedModel || "unknown",
        upstream: execResult.lastUpstream || candidateUpstreams[0]?.name || "unknown",
        keyMask: execResult.lastKeyMask || "-",
        status: execResult.lastErrorResponse?.status || 502,
        ttfbMs: Date.now() - reqStartTime,
        inputTokens: 0,
        outputTokens: 0,
        cachedTokens: 0,
        mode: execResult.lastResponseMode || "error",
        failovers: execResult.failoverCount,
        client: authResult.keyLabel,
        error: execResult.errorSummary || "Upstream failed"
      });

      if (execResult.lastErrorResponse) {
        const errHeaders = new Headers(execResult.lastErrorResponse.headers);
        applyCors(errHeaders);
        return new Response(execResult.lastErrorResponse.body, {
          status: execResult.lastErrorResponse.status,
          headers: errHeaders
        });
      }
      return jsonResponse({
        error: {
          message: `Tất cả upstream và API key đều thất bại cho model '${realModelName}'. Chi tiết: ${execResult.errorSummary || "Unknown error"}`,
          type: "upstream_error"
        }
      }, 502);
    }

    // 8. Transform / Stream Response with Cancellation, Idle Timeout, Heartbeat & Token Accounting
    const {
      response,
      peekedReader,
      upstreamAbortController,
      responseMode,
      activeUpstream,
      effectiveModel,
      keyId,
      keyMask,
      ttfbMs,
      failoverCount
    } = execResult;

    const resContentType = (response.headers.get("content-type") || "").toLowerCase();
    const isEventStream = resContentType.includes("text/event-stream");

    const onFinishUsage = (usage, finalError = null) => {
      const inputTokens = usage?.inputTokens || 0;
      const outputTokens = usage?.outputTokens || 0;
      const cachedTokens = usage?.cachedTokens || 0;
      recordRequestLog(env, ctx, {
        ts: Date.now(),
        model: effectiveModel || realModelName,
        upstream: activeUpstream.name,
        keyMask,
        status: finalError ? 502 : response.status,
        ttfbMs,
        inputTokens,
        outputTokens,
        cachedTokens,
        mode: responseMode,
        failovers: failoverCount,
        client: authResult.keyLabel,
        error: finalError || ""
      });
      if (finalError) {
        reportKeyOutcome(env, ctx, {
          keyId,
          upstream: activeUpstream.name,
          keyMask,
          ok: false,
          status: 502,
          error: finalError
        });
      }
    };

    const extraDebugHeaders = {
      "X-Gateway-Upstream": activeUpstream.name,
      "X-Gateway-TTFB": `${ttfbMs}ms`,
      "X-Gateway-Failovers": String(failoverCount)
    };

    if (responseMode === "responses_sse_to_json") {
      if (isEventStream) {
        const assembled = await collectResponsesFromSSE(peekedReader, effectiveModel, upstreamAbortController);
        onFinishUsage(extractResponsesUsage(assembled));
        return jsonResponse(assembled, 200, extraDebugHeaders);
      }
      const rawJson = await response.json();
      onFinishUsage(extractResponsesUsage(rawJson));
      return jsonResponse(rawJson, response.status, extraDebugHeaders);
    }

    if (responseMode === "responses_to_chat") {
      if (clientStreamRequested && isEventStream) {
        return streamResponsesToChatCompletions({
          reader: peekedReader,
          abortController: upstreamAbortController,
          fallbackModel: effectiveModel,
          includeUsage,
          extraHeaders: extraDebugHeaders,
          onFinishUsage
        });
      }
      const respObj = isEventStream
        ? await collectResponsesFromSSE(peekedReader, effectiveModel, upstreamAbortController)
        : await response.json();
      onFinishUsage(extractResponsesUsage(respObj));
      return jsonResponse(convertResponsesJsonToChatCompletion(respObj, effectiveModel), response.status, extraDebugHeaders);
    }

    if (responseMode === "responses_to_anthropic") {
      if (clientStreamRequested && isEventStream) {
        return streamResponsesToAnthropic({
          reader: peekedReader,
          abortController: upstreamAbortController,
          fallbackModel: effectiveModel,
          extraHeaders: extraDebugHeaders,
          onFinishUsage
        });
      }
      const respObj = isEventStream
        ? await collectResponsesFromSSE(peekedReader, effectiveModel, upstreamAbortController)
        : await response.json();
      onFinishUsage(extractResponsesUsage(respObj));
      return jsonResponse(convertResponsesJsonToAnthropic(respObj, effectiveModel), response.status, extraDebugHeaders);
    }

    if (responseMode === "chat_to_anthropic") {
      if (clientStreamRequested && isEventStream) {
        return streamChatCompletionsToAnthropic({
          reader: peekedReader,
          abortController: upstreamAbortController,
          fallbackModel: effectiveModel,
          extraHeaders: extraDebugHeaders,
          onFinishUsage
        });
      }
      const chatObj = await response.json();
      onFinishUsage(extractChatUsage(chatObj));
      return jsonResponse(convertChatJsonToAnthropic(chatObj, effectiveModel), response.status, extraDebugHeaders);
    }

    // Native passthrough (SSE with heartbeat/idle-timeout/usage spy or plain JSON)
    if (isEventStream) {
      return passthroughSSEStream({
        reader: peekedReader,
        abortController: upstreamAbortController,
        responseHeaders: response.headers,
        status: response.status,
        extraHeaders: extraDebugHeaders,
        onFinishUsage
      });
    }

    // Plain JSON passthrough (read clone only if JSON to track usage)
    if (resContentType.includes("application/json")) {
      const clonedText = await response.clone().text().catch(() => "");
      if (clonedText) {
        try {
          const parsed = JSON.parse(clonedText);
          onFinishUsage(extractAnyUsage(parsed));
        } catch {
          onFinishUsage(null);
        }
      } else {
        onFinishUsage(null);
      }
    } else {
      onFinishUsage(null);
    }
    return passthroughResponse(response, false, extraDebugHeaders);
  }
};

// ============================================================================
// CORE EXECUTION ENGINE: CROSS-UPSTREAM + KEY FAILOVER + FIRST-CHUNK PEEK
// ============================================================================
async function executeAcrossUpstreams(params) {
  const {
    candidateUpstreams,
    subPath,
    urlSearch,
    httpMethod,
    incomingHeaders,
    rawBodyText,
    bodyJson,
    realModelName,
    isNativeResponsesRoute,
    isChatCompletionsRoute,
    isAnthropicRoute,
    clientStreamRequested,
    clientKey,
    env,
    ctx,
    stickyHash
  } = params;

  let lastErrorResponse = null;
  let lastUpstream = "";
  let lastKeyMask = "";
  let lastResponseMode = "passthrough";
  let errorSummary = "";
  let failoverCount = 0;

  for (let uIdx = 0; uIdx < candidateUpstreams.length; uIdx++) {
    const upstream = candidateUpstreams[uIdx];
    lastUpstream = upstream.name;

    let rawKeys = Array.isArray(upstream.keys) ? upstream.keys.filter(Boolean) : [];
    if (rawKeys.length === 0 && clientKey && !env.WORKER_AUTH_KEY) {
      rawKeys = [clientKey];
    }
    if (rawKeys.length === 0) {
      errorSummary = `Upstream '${upstream.name}' không có API key`;
      continue;
    }

    // Chọn key thông minh: ưu tiên Sticky Key khỏe -> Healthy keys theo TTFB -> Cooldown sắp hết hạn
    const orderedKeys = selectOrderedKeys(upstream.name, rawKeys, stickyHash).slice(0, CONFIG.MAX_RETRY_KEYS_PER_UPSTREAM);
    if (orderedKeys.length === 0) continue;

    // Build payload tương ứng với giao thức của upstream hiện tại
    const effectiveModel = mapModelForUpstream(upstream, realModelName);
    const routePlan = buildUpstreamRequestPlan({
      upstream,
      subPath,
      httpMethod,
      rawBodyText,
      bodyJson,
      effectiveModel,
      isNativeResponsesRoute,
      isChatCompletionsRoute,
      isAnthropicRoute,
      clientStreamRequested,
      strictSanitize: false
    });

    lastResponseMode = routePlan.responseMode;
    const baseUrlClean = upstream.baseUrl.replace(/\/+$/, "");
    const targetUrl = `${baseUrlClean}/${routePlan.targetSubPath}${urlSearch}`;
    let bodyBuffer = routePlan.outgoingBodyText ? new TextEncoder().encode(routePlan.outgoingBodyText) : null;
    let didSanitizeRetry = false;

    let transientCount = 0;
    const maxAttempts = Math.max(orderedKeys.length, CONFIG.TRANSIENT_RETRIES + 1);

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const keyEntry = orderedKeys[attempt % orderedKeys.length];
      lastKeyMask = keyEntry.keyMask;
      const upstreamHeaders = buildCleanHeaders(incomingHeaders, keyEntry.apiKey, bodyBuffer !== null, upstream);
      const attemptStart = Date.now();
      const abortController = new AbortController();
      const connectTimer = setTimeout(() => abortController.abort(new Error("Connect timeout")), CONFIG.CONNECT_TIMEOUT_MS);

      try {
        const res = await fetch(targetUrl, {
          method: httpMethod,
          headers: upstreamHeaders,
          body: bodyBuffer,
          redirect: "follow",
          signal: abortController.signal
        });
        clearTimeout(connectTimer);
        const ttfbMs = Date.now() - attemptStart;

        if (res.ok) {
          const ct = (res.headers.get("content-type") || "").toLowerCase();

          // A. Kiểm tra JSON 200 giả chứa lỗi quota/token thấp
          if (ct.includes("application/json")) {
            const jsonCheck = await inspectJson200ForSoftError(res);
            if (jsonCheck.isSoftError) {
              lastErrorResponse = res;
              errorSummary = jsonCheck.reason;
              failoverCount++;
              reportKeyOutcome(env, ctx, {
                keyId: keyEntry.keyId,
                upstream: upstream.name,
                keyMask: keyEntry.keyMask,
                ok: false,
                status: 403,
                cooldownMs: CONFIG.COOLDOWN_AUTH_OR_QUOTA_MS,
                error: jsonCheck.reason
              });
              continue;
            }

            reportKeyOutcome(env, ctx, {
              keyId: keyEntry.keyId,
              upstream: upstream.name,
              keyMask: keyEntry.keyMask,
              ok: true,
              ttfbMs
            });
            return {
              ok: true,
              response: res,
              peekedReader: null,
              upstreamAbortController: abortController,
              responseMode: routePlan.responseMode,
              activeUpstream: upstream,
              effectiveModel,
              keyId: keyEntry.keyId,
              keyMask: keyEntry.keyMask,
              ttfbMs,
              failoverCount
            };
          }

          // B. First-Chunk Peek cho SSE stream (bắt lỗi 200 OK giả ở chunk đầu)
          if (ct.includes("text/event-stream") && res.body) {
            const peekResult = await peekFirstSSEChunk(res.body, abortController, CONFIG.FIRST_CHUNK_TIMEOUT_MS);
            if (!peekResult.ok) {
              abortController.abort(new Error(peekResult.error));
              errorSummary = `SSE fake-200 error: ${peekResult.error}`;
              failoverCount++;
              const isQuotaOrAuth = /(quota|insufficient|credit|balance|unauthorized|invalid_api_key|billing)/i.test(peekResult.error);
              const isRateLimit = /(rate_limit|429|too many|overloaded)/i.test(peekResult.error);
              reportKeyOutcome(env, ctx, {
                keyId: keyEntry.keyId,
                upstream: upstream.name,
                keyMask: keyEntry.keyMask,
                ok: false,
                status: isQuotaOrAuth ? 403 : isRateLimit ? 429 : 502,
                cooldownMs: isQuotaOrAuth ? CONFIG.COOLDOWN_AUTH_OR_QUOTA_MS : isRateLimit ? CONFIG.COOLDOWN_RATE_LIMIT_DEFAULT_MS : CONFIG.COOLDOWN_TRANSIENT_BASE_MS,
                error: peekResult.error
              });
              continue;
            }

            const totalTtfb = Date.now() - attemptStart;
            reportKeyOutcome(env, ctx, {
              keyId: keyEntry.keyId,
              upstream: upstream.name,
              keyMask: keyEntry.keyMask,
              ok: true,
              ttfbMs: totalTtfb
            });
            return {
              ok: true,
              response: res,
              peekedReader: peekResult.reader,
              upstreamAbortController: abortController,
              responseMode: routePlan.responseMode,
              activeUpstream: upstream,
              effectiveModel,
              keyId: keyEntry.keyId,
              keyMask: keyEntry.keyMask,
              ttfbMs: totalTtfb,
              failoverCount
            };
          }

          // Các Content-Type khác (binary/plain)
          reportKeyOutcome(env, ctx, {
            keyId: keyEntry.keyId,
            upstream: upstream.name,
            keyMask: keyEntry.keyMask,
            ok: true,
            ttfbMs
          });
          return {
            ok: true,
            response: res,
            peekedReader: res.body ? res.body.getReader() : null,
            upstreamAbortController: abortController,
            responseMode: routePlan.responseMode,
            activeUpstream: upstream,
            effectiveModel,
            keyId: keyEntry.keyId,
            keyMask: keyEntry.keyMask,
            ttfbMs,
            failoverCount
          };
        }

        // Xử lý HTTP non-2xx
        lastErrorResponse = res;
        const errBodySnippet = await res.clone().text().then((t) => t.slice(0, 350)).catch(() => "");
        errorSummary = `HTTP ${res.status} (${upstream.name}): ${errBodySnippet.slice(0, 120)}`;

        // Lỗi 400 do tham số không tương thích -> tự dọn payload và retry 1 lần trên cùng key
        if (res.status === 400 && !didSanitizeRetry && bodyJson && SANITIZE_400_REGEX.test(errBodySnippet)) {
          didSanitizeRetry = true;
          const sanitizedPlan = buildUpstreamRequestPlan({
            upstream,
            subPath,
            httpMethod,
            rawBodyText,
            bodyJson,
            effectiveModel,
            isNativeResponsesRoute,
            isChatCompletionsRoute,
            isAnthropicRoute,
            clientStreamRequested,
            strictSanitize: true
          });
          bodyBuffer = sanitizedPlan.outgoingBodyText ? new TextEncoder().encode(sanitizedPlan.outgoingBodyText) : null;
          attempt--; // thử lại ngay trên cùng key
          continue;
        }

        // 404 (model không tồn tại ở upstream này) -> bỏ upstream này, nhảy sang fallback upstream tiếp theo
        if (res.status === 404) {
          failoverCount++;
          break;
        }

        // 400 / 422 thật từ phía client (sau khi đã sanitize hoặc lỗi syntax) -> trả thẳng về client
        if (res.status === 400 || res.status === 422) {
          return { ok: false, lastErrorResponse, lastUpstream, lastKeyMask, lastResponseMode, errorSummary, failoverCount };
        }

        // 401 / 403 -> đánh dấu key chết 20 phút và xoay key
        if (res.status === 401 || res.status === 403) {
          failoverCount++;
          reportKeyOutcome(env, ctx, {
            keyId: keyEntry.keyId,
            upstream: upstream.name,
            keyMask: keyEntry.keyMask,
            ok: false,
            status: res.status,
            cooldownMs: CONFIG.COOLDOWN_AUTH_OR_QUOTA_MS,
            error: `HTTP ${res.status}`
          });
          if (attempt + 1 >= orderedKeys.length) break;
          continue;
        }

        // 429 Rate Limit -> đọc Retry-After, đánh dấu cooldown và xoay key
        if (res.status === 429) {
          failoverCount++;
          const retryAfterMs = parseRetryAfterMs(res.headers.get("retry-after")) || CONFIG.COOLDOWN_RATE_LIMIT_DEFAULT_MS;
          reportKeyOutcome(env, ctx, {
            keyId: keyEntry.keyId,
            upstream: upstream.name,
            keyMask: keyEntry.keyMask,
            ok: false,
            status: 429,
            cooldownMs: retryAfterMs,
            error: `HTTP 429 (cooldown ${Math.round(retryAfterMs / 1000)}s)`
          });
          transientCount++;
          if (attempt + 1 >= orderedKeys.length) {
            if (uIdx + 1 < candidateUpstreams.length) break; // nhảy sang upstream dự phòng ngay thay vì ngủ chờ
            if (transientCount > CONFIG.TRANSIENT_RETRIES) break;
            await sleep(Math.min(CONFIG.RETRY_BASE_DELAY_MS * Math.pow(2, transientCount), 3000));
          }
          continue;
        }

        // 408 / 5xx -> đánh dấu transient cooldown ngắn và xoay key
        if ([408, 500, 502, 503, 504, 520, 522, 524].includes(res.status)) {
          failoverCount++;
          transientCount++;
          reportKeyOutcome(env, ctx, {
            keyId: keyEntry.keyId,
            upstream: upstream.name,
            keyMask: keyEntry.keyMask,
            ok: false,
            status: res.status,
            cooldownMs: CONFIG.COOLDOWN_TRANSIENT_BASE_MS,
            error: `HTTP ${res.status}`
          });
          if (attempt + 1 >= orderedKeys.length) {
            if (uIdx + 1 < candidateUpstreams.length) break;
            if (transientCount > CONFIG.TRANSIENT_RETRIES) break;
            const delay = CONFIG.RETRY_BASE_DELAY_MS * Math.pow(2, transientCount - 1) + Math.floor(Math.random() * 200);
            await sleep(Math.min(delay, 3500));
          }
          continue;
        }

        break;
      } catch (err) {
        clearTimeout(connectTimer);
        failoverCount++;
        transientCount++;
        const msg = err?.message || String(err);
        errorSummary = `Network/Timeout (${upstream.name}): ${msg}`;
        reportKeyOutcome(env, ctx, {
          keyId: keyEntry.keyId,
          upstream: upstream.name,
          keyMask: keyEntry.keyMask,
          ok: false,
          status: 504,
          cooldownMs: CONFIG.COOLDOWN_TRANSIENT_BASE_MS,
          error: msg.slice(0, 80)
        });
        if (attempt + 1 >= orderedKeys.length) {
          if (uIdx + 1 < candidateUpstreams.length) break;
          if (transientCount > CONFIG.TRANSIENT_RETRIES) break;
          await sleep(Math.min(CONFIG.RETRY_BASE_DELAY_MS * transientCount, 2500));
        }
      }
    }
  }

  return { ok: false, lastErrorResponse, lastUpstream, lastKeyMask, lastResponseMode, errorSummary, failoverCount };
}

// ============================================================================
// FIRST-CHUNK SSE PEEK & SYNTHETIC STREAM WRAPPER
// ============================================================================
async function peekFirstSSEChunk(bodyStream, abortController, timeoutMs) {
  const reader = bodyStream.getReader();
  const decoder = new TextDecoder();
  const bufferedChunks = [];
  let textBuffer = "";
  const deadline = Date.now() + timeoutMs;

  try {
    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        await reader.cancel().catch(() => {});
        return { ok: false, error: "First-chunk SSE timeout" };
      }

      const { done, value } = await readWithTimeout(reader, remaining);
      if (done) {
        if (bufferedChunks.length === 0) {
          return { ok: false, error: "Empty SSE stream" };
        }
        return { ok: true, reader: createPrependedReader(bufferedChunks, reader) };
      }

      bufferedChunks.push(value);
      textBuffer += decoder.decode(value, { stream: true });

      // Phân tích các dòng đã hoàn chỉnh để kiểm tra event đầu tiên
      const lines = textBuffer.split("\n");
      for (let i = 0; i < lines.length - 1; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith(":") || line.startsWith("event:")) continue;
        if (line.startsWith("data:")) {
          const dataStr = line.slice(5).trim();
          if (!dataStr || dataStr === "[DONE]") {
            return { ok: true, reader: createPrependedReader(bufferedChunks, reader) };
          }
          try {
            const evt = JSON.parse(dataStr);
            const sseErr = detectSSEErrorPayload(evt);
            if (sseErr) {
              await reader.cancel().catch(() => {});
              return { ok: false, error: sseErr };
            }
          } catch {
            // Không phải JSON chuẩn -> cứ cho qua để downstream xử lý
          }
          return { ok: true, reader: createPrependedReader(bufferedChunks, reader) };
        }
        // Nếu upstream trả JSON lỗi trực tiếp dù header là text/event-stream
        if (line.startsWith("{")) {
          try {
            const obj = JSON.parse(line);
            const sseErr = detectSSEErrorPayload(obj);
            if (sseErr) {
              await reader.cancel().catch(() => {});
              return { ok: false, error: sseErr };
            }
          } catch {
            // Chưa đủ JSON
          }
        }
      }

      // Tránh buffer quá lớn nếu upstream gửi cục text khổng lồ không xuống dòng
      if (textBuffer.length > 65536) {
        return { ok: true, reader: createPrependedReader(bufferedChunks, reader) };
      }
    }
  } catch (err) {
    await reader.cancel().catch(() => {});
    return { ok: false, error: err?.message || "SSE peek read error" };
  }
}

function detectSSEErrorPayload(evt) {
  if (!evt || typeof evt !== "object") return null;
  if (evt.type === "error") {
    return evt.error?.message || evt.message || "Upstream SSE error event";
  }
  if (evt.type === "response.failed") {
    return evt.response?.error?.message || "Upstream response.failed";
  }
  if (evt.error) {
    return typeof evt.error === "string" ? evt.error : (evt.error.message || evt.error.code || "Upstream JSON error in SSE");
  }
  if (evt.availableTokens !== undefined && evt.availableTokens < CONFIG.MIN_AVAILABLE_TOKENS) {
    return `availableTokens too low (${evt.availableTokens})`;
  }
  return null;
}

function createPrependedReader(initialChunks, underlyingReader) {
  let idx = 0;
  return {
    async read() {
      if (idx < initialChunks.length) {
        return { done: false, value: initialChunks[idx++] };
      }
      return underlyingReader.read();
    },
    async cancel(reason) {
      idx = initialChunks.length;
      return underlyingReader.cancel(reason);
    }
  };
}

async function inspectJson200ForSoftError(res) {
  try {
    const clonedText = await res.clone().text();
    if (!clonedText.startsWith("{")) return { isSoftError: false };
    const data = JSON.parse(clonedText);
    if (data.availableTokens !== undefined && data.availableTokens < CONFIG.MIN_AVAILABLE_TOKENS) {
      return { isSoftError: true, reason: `availableTokens=${data.availableTokens}` };
    }
    const errCode = typeof data.error === "string" ? data.error : data.error?.code;
    const errMsg = typeof data.error === "string" ? data.error : data.error?.message;
    if (errCode === "insufficient_quota" || errCode === "QUOTA_EXCEEDED" || /insufficient_quota|quota_exceeded/i.test(String(errMsg || ""))) {
      return { isSoftError: true, reason: errCode || errMsg || "insufficient_quota" };
    }
  } catch {
    // ignore parse error
  }
  return { isSoftError: false };
}

// ============================================================================
// REQUEST ROUTING, MODEL ALIASING & PROTOCOL CONVERSION PLANNER
// ============================================================================
function buildUpstreamRequestPlan({
  upstream,
  subPath,
  httpMethod,
  rawBodyText,
  bodyJson,
  effectiveModel,
  isNativeResponsesRoute,
  isChatCompletionsRoute,
  isAnthropicRoute,
  clientStreamRequested,
  strictSanitize
}) {
  const apiType = resolveApiType(upstream);
  const isResponsesOnly = apiType === "responses";
  const isAnthropicNative = apiType === "anthropic";
  const useResponsesUpstream = isNativeResponsesRoute || isResponsesOnly;
  const shouldStripSampling = Boolean(strictSanitize || upstream.stripSamplingParams || isResponsesOnly || REASONING_MODEL_REGEX.test(effectiveModel));

  let targetSubPath = subPath;
  let responseMode = "passthrough";
  let outgoingPayloadObj = null;
  let outgoingBodyText = rawBodyText;

  if (bodyJson && httpMethod === "POST") {
    const clonedBody = { ...bodyJson, model: effectiveModel };

    if (isAnthropicRoute && isAnthropicNative) {
      // Upstream hỗ trợ sẵn Anthropic /v1/messages -> passthrough trực tiếp
      targetSubPath = "messages";
      responseMode = "passthrough";
      outgoingPayloadObj = clonedBody;
    } else if (isNativeResponsesRoute) {
      targetSubPath = "responses";
      outgoingPayloadObj = normalizeNativeResponsesPayload(clonedBody, isResponsesOnly, shouldStripSampling, strictSanitize);
      if (isResponsesOnly && CONFIG.FORCE_STREAM_ON_RESPONSES_ONLY && !clientStreamRequested) {
        outgoingPayloadObj.stream = true;
        responseMode = "responses_sse_to_json";
      }
    } else if (isChatCompletionsRoute && useResponsesUpstream) {
      targetSubPath = "responses";
      responseMode = "responses_to_chat";
      outgoingPayloadObj = convertChatToResponsesPayload(clonedBody, isResponsesOnly, shouldStripSampling, strictSanitize);
      if (isResponsesOnly && CONFIG.FORCE_STREAM_ON_RESPONSES_ONLY && !clientStreamRequested) {
        outgoingPayloadObj.stream = true;
      }
    } else if (isAnthropicRoute && useResponsesUpstream) {
      targetSubPath = "responses";
      responseMode = "responses_to_anthropic";
      const shouldStreamUpstream = clientStreamRequested || (isResponsesOnly && CONFIG.FORCE_STREAM_ON_RESPONSES_ONLY);
      outgoingPayloadObj = convertAnthropicToResponsesPayload(clonedBody, shouldStreamUpstream, isResponsesOnly, shouldStripSampling, strictSanitize);
    } else if (isAnthropicRoute) {
      targetSubPath = "chat/completions";
      responseMode = "chat_to_anthropic";
      outgoingPayloadObj = convertAnthropicToOpenAIPayload(clonedBody, clientStreamRequested, shouldStripSampling, strictSanitize);
    } else {
      targetSubPath = subPath;
      outgoingPayloadObj = sanitizeGenericChatPayload(clonedBody, shouldStripSampling, strictSanitize);
    }

    if (outgoingPayloadObj) {
      outgoingBodyText = JSON.stringify(outgoingPayloadObj);
    }
  }

  return { targetSubPath, responseMode, outgoingBodyText };
}

function buildCandidateUpstreams(upstreamConfig, detectedName, realModelName) {
  const ordered = [];
  const added = new Set();
  const pushUnique = (u) => {
    if (u && !added.has(u.name)) {
      added.add(u.name);
      ordered.push(u);
    }
  };

  let primary = null;
  if (detectedName) {
    primary = upstreamConfig.find((u) => String(u.name || "").toLowerCase() === detectedName.toLowerCase());
  }
  if (!primary && realModelName) {
    const matches = upstreamConfig
      .filter((u) => upstreamSupportsModel(u, realModelName))
      .sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
    primary = matches[0] || null;
  }
  if (!primary) {
    primary = [...upstreamConfig].sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100))[0];
  }

  pushUnique(primary);

  // 1. Explicit fallbackUpstreams trên primary
  if (Array.isArray(primary?.fallbackUpstreams)) {
    for (const fbName of primary.fallbackUpstreams) {
      const found = upstreamConfig.find((u) => String(u.name || "").toLowerCase() === String(fbName).toLowerCase());
      pushUnique(found);
    }
  }

  // 2. Các upstream khác cũng khai báo hỗ trợ model này (xếp theo priority)
  if (realModelName) {
    const others = upstreamConfig
      .filter((u) => !added.has(u.name) && upstreamSupportsModel(u, realModelName))
      .sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
    for (const u of others) pushUnique(u);
  }

  return ordered;
}

function upstreamSupportsModel(u, modelName) {
  const lower = String(modelName || "").toLowerCase();
  if (!lower) return false;
  if (u.modelMap && typeof u.modelMap === "object") {
    for (const k of Object.keys(u.modelMap)) {
      if (k.toLowerCase() === lower) return true;
    }
  }
  if (Array.isArray(u.models)) {
    return u.models.some((m) => String(m).toLowerCase() === lower);
  }
  return false;
}

function mapModelForUpstream(upstream, modelName) {
  if (!modelName || !upstream?.modelMap || typeof upstream.modelMap !== "object") return modelName;
  if (upstream.modelMap[modelName]) return upstream.modelMap[modelName];
  const lower = modelName.toLowerCase();
  for (const [k, v] of Object.entries(upstream.modelMap)) {
    if (k.toLowerCase() === lower) return v;
  }
  return modelName;
}

function resolveApiType(upstream) {
  if (!upstream) return "chat";
  if (upstream.apiType) return String(upstream.apiType).toLowerCase();
  if (CONFIG.RESPONSES_ONLY_UPSTREAMS.includes(String(upstream.name || "").toLowerCase())) {
    return "responses";
  }
  return "chat";
}

function parseModelAliases(envAliases) {
  if (!envAliases) return {};
  try {
    const parsed = JSON.parse(String(envAliases).replace(/[\u201C\u201D]/g, '"').trim());
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function resolveModelAlias(modelName, aliases) {
  if (!modelName || !aliases) return modelName;
  if (aliases[modelName]) return String(aliases[modelName]);
  const lower = modelName.toLowerCase();
  for (const [k, v] of Object.entries(aliases)) {
    if (k.toLowerCase() === lower) return String(v);
  }
  return modelName;
}

// ============================================================================
// SMART KEY SELECTION (STICKY ROUTING + CIRCUIT BREAKER + EWMA TTFB)
// ============================================================================
function selectOrderedKeys(upstreamName, rawKeys, stickyHash) {
  const now = Date.now();
  const entries = rawKeys.map((apiKey) => {
    const keyId = makeKeyId(upstreamName, apiKey);
    const keyMask = maskApiKey(apiKey);
    const health = localState.keyHealth[keyId] || {};
    const cooldownUntil = health.cooldownUntil || 0;
    const isCoolingDown = cooldownUntil > now;
    const ewmaTtfb = health.ewmaTtfbMs || 1500;
    return { apiKey, keyId, keyMask, isCoolingDown, cooldownUntil, ewmaTtfb };
  });

  const healthy = entries.filter((e) => !e.isCoolingDown);
  const cooling = entries.filter((e) => e.isCoolingDown).sort((a, b) => a.cooldownUntil - b.cooldownUntil);

  if (healthy.length > 1) {
    // 1. Giữ nguyên Sticky Key ở vị trí đầu để ăn trọn Prompt Caching
    const stickyIdx = stickyHash % healthy.length;
    const pinned = healthy[stickyIdx];
    const rest = healthy.filter((_, idx) => idx !== stickyIdx);
    // 2. Các key dự phòng xếp theo EWMA TTFB nhanh nhất
    rest.sort((a, b) => a.ewmaTtfb - b.ewmaTtfb);
    return [pinned, ...rest, ...cooling];
  }

  return [...healthy, ...cooling];
}

function computeStickyHash(bodyJson, fallbackSeed) {
  if (!bodyJson || typeof bodyJson !== "object") return fnv1aHash(fallbackSeed || "default");
  if (bodyJson.prompt_cache_key) return fnv1aHash(String(bodyJson.prompt_cache_key));
  if (bodyJson.user) return fnv1aHash(String(bodyJson.user));

  let seed = String(bodyJson.model || "");
  if (bodyJson.instructions) {
    seed += "|" + String(bodyJson.instructions).slice(0, 512);
  } else if (bodyJson.system) {
    seed += "|" + extractPlainText(bodyJson.system).slice(0, 512);
  }

  const msgs = Array.isArray(bodyJson.messages) ? bodyJson.messages : Array.isArray(bodyJson.input) ? bodyJson.input : [];
  for (let i = 0; i < Math.min(msgs.length, 3); i++) {
    const m = msgs[i];
    if (m && (m.role === "system" || m.role === "developer" || m.role === "user")) {
      seed += "|" + extractPlainText(m.content).slice(0, 512);
    }
  }
  return fnv1aHash(seed || fallbackSeed || "default");
}

function fnv1aHash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function makeKeyId(upstreamName, apiKey) {
  return `${upstreamName}:${fnv1aHash(`${upstreamName}|${apiKey}`).toString(16)}`;
}

function maskApiKey(key) {
  const s = String(key || "");
  if (s.length <= 10) return "***";
  return `${s.slice(0, 6)}...${s.slice(-4)}`;
}

function parseRetryAfterMs(headerVal) {
  if (!headerVal) return 0;
  const secs = Number(headerVal);
  if (!Number.isNaN(secs) && secs > 0) {
    return Math.min(secs * 1000, 10 * 60 * 1000);
  }
  const dateMs = Date.parse(headerVal);
  if (!Number.isNaN(dateMs) && dateMs > Date.now()) {
    return Math.min(dateMs - Date.now(), 10 * 60 * 1000);
  }
  return 0;
}

// ============================================================================
// PAYLOAD CONVERTERS & AUTO-SANITIZER (BUGS 1, 2, 4 FIXED)
// ============================================================================
function mapThinkingBudgetToEffort(budget) {
  const n = Number(budget || 0);
  if (n >= 16000) return "high";
  if (n >= 4000) return "medium";
  return "low";
}

function stripUnsupportedParams(payload, shouldStripSampling, strictSanitize) {
  if (shouldStripSampling) {
    delete payload.temperature;
    delete payload.top_p;
    delete payload.presence_penalty;
    delete payload.frequency_penalty;
    delete payload.logprobs;
    delete payload.top_logprobs;
  }
  if (strictSanitize) {
    delete payload.temperature;
    delete payload.top_p;
    delete payload.presence_penalty;
    delete payload.frequency_penalty;
    delete payload.reasoning;
    delete payload.reasoning_effort;
    delete payload.stream_options;
    delete payload.parallel_tool_calls;
  }
  return payload;
}

function sanitizeGenericChatPayload(body, shouldStripSampling, strictSanitize) {
  const payload = { ...body };
  if (payload.thinking && !payload.reasoning_effort && !strictSanitize) {
    if (payload.thinking.type === "enabled") {
      payload.reasoning_effort = mapThinkingBudgetToEffort(payload.thinking.budget_tokens);
    }
    delete payload.thinking;
  }
  return stripUnsupportedParams(payload, shouldStripSampling, strictSanitize);
}

function normalizeNativeResponsesPayload(body, strictCodex, shouldStripSampling, strictSanitize) {
  const payload = { ...body };
  if (strictCodex) {
    if (payload.store === undefined) payload.store = false;
    if (!payload.instructions) payload.instructions = CONFIG.DEFAULT_INSTRUCTIONS;
    if (typeof payload.input === "string") {
      payload.input = [
        { type: "message", role: "user", content: [{ type: "input_text", text: payload.input }] }
      ];
    }
  }
  return stripUnsupportedParams(payload, shouldStripSampling, strictSanitize);
}

function convertChatToResponsesPayload(chat, strictCodex, shouldStripSampling, strictSanitize) {
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
            arguments: typeof tc.function?.arguments === "string" ? tc.function.arguments : JSON.stringify(tc.function?.arguments || {})
          });
        }
      }
      continue;
    }

    if (Array.isArray(msg.content)) {
      const parts = msg.content.map((part) => {
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
    payload.tools = chat.tools.map((t) => {
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

  if (chat.reasoning !== undefined) {
    payload.reasoning = chat.reasoning;
  } else if (chat.reasoning_effort !== undefined) {
    payload.reasoning = { effort: chat.reasoning_effort, summary: "auto" };
  }

  return stripUnsupportedParams(payload, shouldStripSampling, strictSanitize);
}

function convertAnthropicToResponsesPayload(anth, stream, strictCodex, shouldStripSampling, strictSanitize) {
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
        } else if (block.type === "image" && block.source) {
          const imgUrl = block.source.type === "base64"
            ? `data:${block.source.media_type || "image/png"};base64,${block.source.data}`
            : block.source.url;
          if (imgUrl) contentParts.push({ type: "input_image", image_url: imgUrl });
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
  if (anth.top_p !== undefined) payload.top_p = anth.top_p;
  if (anth.max_tokens !== undefined) payload.max_output_tokens = anth.max_tokens;

  // Dịch Anthropic thinking -> OpenAI Responses reasoning
  if (anth.thinking?.type === "enabled") {
    payload.reasoning = {
      effort: mapThinkingBudgetToEffort(anth.thinking.budget_tokens),
      summary: "auto"
    };
  }

  if (Array.isArray(anth.tools) && anth.tools.length > 0) {
    payload.tools = anth.tools.map((t) => ({
      type: "function",
      name: t.name,
      description: t.description || "",
      parameters: t.input_schema || { type: "object", properties: {} }
    }));
  }

  if (anth.tool_choice) {
    if (anth.tool_choice.type === "auto") payload.tool_choice = "auto";
    else if (anth.tool_choice.type === "any") payload.tool_choice = "required";
    else if (anth.tool_choice.type === "none") payload.tool_choice = "none";
    else if (anth.tool_choice.type === "tool" && anth.tool_choice.name) {
      payload.tool_choice = { type: "function", name: anth.tool_choice.name };
    }
  }

  return stripUnsupportedParams(payload, shouldStripSampling, strictSanitize);
}

function convertAnthropicToOpenAIPayload(anth, stream, shouldStripSampling, strictSanitize) {
  const messages = [];
  const sysText = extractPlainText(anth.system);
  if (sysText) messages.push({ role: "system", content: sysText });

  for (const msg of anth.messages || []) {
    if (typeof msg.content === "string") {
      messages.push({ role: msg.role, content: msg.content });
      continue;
    }

    if (Array.isArray(msg.content)) {
      const contentParts = [];
      const toolCalls = [];
      const toolResults = [];
      let hasImage = false;

      for (const block of msg.content) {
        if (block.type === "text" && block.text) {
          contentParts.push({ type: "text", text: block.text });
        } else if (block.type === "image" && block.source) {
          hasImage = true;
          const imgUrl = block.source.type === "base64"
            ? `data:${block.source.media_type || "image/png"};base64,${block.source.data}`
            : block.source.url;
          if (imgUrl) {
            contentParts.push({ type: "image_url", image_url: { url: imgUrl } });
          }
        } else if (block.type === "tool_use") {
          toolCalls.push({
            id: block.id || `call_${Math.random().toString(36).slice(2, 10)}`,
            type: "function",
            function: {
              name: block.name || "",
              arguments: typeof block.input === "string" ? block.input : JSON.stringify(block.input || {})
            }
          });
        } else if (block.type === "tool_result") {
          toolResults.push({
            role: "tool",
            tool_call_id: block.tool_use_id || "",
            content: extractPlainText(block.content)
          });
        }
      }

      if (contentParts.length > 0 || toolCalls.length > 0) {
        const contentVal = contentParts.length === 0
          ? null
          : hasImage
            ? contentParts
            : contentParts.map((p) => p.text).join("\n");
        const m = { role: msg.role, content: contentVal };
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

  // Yêu cầu upstream trả usage ở chunk cuối khi stream để điền đúng output_tokens cho Anthropic
  if (stream && !strictSanitize) {
    payload.stream_options = { include_usage: true };
  }
  if (anth.temperature !== undefined) payload.temperature = anth.temperature;
  if (anth.top_p !== undefined) payload.top_p = anth.top_p;
  if (anth.max_tokens !== undefined) payload.max_tokens = anth.max_tokens;
  if (Array.isArray(anth.stop_sequences) && anth.stop_sequences.length > 0) {
    payload.stop = anth.stop_sequences;
  }

  if (anth.thinking?.type === "enabled") {
    payload.reasoning_effort = mapThinkingBudgetToEffort(anth.thinking.budget_tokens);
  }

  if (Array.isArray(anth.tools) && anth.tools.length > 0) {
    payload.tools = anth.tools.map((t) => ({
      type: "function",
      function: {
        name: t.name,
        description: t.description || "",
        parameters: t.input_schema || { type: "object", properties: {} }
      }
    }));
  }

  if (anth.tool_choice) {
    if (anth.tool_choice.type === "auto") payload.tool_choice = "auto";
    else if (anth.tool_choice.type === "any") payload.tool_choice = "required";
    else if (anth.tool_choice.type === "none") payload.tool_choice = "none";
    else if (anth.tool_choice.type === "tool" && anth.tool_choice.name) {
      payload.tool_choice = { type: "function", function: { name: anth.tool_choice.name } };
    }
  }

  return stripUnsupportedParams(payload, shouldStripSampling, strictSanitize);
}

// ============================================================================
// STREAMING & JSON CONVERTERS (WITH CANCEL, IDLE TIMEOUT & HEARTBEAT)
// ============================================================================
function createManagedSSEResponse({ reader, abortController, headers, status = 200, processor }) {
  const encoder = new TextEncoder();
  let closed = false;
  let lastWriteAt = Date.now();
  let heartbeatTimer = null;

  const stream = new ReadableStream({
    async start(controller) {
      const safeEnqueue = (strOrBytes) => {
        if (closed) return;
        try {
          const bytes = typeof strOrBytes === "string" ? encoder.encode(strOrBytes) : strOrBytes;
          controller.enqueue(bytes);
          lastWriteAt = Date.now();
        } catch {
          closed = true;
        }
      };

      const safeClose = () => {
        if (closed) return;
        closed = true;
        if (heartbeatTimer) clearInterval(heartbeatTimer);
        try {
          controller.close();
        } catch {
          // ignore
        }
      };

      heartbeatTimer = setInterval(() => {
        if (closed) {
          clearInterval(heartbeatTimer);
          return;
        }
        if (Date.now() - lastWriteAt >= CONFIG.HEARTBEAT_INTERVAL_MS) {
          safeEnqueue(": keep-alive\n\n");
        }
      }, 5000);

      try {
        await processor({
          reader,
          safeEnqueue,
          isClosed: () => closed,
          readNext: () => readWithTimeout(reader, CONFIG.STREAM_IDLE_TIMEOUT_MS)
        });
      } catch (err) {
        if (!closed) {
          console.error("[StreamProcessor Error]", err?.message || err);
        }
      } finally {
        safeClose();
      }
    },
    async cancel() {
      // Client bấm Stop / đóng kết nối -> cắt upstream ngay để không rò rỉ token
      closed = true;
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      try {
        abortController?.abort(new Error("Client disconnected"));
      } catch {
        // ignore
      }
      try {
        await reader?.cancel();
      } catch {
        // ignore
      }
    }
  });

  return new Response(stream, { status, headers });
}

function passthroughSSEStream({ reader, abortController, responseHeaders, status, extraHeaders, onFinishUsage }) {
  const headers = new Headers(responseHeaders);
  applyCors(headers);
  for (const [k, v] of Object.entries(extraHeaders || {})) headers.set(k, v);
  headers.set("Cache-Control", "no-cache, no-transform");
  headers.set("Connection", "keep-alive");

  return createManagedSSEResponse({
    reader,
    abortController,
    headers,
    status,
    processor: async ({ safeEnqueue, isClosed, readNext }) => {
      const decoder = new TextDecoder();
      let spyBuffer = "";
      let capturedUsage = null;
      let streamErr = null;

      try {
        while (!isClosed()) {
          const { done, value } = await readNext();
          if (done) break;
          safeEnqueue(value);

          // Đọc thụ động usage từ dòng cuối để thống kê lên /admin
          spyBuffer += decoder.decode(value, { stream: true });
          const lines = spyBuffer.split("\n");
          spyBuffer = lines.pop() || "";
          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line.startsWith("data:")) continue;
            const dataStr = line.slice(5).trim();
            if (!dataStr || dataStr === "[DONE]") continue;
            if (dataStr.includes('"usage"')) {
              try {
                const parsed = JSON.parse(dataStr);
                const u = extractAnyUsage(parsed);
                if (u && (u.inputTokens || u.outputTokens)) capturedUsage = u;
              } catch {
                // ignore
              }
            }
          }
        }
      } catch (err) {
        streamErr = err?.message || "Stream idle timeout";
      } finally {
        onFinishUsage(capturedUsage, streamErr);
      }
    }
  });
}

function streamResponsesToChatCompletions({ reader, abortController, fallbackModel, includeUsage, extraHeaders, onFinishUsage }) {
  const headers = new Headers({
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    ...extraHeaders
  });
  applyCors(headers);

  return createManagedSSEResponse({
    reader,
    abortController,
    headers,
    processor: async ({ safeEnqueue, isClosed, readNext }) => {
      const decoder = new TextDecoder();
      const chatId = `chatcmpl_${Date.now()}`;
      const created = Math.floor(Date.now() / 1000);
      let model = fallbackModel;
      let buffer = "";
      let hasToolCall = false;
      let sentFinish = false;
      let finalUsage = null;
      let ledgerUsage = null;
      let streamErr = null;
      const toolIndexByItemId = new Map();
      let nextToolIndex = 0;

      const sendChunk = (delta, finishReason = null, usage = null) => {
        const chunk = {
          id: chatId,
          object: "chat.completion.chunk",
          created,
          model,
          choices: delta !== null ? [{ index: 0, delta, finish_reason: finishReason }] : []
        };
        if (usage) chunk.usage = usage;
        safeEnqueue(`data: ${JSON.stringify(chunk)}\n\n`);
      };

      try {
        while (!isClosed()) {
          const { done, value } = await readNext();
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
            } catch {
              continue;
            }

            if (evt.response?.model) model = evt.response.model;

            if (evt.type === "response.output_text.delta" && evt.delta) {
              sendChunk({ content: evt.delta });
            } else if ((evt.type === "response.reasoning_summary_text.delta" || evt.type === "response.reasoning_text.delta") && evt.delta) {
              sendChunk({ reasoning_content: evt.delta });
            } else if (evt.type === "response.output_item.added" && evt.item?.type === "function_call") {
              hasToolCall = true;
              const idx = nextToolIndex++;
              toolIndexByItemId.set(evt.item.id || evt.item.call_id, idx);
              sendChunk({
                tool_calls: [{
                  index: idx,
                  id: evt.item.call_id || evt.item.id || `call_${idx}`,
                  type: "function",
                  function: { name: evt.item.name || "", arguments: "" }
                }]
              });
            } else if (evt.type === "response.function_call_arguments.delta" && evt.delta) {
              const idx = toolIndexByItemId.get(evt.item_id) ?? 0;
              sendChunk({ tool_calls: [{ index: idx, function: { arguments: evt.delta } }] });
            } else if (evt.type === "response.completed" || evt.type === "response.incomplete") {
              if (evt.response?.usage) {
                ledgerUsage = extractResponsesUsage(evt.response);
                finalUsage = {
                  prompt_tokens: ledgerUsage.inputTokens,
                  completion_tokens: ledgerUsage.outputTokens,
                  total_tokens: ledgerUsage.inputTokens + ledgerUsage.outputTokens,
                  prompt_tokens_details: { cached_tokens: ledgerUsage.cachedTokens }
                };
              }
              sentFinish = true;
              const reason = evt.type === "response.incomplete" ? "length" : (hasToolCall ? "tool_calls" : "stop");
              sendChunk({}, reason);
            } else if (evt.type === "response.failed" || evt.type === "error") {
              const msg = evt.response?.error?.message || evt.error?.message || "Upstream response failed";
              streamErr = msg;
              sendChunk({ content: `\n[Error: ${msg}]` }, "stop");
              sentFinish = true;
            }
          }
        }

        if (!isClosed()) {
          if (!sentFinish) sendChunk({}, hasToolCall ? "tool_calls" : "stop");
          if (includeUsage && finalUsage) sendChunk(null, null, finalUsage);
          safeEnqueue("data: [DONE]\n\n");
        }
      } catch (err) {
        streamErr = err?.message || "Responses->Chat stream interrupted";
        if (!isClosed()) {
          sendChunk({ content: `\n[Gateway Stream Error: ${streamErr}]` }, "stop");
          safeEnqueue("data: [DONE]\n\n");
        }
      } finally {
        onFinishUsage(ledgerUsage, streamErr);
      }
    }
  });
}

// FIXED: Hỗ trợ thinking, parallel tool calls không bị trộn JSON, input/output tokens và error events
function streamResponsesToAnthropic({ reader, abortController, fallbackModel, extraHeaders, onFinishUsage }) {
  const headers = new Headers({
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    ...extraHeaders
  });
  applyCors(headers);

  return createManagedSSEResponse({
    reader,
    abortController,
    headers,
    processor: async ({ safeEnqueue, isClosed, readNext }) => {
      const decoder = new TextDecoder();
      const msgId = `msg_${Date.now()}`;
      let buffer = "";
      let currentBlockIndex = -1;
      let currentBlockType = null;
      let activeToolItemId = null;
      let hasToolUse = false;
      let stopReason = "end_turn";
      let inputTokens = 0;
      let outputTokens = 0;
      let cachedTokens = 0;
      let streamErr = null;

      // Buffer các tool call chạy song song để không trộn JSON trong cùng 1 content_block
      const pendingTools = new Map(); // itemId -> { id, name, args, done }

      const emit = (event, data) => {
        safeEnqueue(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      };

      const closeCurrentBlock = () => {
        if (currentBlockIndex >= 0 && currentBlockType !== null) {
          emit("content_block_stop", { type: "content_block_stop", index: currentBlockIndex });
          currentBlockType = null;
          activeToolItemId = null;
        }
      };

      const flushPendingTools = () => {
        for (const [itemId, t] of pendingTools.entries()) {
          closeCurrentBlock();
          currentBlockIndex++;
          currentBlockType = "tool_use";
          activeToolItemId = itemId;
          emit("content_block_start", {
            type: "content_block_start",
            index: currentBlockIndex,
            content_block: { type: "tool_use", id: t.id, name: t.name, input: {} }
          });
          if (t.args) {
            emit("content_block_delta", {
              type: "content_block_delta",
              index: currentBlockIndex,
              delta: { type: "input_json_delta", partial_json: t.args }
            });
          }
          if (t.done) {
            closeCurrentBlock();
          }
          pendingTools.delete(itemId);
          if (!t.done) break; // Giữ tool đang dở làm active tool
        }
      };

      try {
        emit("message_start", {
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

        while (!isClosed()) {
          const { done, value } = await readNext();
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
            } catch {
              continue;
            }

            if ((evt.type === "response.reasoning_summary_text.delta" || evt.type === "response.reasoning_text.delta") && evt.delta) {
              if (currentBlockType !== "thinking") {
                closeCurrentBlock();
                currentBlockIndex++;
                currentBlockType = "thinking";
                emit("content_block_start", {
                  type: "content_block_start",
                  index: currentBlockIndex,
                  content_block: { type: "thinking", thinking: "" }
                });
              }
              emit("content_block_delta", {
                type: "content_block_delta",
                index: currentBlockIndex,
                delta: { type: "thinking_delta", thinking: evt.delta }
              });
            } else if (evt.type === "response.output_text.delta" && evt.delta) {
              if (currentBlockType !== "text") {
                closeCurrentBlock();
                currentBlockIndex++;
                currentBlockType = "text";
                emit("content_block_start", {
                  type: "content_block_start",
                  index: currentBlockIndex,
                  content_block: { type: "text", text: "" }
                });
              }
              emit("content_block_delta", {
                type: "content_block_delta",
                index: currentBlockIndex,
                delta: { type: "text_delta", text: evt.delta }
              });
            } else if (evt.type === "response.output_item.added" && evt.item?.type === "function_call") {
              hasToolUse = true;
              const itemId = evt.item.id || evt.item.call_id || `fc_${Date.now()}_${currentBlockIndex}`;
              const callId = evt.item.call_id || evt.item.id || `toolu_${Date.now()}`;
              const name = evt.item.name || "";

              if (currentBlockType === "tool_use" && activeToolItemId && activeToolItemId !== itemId) {
                // Có tool khác đang mở -> buffer lại, lát mở sau
                pendingTools.set(itemId, { id: callId, name, args: "", done: false });
              } else {
                closeCurrentBlock();
                currentBlockIndex++;
                currentBlockType = "tool_use";
                activeToolItemId = itemId;
                emit("content_block_start", {
                  type: "content_block_start",
                  index: currentBlockIndex,
                  content_block: { type: "tool_use", id: callId, name, input: {} }
                });
              }
            } else if (evt.type === "response.function_call_arguments.delta" && evt.delta) {
              const itemId = evt.item_id;
              if (currentBlockType === "tool_use" && (!itemId || itemId === activeToolItemId)) {
                emit("content_block_delta", {
                  type: "content_block_delta",
                  index: currentBlockIndex,
                  delta: { type: "input_json_delta", partial_json: evt.delta }
                });
              } else if (itemId && pendingTools.has(itemId)) {
                pendingTools.get(itemId).args += evt.delta;
              }
            } else if (evt.type === "response.output_item.done" && evt.item?.type === "function_call") {
              const itemId = evt.item.id || evt.item.call_id;
              if (itemId === activeToolItemId) {
                closeCurrentBlock();
                flushPendingTools();
              } else if (pendingTools.has(itemId)) {
                pendingTools.get(itemId).done = true;
              }
            } else if (evt.type === "response.completed" || evt.type === "response.incomplete") {
              const u = extractResponsesUsage(evt.response);
              inputTokens = u.inputTokens;
              outputTokens = u.outputTokens;
              cachedTokens = u.cachedTokens;
              if (evt.type === "response.incomplete") stopReason = "max_tokens";
            } else if (evt.type === "response.failed" || evt.type === "error") {
              streamErr = evt.response?.error?.message || evt.error?.message || "Upstream failed";
              emit("error", { type: "error", error: { type: "api_error", message: streamErr } });
              return;
            }
          }
        }

        if (!isClosed()) {
          closeCurrentBlock();
          // Flush bất kỳ tool call nào còn nằm trong pending
          for (const [, t] of pendingTools.entries()) {
            currentBlockIndex++;
            emit("content_block_start", {
              type: "content_block_start",
              index: currentBlockIndex,
              content_block: { type: "tool_use", id: t.id, name: t.name, input: {} }
            });
            if (t.args) {
              emit("content_block_delta", {
                type: "content_block_delta",
                index: currentBlockIndex,
                delta: { type: "input_json_delta", partial_json: t.args }
              });
            }
            emit("content_block_stop", { type: "content_block_stop", index: currentBlockIndex });
          }

          if (currentBlockIndex < 0) {
            emit("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
            emit("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "" } });
            emit("content_block_stop", { type: "content_block_stop", index: 0 });
          }

          emit("message_delta", {
            type: "message_delta",
            delta: { stop_reason: hasToolUse ? "tool_use" : stopReason, stop_sequence: null },
            usage: { input_tokens: inputTokens, output_tokens: outputTokens, cache_read_input_tokens: cachedTokens }
          });
          emit("message_stop", { type: "message_stop" });
        }
      } catch (err) {
        streamErr = err?.message || "Responses->Anthropic stream interrupted";
        if (!isClosed()) {
          emit("error", { type: "error", error: { type: "api_error", message: streamErr } });
        }
      } finally {
        onFinishUsage({ inputTokens, outputTokens, cachedTokens }, streamErr);
      }
    }
  });
}

// FIXED: Hỗ trợ đầy đủ delta.tool_calls, delta.reasoning_content, stop_reason thật và usage thật
function streamChatCompletionsToAnthropic({ reader, abortController, fallbackModel, extraHeaders, onFinishUsage }) {
  const headers = new Headers({
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    ...extraHeaders
  });
  applyCors(headers);

  return createManagedSSEResponse({
    reader,
    abortController,
    headers,
    processor: async ({ safeEnqueue, isClosed, readNext }) => {
      const decoder = new TextDecoder();
      const msgId = `msg_${Date.now()}`;
      let buffer = "";
      let currentBlockIndex = -1;
      let currentBlockType = null;
      let activeOpenAIToolIdx = null;
      let hasToolUse = false;
      let finishReason = "end_turn";
      let inputTokens = 0;
      let outputTokens = 0;
      let cachedTokens = 0;
      let streamErr = null;

      // Buffer cho tool call song song nếu OpenAI stream xen kẽ index 0 và 1
      const openAITools = new Map(); // openaiIndex -> { id, name, args, emitted }

      const emit = (event, data) => {
        safeEnqueue(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      };

      const closeCurrentBlock = () => {
        if (currentBlockIndex >= 0 && currentBlockType !== null) {
          emit("content_block_stop", { type: "content_block_stop", index: currentBlockIndex });
          currentBlockType = null;
          activeOpenAIToolIdx = null;
        }
      };

      try {
        emit("message_start", {
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

        while (!isClosed()) {
          const { done, value } = await readNext();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line.startsWith("data:")) continue;
            const dataStr = line.slice(5).trim();
            if (!dataStr || dataStr === "[DONE]") continue;

            let parsed;
            try {
              parsed = JSON.parse(dataStr);
            } catch {
              continue;
            }

            if (parsed.error) {
              streamErr = parsed.error.message || String(parsed.error);
              emit("error", { type: "error", error: { type: "api_error", message: streamErr } });
              return;
            }

            if (parsed.usage) {
              const u = extractChatUsage(parsed);
              inputTokens = u.inputTokens || inputTokens;
              outputTokens = u.outputTokens || outputTokens;
              cachedTokens = u.cachedTokens || cachedTokens;
            }

            const choice = parsed.choices?.[0];
            if (!choice) continue;

            const delta = choice.delta || {};

            // 1. Reasoning / Thinking delta
            const reasoningDelta = delta.reasoning_content || delta.reasoning;
            if (reasoningDelta) {
              if (currentBlockType !== "thinking") {
                closeCurrentBlock();
                currentBlockIndex++;
                currentBlockType = "thinking";
                emit("content_block_start", {
                  type: "content_block_start",
                  index: currentBlockIndex,
                  content_block: { type: "thinking", thinking: "" }
                });
              }
              emit("content_block_delta", {
                type: "content_block_delta",
                index: currentBlockIndex,
                delta: { type: "thinking_delta", thinking: reasoningDelta }
              });
            }

            // 2. Text content delta
            if (delta.content) {
              if (currentBlockType !== "text") {
                closeCurrentBlock();
                currentBlockIndex++;
                currentBlockType = "text";
                emit("content_block_start", {
                  type: "content_block_start",
                  index: currentBlockIndex,
                  content_block: { type: "text", text: "" }
                });
              }
              emit("content_block_delta", {
                type: "content_block_delta",
                index: currentBlockIndex,
                delta: { type: "text_delta", text: delta.content }
              });
            }

            // 3. Tool calls delta
            if (Array.isArray(delta.tool_calls)) {
              hasToolUse = true;
              for (const tc of delta.tool_calls) {
                const idx = tc.index ?? 0;
                if (!openAITools.has(idx)) {
                  const id = tc.id || `toolu_${Date.now()}_${idx}`;
                  const name = tc.function?.name || "";
                  if (currentBlockType !== "tool_use") {
                    closeCurrentBlock();
                    currentBlockIndex++;
                    currentBlockType = "tool_use";
                    activeOpenAIToolIdx = idx;
                    openAITools.set(idx, { id, name, args: "", emitted: true });
                    emit("content_block_start", {
                      type: "content_block_start",
                      index: currentBlockIndex,
                      content_block: { type: "tool_use", id, name, input: {} }
                    });
                  } else if (activeOpenAIToolIdx !== idx) {
                    // Tool mới xuất hiện trong khi tool cũ đang stream -> buffer lại
                    openAITools.set(idx, { id, name, args: "", emitted: false });
                  }
                } else {
                  const entry = openAITools.get(idx);
                  if (tc.id && !entry.id) entry.id = tc.id;
                  if (tc.function?.name && !entry.name) entry.name = tc.function.name;
                }

                const argChunk = tc.function?.arguments;
                if (argChunk) {
                  const entry = openAITools.get(idx);
                  if (entry.emitted && activeOpenAIToolIdx === idx) {
                    emit("content_block_delta", {
                      type: "content_block_delta",
                      index: currentBlockIndex,
                      delta: { type: "input_json_delta", partial_json: argChunk }
                    });
                  } else {
                    entry.args += argChunk;
                  }
                }
              }
            }

            if (choice.finish_reason) {
              if (choice.finish_reason === "tool_calls") finishReason = "tool_use";
              else if (choice.finish_reason === "length") finishReason = "max_tokens";
              else finishReason = "end_turn";
            }
          }
        }

        if (!isClosed()) {
          closeCurrentBlock();

          // Flush các tool call còn lại đã buffer
          for (const [, entry] of openAITools.entries()) {
            if (entry.emitted) continue;
            currentBlockIndex++;
            emit("content_block_start", {
              type: "content_block_start",
              index: currentBlockIndex,
              content_block: { type: "tool_use", id: entry.id, name: entry.name, input: {} }
            });
            if (entry.args) {
              emit("content_block_delta", {
                type: "content_block_delta",
                index: currentBlockIndex,
                delta: { type: "input_json_delta", partial_json: entry.args }
              });
            }
            emit("content_block_stop", { type: "content_block_stop", index: currentBlockIndex });
          }

          if (currentBlockIndex < 0) {
            emit("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
            emit("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "" } });
            emit("content_block_stop", { type: "content_block_stop", index: 0 });
          }

          emit("message_delta", {
            type: "message_delta",
            delta: { stop_reason: hasToolUse ? "tool_use" : finishReason, stop_sequence: null },
            usage: { input_tokens: inputTokens, output_tokens: outputTokens, cache_read_input_tokens: cachedTokens }
          });
          emit("message_stop", { type: "message_stop" });
        }
      } catch (err) {
        streamErr = err?.message || "Chat->Anthropic stream interrupted";
        if (!isClosed()) {
          emit("error", { type: "error", error: { type: "api_error", message: streamErr } });
        }
      } finally {
        onFinishUsage({ inputTokens, outputTokens, cachedTokens }, streamErr);
      }
    }
  });
}

async function collectResponsesFromSSE(reader, fallbackModel, abortController) {
  const decoder = new TextDecoder();
  let buffer = "";
  let completedResponse = null;
  let accumulatedText = "";
  let accumulatedReasoning = "";
  let model = fallbackModel;
  const callsById = new Map();

  try {
    while (true) {
      const { done, value } = await readWithTimeout(reader, CONFIG.STREAM_IDLE_TIMEOUT_MS);
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
        } catch {
          continue;
        }

        if (evt.response?.model) model = evt.response.model;
        if (evt.type === "response.completed" && evt.response) {
          completedResponse = evt.response;
        } else if (evt.type === "response.output_text.delta" && evt.delta) {
          accumulatedText += evt.delta;
        } else if ((evt.type === "response.reasoning_summary_text.delta" || evt.type === "response.reasoning_text.delta") && evt.delta) {
          accumulatedReasoning += evt.delta;
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
  } catch (err) {
    abortController?.abort(err);
  }

  if (completedResponse) return completedResponse;

  const output = [];
  if (accumulatedReasoning) {
    output.push({ type: "reasoning", summary: [{ type: "summary_text", text: accumulatedReasoning }] });
  }
  if (accumulatedText) {
    output.push({ type: "message", role: "assistant", content: [{ type: "output_text", text: accumulatedText }] });
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

function convertResponsesJsonToChatCompletion(data, fallbackModel) {
  let contentText = typeof data.output_text === "string" ? data.output_text : "";
  const reasoningParts = [];
  const toolCalls = [];

  if (Array.isArray(data.output)) {
    const textParts = [];
    for (const item of data.output) {
      if (item.type === "reasoning" && Array.isArray(item.summary)) {
        for (const s of item.summary) {
          if (s.text) reasoningParts.push(s.text);
        }
      } else if (item.type === "message" && Array.isArray(item.content)) {
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
  if (reasoningParts.length > 0) message.reasoning_content = reasoningParts.join("\n");
  if (toolCalls.length > 0) message.tool_calls = toolCalls;

  const u = extractResponsesUsage(data);
  return {
    id: data.id || `chatcmpl_${Date.now()}`,
    object: "chat.completion",
    created: data.created_at || Math.floor(Date.now() / 1000),
    model: data.model || fallbackModel,
    choices: [{ index: 0, message, finish_reason: toolCalls.length > 0 ? "tool_calls" : "stop" }],
    usage: {
      prompt_tokens: u.inputTokens,
      completion_tokens: u.outputTokens,
      total_tokens: u.inputTokens + u.outputTokens,
      prompt_tokens_details: { cached_tokens: u.cachedTokens }
    }
  };
}

function convertResponsesJsonToAnthropic(data, fallbackModel) {
  const content = [];
  let hasToolUse = false;

  if (Array.isArray(data.output)) {
    for (const item of data.output) {
      if (item.type === "reasoning" && Array.isArray(item.summary)) {
        const thinkText = item.summary.map((s) => s.text || "").filter(Boolean).join("\n");
        if (thinkText) content.push({ type: "thinking", thinking: thinkText });
      } else if (item.type === "message" && Array.isArray(item.content)) {
        for (const c of item.content) {
          if ((c.type === "output_text" || c.type === "text") && c.text) {
            content.push({ type: "text", text: c.text });
          }
        }
      } else if (item.type === "function_call") {
        hasToolUse = true;
        let parsedInput = {};
        try {
          parsedInput = typeof item.arguments === "string" ? JSON.parse(item.arguments || "{}") : item.arguments || {};
        } catch {
          // ignore
        }
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

  const u = extractResponsesUsage(data);
  return {
    id: data.id || `msg_${Date.now()}`,
    type: "message",
    role: "assistant",
    model: data.model || fallbackModel,
    content,
    stop_reason: hasToolUse ? "tool_use" : "end_turn",
    stop_sequence: null,
    usage: {
      input_tokens: u.inputTokens,
      output_tokens: u.outputTokens,
      cache_read_input_tokens: u.cachedTokens
    }
  };
}

function convertChatJsonToAnthropic(chat, fallbackModel) {
  const choice = chat.choices?.[0] || {};
  const msg = choice.message || {};
  const content = [];

  if (msg.reasoning_content) {
    content.push({ type: "thinking", thinking: msg.reasoning_content });
  }
  if (msg.content) {
    content.push({ type: "text", text: msg.content });
  }
  if (Array.isArray(msg.tool_calls)) {
    for (const tc of msg.tool_calls) {
      let input = {};
      try {
        input = JSON.parse(tc.function?.arguments || "{}");
      } catch {
        // ignore
      }
      content.push({ type: "tool_use", id: tc.id || `toolu_${Date.now()}`, name: tc.function?.name || "", input });
    }
  }
  if (content.length === 0) content.push({ type: "text", text: "" });

  const u = extractChatUsage(chat);
  let stopReason = "end_turn";
  if (msg.tool_calls?.length || choice.finish_reason === "tool_calls") stopReason = "tool_use";
  else if (choice.finish_reason === "length") stopReason = "max_tokens";

  return {
    id: chat.id || `msg_${Date.now()}`,
    type: "message",
    role: "assistant",
    model: chat.model || fallbackModel,
    content,
    stop_reason: stopReason,
    stop_sequence: null,
    usage: {
      input_tokens: u.inputTokens,
      output_tokens: u.outputTokens,
      cache_read_input_tokens: u.cachedTokens
    }
  };
}

// ============================================================================
// MODELS ROUTE (ISOLATE + OPTIONAL KV CACHE + ALIASES)
// ============================================================================
async function handleModelsRoute(request, env, ctx, url, upstreamConfig, modelAliases) {
  const bypassCache = url.searchParams.get("refresh") === "1";

  if (!bypassCache && modelsCache.payload && Date.now() < modelsCache.expiresAt) {
    return jsonResponse(modelsCache.payload, 200, { "X-Cache": "HIT-ISOLATE" });
  }

  if (!bypassCache && env.GATEWAY_KV) {
    try {
      const kvCached = await env.GATEWAY_KV.get("models_cache_v3", "json");
      if (kvCached && Array.isArray(kvCached.data)) {
        modelsCache = { expiresAt: Date.now() + CONFIG.MODELS_CACHE_TTL_MS, payload: kvCached };
        return jsonResponse(kvCached, 200, { "X-Cache": "HIT-KV" });
      }
    } catch {
      // ignore KV error
    }
  }

  const fetchPromises = upstreamConfig.map(async (upstream) => {
    const keys = Array.isArray(upstream.keys) ? upstream.keys.filter(Boolean) : [];
    if (keys.length === 0) return fallbackStaticModels(upstream, upstreamConfig.length);

    const ordered = selectOrderedKeys(upstream.name, keys, Math.floor(Math.random() * 1000));
    const chosen = ordered[0];
    const targetModelsUrl = `${upstream.baseUrl.replace(/\/+$/, "")}/models`;
    const headers = buildCleanHeaders(request.headers, chosen.apiKey, false, upstream);

    try {
      const res = await fetchWithTimeout(targetModelsUrl, { method: "GET", headers }, CONFIG.MODELS_TIMEOUT_MS);
      if (res.ok) {
        const rawData = await res.json();
        const rawList = Array.isArray(rawData) ? rawData : (rawData && Array.isArray(rawData.data) ? rawData.data : []);
        return rawList.filter((m) => m && m.id).map((m) => {
          const baseId = String(m.id).replace(/\s*\(.*?\)/g, "").trim();
          const displayId = upstreamConfig.length > 1 ? `${baseId} (${upstream.name})` : baseId;
          return { ...m, id: displayId, owned_by: upstream.name };
        });
      }
    } catch {
      // fallback static
    }
    return fallbackStaticModels(upstream, upstreamConfig.length);
  });

  const results = await Promise.allSettled(fetchPromises);
  const finalModels = [];

  // Đưa Model Aliases lên đầu danh sách
  for (const [alias, target] of Object.entries(modelAliases)) {
    finalModels.push({ id: alias, object: "model", owned_by: `alias -> ${target}` });
  }
  for (const r of results) {
    if (r.status === "fulfilled" && Array.isArray(r.value)) {
      finalModels.push(...r.value);
    }
  }

  const uniqueModels = Array.from(new Map(finalModels.map((item) => [item.id, item])).values());
  const payload = { object: "list", data: uniqueModels };

  if (uniqueModels.length > 0) {
    modelsCache = { expiresAt: Date.now() + CONFIG.MODELS_CACHE_TTL_MS, payload };
    if (env.GATEWAY_KV) {
      ctx.waitUntil(
        env.GATEWAY_KV.put("models_cache_v3", JSON.stringify(payload), {
          expirationTtl: Math.max(60, Math.floor(CONFIG.MODELS_CACHE_TTL_MS / 1000))
        }).catch(() => {})
      );
    }
  }

  return jsonResponse(payload, 200, { "X-Cache": "MISS" });
}

// ============================================================================
// AUTHENTICATION & VIRTUAL KEY RPM CHECK
// ============================================================================
async function authenticateRequest(clientKey, env) {
  const hasMasterAuth = Boolean(env.WORKER_AUTH_KEY);
  const masterKeys = hasMasterAuth
    ? String(env.WORKER_AUTH_KEY).split(",").map((k) => k.trim()).filter(Boolean)
    : [];

  if (clientKey && masterKeys.includes(clientKey)) {
    return { ok: true, keyLabel: "master" };
  }

  // Kiểm tra Virtual Keys (nếu có cấu hình trong DO hoặc env)
  if (clientKey && localState.virtualKeys && localState.virtualKeys[clientKey]) {
    const vk = localState.virtualKeys[clientKey];
    if (!vk.enabled) {
      return { ok: false, status: 403, type: "authentication_error", message: "Virtual API Key đã bị khóa." };
    }
    if (vk.rpm > 0) {
      const rpmOk = await checkVirtualKeyRpm(env, clientKey, vk.rpm);
      if (!rpmOk) {
        return { ok: false, status: 429, type: "rate_limit_error", message: `Vượt giới hạn ${vk.rpm} RPM cho Virtual Key '${vk.name}'.` };
      }
    }
    return { ok: true, keyLabel: `vk:${vk.name}` };
  }

  if (!hasMasterAuth && Object.keys(localState.virtualKeys || {}).length === 0) {
    return { ok: true, keyLabel: "open" };
  }

  return { ok: false, status: 401, type: "authentication_error", message: "Unauthorized: Invalid Worker or Virtual API Key" };
}

function getAdminSecret(env) {
  if (env.ADMIN_KEY) return String(env.ADMIN_KEY).trim();
  if (env.WORKER_AUTH_KEY) return String(env.WORKER_AUTH_KEY).split(",")[0].trim();
  return "";
}

// ============================================================================
// DURABLE OBJECT COMMUNICATION & LOCAL MIRROR
// ============================================================================
function getDOStub(env) {
  if (!env.GATEWAY_STATE) return null;
  const id = env.GATEWAY_STATE.idFromName("global-gateway-v3");
  return env.GATEWAY_STATE.get(id);
}

async function syncLocalStateFromDO(env, force = false) {
  const stub = getDOStub(env);
  if (!stub) return;
  if (!force && Date.now() - localState.syncedAt < CONFIG.STATE_SYNC_TTL_MS) return;

  try {
    const res = await stub.fetch("https://do.internal/snapshot");
    if (res.ok) {
      const snap = await res.json();
      localState.keyHealth = snap.keyHealth || {};
      localState.stats = snap.stats || localState.stats;
      localState.virtualKeys = snap.virtualKeys || {};
      localState.logs = snap.logs || [];
      localState.syncedAt = Date.now();
    }
  } catch {
    // fallback dùng localState hiện tại
  }
}

async function checkVirtualKeyRpm(env, token, rpmLimit) {
  const stub = getDOStub(env);
  if (!stub) return true; // không có DO thì cho qua
  try {
    const res = await stub.fetch("https://do.internal/check-rpm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, rpmLimit })
    });
    if (res.ok) {
      const data = await res.json();
      return Boolean(data.allowed);
    }
  } catch {
    // fail-open
  }
  return true;
}

function reportKeyOutcome(env, ctx, payload) {
  // Cập nhật ngay local mirror để request tiếp theo trong isolate thấy liền
  applyKeyOutcomeToState(localState, payload);

  const stub = getDOStub(env);
  if (stub && ctx) {
    ctx.waitUntil(
      stub.fetch("https://do.internal/report-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }).catch(() => {})
    );
  }
}

function recordRequestLog(env, ctx, entry) {
  applyLogToState(localState, entry);

  const stub = getDOStub(env);
  if (stub && ctx) {
    ctx.waitUntil(
      stub.fetch("https://do.internal/report-log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry)
      }).catch(() => {})
    );
  }
}

function applyKeyOutcomeToState(target, p) {
  if (!p?.keyId) return;
  const now = Date.now();
  const cur = target.keyHealth[p.keyId] || {
    keyId: p.keyId,
    upstream: p.upstream || "unknown",
    keyMask: p.keyMask || "***",
    okCount: 0,
    errCount: 0,
    consecutiveErrors: 0,
    ewmaTtfbMs: 0,
    cooldownUntil: 0,
    lastStatus: 0,
    lastError: "",
    updatedAt: now
  };

  cur.updatedAt = now;
  if (p.upstream) cur.upstream = p.upstream;
  if (p.keyMask) cur.keyMask = p.keyMask;

  if (p.ok) {
    cur.okCount += 1;
    cur.consecutiveErrors = 0;
    cur.cooldownUntil = 0;
    cur.lastStatus = 200;
    cur.lastError = "";
    if (typeof p.ttfbMs === "number" && p.ttfbMs > 0) {
      cur.ewmaTtfbMs = cur.ewmaTtfbMs
        ? Math.round(CONFIG.EWMA_ALPHA * p.ttfbMs + (1 - CONFIG.EWMA_ALPHA) * cur.ewmaTtfbMs)
        : Math.round(p.ttfbMs);
    }
  } else {
    cur.errCount += 1;
    cur.consecutiveErrors += 1;
    cur.lastStatus = p.status || 500;
    cur.lastError = String(p.error || "Unknown error").slice(0, 140);
    const baseCd = p.cooldownMs || CONFIG.COOLDOWN_TRANSIENT_BASE_MS;
    const multiplier = Math.min(Math.pow(2, Math.max(0, cur.consecutiveErrors - 1)), 8);
    const finalCd = p.status === 401 || p.status === 403 ? baseCd : Math.min(baseCd * multiplier, 30 * 60 * 1000);
    cur.cooldownUntil = Math.max(cur.cooldownUntil, now + finalCd);
  }

  target.keyHealth[p.keyId] = cur;
}

function applyLogToState(target, entry) {
  target.stats.requests += 1;
  if (entry.status >= 200 && entry.status < 300 && !entry.error) {
    target.stats.success += 1;
  } else {
    target.stats.errors += 1;
  }
  target.stats.failovers += entry.failovers || 0;
  target.stats.inputTokens += entry.inputTokens || 0;
  target.stats.outputTokens += entry.outputTokens || 0;
  target.stats.cachedTokens += entry.cachedTokens || 0;

  target.logs.unshift(entry);
  if (target.logs.length > CONFIG.MAX_RECENT_LOGS) {
    target.logs.length = CONFIG.MAX_RECENT_LOGS;
  }
}

// ============================================================================
// DURABLE OBJECT CLASS: GatewayState
// ============================================================================
export class GatewayState {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.loaded = false;
    this.dirty = false;
    this.lastFlushAt = 0;
    this.data = {
      keyHealth: {},
      stats: { requests: 0, success: 0, errors: 0, failovers: 0, inputTokens: 0, outputTokens: 0, cachedTokens: 0 },
      virtualKeys: {},
      logs: []
    };
    this.rpmBuckets = new Map(); // token -> timestamps[]
  }

  async ensureLoaded() {
    if (this.loaded) return;
    const saved = await this.state.storage.get("gateway_state_v3");
    if (saved && typeof saved === "object") {
      this.data = {
        keyHealth: saved.keyHealth || {},
        stats: saved.stats || this.data.stats,
        virtualKeys: saved.virtualKeys || {},
        logs: Array.isArray(saved.logs) ? saved.logs : []
      };
    }
    this.loaded = true;
  }

  async flushIfNeeded(force = false) {
    if (!this.dirty && !force) return;
    const now = Date.now();
    if (force || now - this.lastFlushAt > 5000) {
      this.dirty = false;
      this.lastFlushAt = now;
      await this.state.storage.put("gateway_state_v3", this.data);
    }
  }

  async fetch(request) {
    await this.ensureLoaded();
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/snapshot" && request.method === "GET") {
      return Response.json(this.data);
    }

    if (path === "/report-key" && request.method === "POST") {
      const payload = await request.json();
      applyKeyOutcomeToState(this.data, payload);
      this.dirty = true;
      await this.flushIfNeeded(false);
      return Response.json({ ok: true });
    }

    if (path === "/report-log" && request.method === "POST") {
      const entry = await request.json();
      applyLogToState(this.data, entry);
      this.dirty = true;
      await this.flushIfNeeded(false);
      return Response.json({ ok: true });
    }

    if (path === "/check-rpm" && request.method === "POST") {
      const { token, rpmLimit } = await request.json();
      const now = Date.now();
      const cutoff = now - 60000;
      const arr = (this.rpmBuckets.get(token) || []).filter((t) => t > cutoff);
      if (arr.length >= rpmLimit) {
        this.rpmBuckets.set(token, arr);
        return Response.json({ allowed: false, current: arr.length });
      }
      arr.push(now);
      this.rpmBuckets.set(token, arr);
      return Response.json({ allowed: true, current: arr.length });
    }

    if (path === "/reset-key" && request.method === "POST") {
      const { keyId } = await request.json();
      if (keyId === "ALL") {
        for (const k of Object.values(this.data.keyHealth)) {
          k.cooldownUntil = 0;
          k.consecutiveErrors = 0;
          k.lastError = "";
        }
      } else if (this.data.keyHealth[keyId]) {
        this.data.keyHealth[keyId].cooldownUntil = 0;
        this.data.keyHealth[keyId].consecutiveErrors = 0;
        this.data.keyHealth[keyId].lastError = "";
      }
      await this.flushIfNeeded(true);
      return Response.json({ ok: true });
    }

    if (path === "/virtual-keys" && request.method === "POST") {
      const body = await request.json();
      if (body.action === "create") {
        const token = `sk-gw-${crypto.randomUUID().replace(/-/g, "").slice(0, 24)}`;
        this.data.virtualKeys[token] = {
          name: String(body.name || "client").slice(0, 40),
          rpm: Math.max(0, Number(body.rpm || 0)),
          enabled: true,
          createdAt: Date.now()
        };
        await this.flushIfNeeded(true);
        return Response.json({ ok: true, token });
      }
      if (body.action === "toggle" && this.data.virtualKeys[body.token]) {
        this.data.virtualKeys[body.token].enabled = !this.data.virtualKeys[body.token].enabled;
        await this.flushIfNeeded(true);
        return Response.json({ ok: true });
      }
      if (body.action === "delete" && this.data.virtualKeys[body.token]) {
        delete this.data.virtualKeys[body.token];
        await this.flushIfNeeded(true);
        return Response.json({ ok: true });
      }
      return Response.json({ ok: false, error: "Invalid action" }, { status: 400 });
    }

    if (path === "/clear-stats" && request.method === "POST") {
      this.data.stats = { requests: 0, success: 0, errors: 0, failovers: 0, inputTokens: 0, outputTokens: 0, cachedTokens: 0 };
      this.data.logs = [];
      await this.flushIfNeeded(true);
      return Response.json({ ok: true });
    }

    return new Response("Not Found", { status: 404 });
  }
}

// ============================================================================
// ADMIN ROUTES & BUILT-IN DASHBOARD (/admin)
// ============================================================================
async function handleAdminRoute(request, env, url, rawPath) {
  if (rawPath === "/admin" && request.method === "GET") {
    return new Response(renderAdminHTML(), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
    });
  }

  // Bảo vệ toàn bộ /admin/api/* bằng ADMIN_KEY (hoặc WORKER_AUTH_KEY đầu tiên)
  const adminSecret = getAdminSecret(env);
  const provided = extractClientApiKey(request) || url.searchParams.get("key") || "";
  if (adminSecret && provided !== adminSecret) {
    return jsonResponse({ error: "Unauthorized Admin Key" }, 401);
  }

  const stub = getDOStub(env);

  if (rawPath === "/admin/api/state" && request.method === "GET") {
    await syncLocalStateFromDO(env, true);
    const parsedCfg = parseUpstreamConfig(env.UPSTREAM_CONFIG);
    const upstreams = (parsedCfg.data || []).map((u) => ({
      name: u.name,
      apiType: resolveApiType(u),
      priority: u.priority ?? 100,
      keysCount: Array.isArray(u.keys) ? u.keys.length : 0,
      fallbacks: u.fallbackUpstreams || [],
      keys: (Array.isArray(u.keys) ? u.keys.filter(Boolean) : []).map((k) => {
        const keyId = makeKeyId(u.name, k);
        const h = localState.keyHealth[keyId] || {};
        return {
          keyId,
          upstream: u.name,
          keyMask: maskApiKey(k),
          okCount: h.okCount || 0,
          errCount: h.errCount || 0,
          ewmaTtfbMs: h.ewmaTtfbMs || 0,
          cooldownUntil: h.cooldownUntil || 0,
          lastStatus: h.lastStatus || 0,
          lastError: h.lastError || ""
        };
      })
    }));

    return jsonResponse({
      version: CONFIG.VERSION,
      now: Date.now(),
      storageMode: stub ? "Durable Object (Global)" : "Isolate Memory (Local)",
      kvEnabled: Boolean(env.GATEWAY_KV),
      aliases: parseModelAliases(env.MODEL_ALIASES),
      upstreams,
      stats: localState.stats,
      virtualKeys: localState.virtualKeys,
      logs: localState.logs
    });
  }

  if (rawPath === "/admin/api/reset-key" && request.method === "POST") {
    const body = await request.json();
    if (stub) {
      await stub.fetch("https://do.internal/reset-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    } else {
      if (body.keyId === "ALL") {
        for (const k of Object.values(localState.keyHealth)) {
          k.cooldownUntil = 0;
          k.consecutiveErrors = 0;
          k.lastError = "";
        }
      } else if (localState.keyHealth[body.keyId]) {
        localState.keyHealth[body.keyId].cooldownUntil = 0;
        localState.keyHealth[body.keyId].consecutiveErrors = 0;
        localState.keyHealth[body.keyId].lastError = "";
      }
    }
    await syncLocalStateFromDO(env, true);
    return jsonResponse({ ok: true });
  }

  if (rawPath === "/admin/api/virtual-keys" && request.method === "POST") {
    const body = await request.json();
    if (stub) {
      const r = await stub.fetch("https://do.internal/virtual-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await r.json();
      await syncLocalStateFromDO(env, true);
      return jsonResponse(data, r.status);
    }
    if (body.action === "create") {
      const token = `sk-gw-${crypto.randomUUID().replace(/-/g, "").slice(0, 24)}`;
      localState.virtualKeys[token] = { name: String(body.name || "client"), rpm: Math.max(0, Number(body.rpm || 0)), enabled: true, createdAt: Date.now() };
      return jsonResponse({ ok: true, token });
    }
    if (body.action === "toggle" && localState.virtualKeys[body.token]) {
      localState.virtualKeys[body.token].enabled = !localState.virtualKeys[body.token].enabled;
      return jsonResponse({ ok: true });
    }
    if (body.action === "delete") {
      delete localState.virtualKeys[body.token];
      return jsonResponse({ ok: true });
    }
    return jsonResponse({ ok: false }, 400);
  }

  if (rawPath === "/admin/api/clear-stats" && request.method === "POST") {
    if (stub) {
      await stub.fetch("https://do.internal/clear-stats", { method: "POST" });
    } else {
      localState.stats = { requests: 0, success: 0, errors: 0, failovers: 0, inputTokens: 0, outputTokens: 0, cachedTokens: 0 };
      localState.logs = [];
    }
    await syncLocalStateFromDO(env, true);
    return jsonResponse({ ok: true });
  }

  return jsonResponse({ error: "Not Found" }, 404);
}

function renderAdminHTML() {
  return `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Gateway v3.0 — Admin Dashboard</title>
<style>
  :root { --bg:#0b0f17; --card:#121826; --border:#1f2937; --text:#e5e7eb; --muted:#9ca3af; --accent:#3b82f6; --green:#10b981; --yellow:#f59e0b; --red:#ef4444; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:ui-sans-serif,system-ui,-apple-system,sans-serif; background:var(--bg); color:var(--text); font-size:14px; }
  header { display:flex; justify-content:space-between; align-items:center; padding:14px 24px; background:var(--card); border-bottom:1px solid var(--border); flex-wrap:wrap; gap:12px; }
  h1 { margin:0; font-size:18px; display:flex; align-items:center; gap:10px; }
  .badge { font-size:11px; padding:3px 8px; border-radius:999px; font-weight:600; background:#1e293b; color:#93c5fd; }
  .badge.ok { background:#064e3b; color:#6ee7b7; }
  .badge.warn { background:#78350f; color:#fcd34d; }
  .badge.err { background:#7f1d1d; color:#fca5a5; }
  main { max-width:1360px; margin:0 auto; padding:20px; display:grid; gap:20px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:16px; }
  .stat-label { color:var(--muted); font-size:12px; margin-bottom:6px; }
  .stat-val { font-size:24px; font-weight:700; }
  .stat-sub { color:var(--muted); font-size:12px; margin-top:4px; }
  .section-head { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:10px; }
  .section-head h2 { margin:0; font-size:15px; }
  button { background:#1f2937; color:var(--text); border:1px solid #374151; padding:6px 12px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:600; }
  button:hover { background:#374151; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  button.danger { background:#7f1d1d; border-color:#991b1b; color:#fecaca; }
  input { background:#0f172a; color:var(--text); border:1px solid #334155; padding:7px 10px; border-radius:6px; font-size:13px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
  .table-wrap { overflow-x:auto; }
  #loginBox { max-width:380px; margin:100px auto; text-align:center; }
  .row-actions { display:flex; gap:6px; }
  .hidden { display:none !important; }
</style>
</head>
<body>
<div id="loginBox" class="card">
  <h2 style="margin-top:0">AI Gateway v3.0 Admin</h2>
  <p style="color:var(--muted);font-size:13px">Nhập <b>ADMIN_KEY</b> (hoặc WORKER_AUTH_KEY) để đăng nhập.</p>
  <input id="adminKeyInput" type="password" placeholder="Admin Key..." style="width:100%;margin-bottom:12px">
  <button class="primary" style="width:100%;padding:9px" onclick="doLogin()">Đăng nhập</button>
  <p id="loginErr" style="color:var(--red);font-size:12px"></p>
</div>

<div id="app" class="hidden">
  <header>
    <h1>⚡ AI Gateway <span id="verBadge" class="badge">v3.0</span> <span id="storageBadge" class="badge">...</span></h1>
    <div class="row-actions">
      <button onclick="loadState()">↻ Làm mới</button>
      <button onclick="resetKey('ALL')">Mở khóa tất cả Key</button>
      <button class="danger" onclick="clearStats()">Xóa Logs/Stats</button>
      <button onclick="logout()">Thoát</button>
    </div>
  </header>

  <main>
    <div class="grid">
      <div class="card"><div class="stat-label">Tổng Requests</div><div class="stat-val" id="stReq">0</div><div class="stat-sub" id="stRate">Success: 100%</div></div>
      <div class="card"><div class="stat-label">Failovers đã cứu</div><div class="stat-val" id="stFailover">0</div><div class="stat-sub" id="stErr">Errors: 0</div></div>
      <div class="card"><div class="stat-label">Input / Output Tokens</div><div class="stat-val" id="stTok">0</div><div class="stat-sub" id="stCache">Cached: 0</div></div>
      <div class="card"><div class="stat-label">API Keys</div><div class="stat-val" id="stKeys">0/0</div><div class="stat-sub" id="stKv">KV Cache: Off</div></div>
    </div>

    <div class="card">
      <div class="section-head">
        <h2>🔑 Sức khỏe Key & Circuit Breaker</h2>
        <span style="color:var(--muted);font-size:12px">Tự làm mới mỗi 5 giây</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Upstream</th><th>Key</th><th>Trạng thái</th><th>EWMA TTFB</th><th>OK / Lỗi</th><th>Lỗi gần nhất</th><th>Thao tác</th></tr></thead>
          <tbody id="keysTbody"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="section-head">
        <h2>🎟️ Virtual Keys & Giới hạn RPM</h2>
        <div class="row-actions">
          <input id="vkName" placeholder="Tên máy / App (vd: OpenCode)">
          <input id="vkRpm" type="number" min="0" value="30" style="width:90px" title="0 = không giới hạn">
          <button class="primary" onclick="createVK()">+ Tạo Key</button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Tên</th><th>Virtual Token</th><th>RPM Limit</th><th>Trạng thái</th><th>Thao tác</th></tr></thead>
          <tbody id="vkTbody"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="section-head"><h2>📜 Request Logs gần nhất (100 dòng)</h2></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Thời gian</th><th>Client</th><th>Model</th><th>Upstream</th><th>Key</th><th>Status</th><th>TTFB</th><th>Tokens (In/Out/Cache)</th><th>Mode / Lỗi</th></tr></thead>
          <tbody id="logsTbody"></tbody>
        </table>
      </div>
    </div>
  </main>
</div>

<script>
let ADMIN_KEY = sessionStorage.getItem("gw_admin_key") || "";
let pollTimer = null;

function esc(s){ return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function fmtNum(n){ return Number(n||0).toLocaleString("en-US"); }

async function apiFetch(path, opts = {}) {
  const headers = Object.assign({ "Authorization": "Bearer " + ADMIN_KEY, "Content-Type": "application/json" }, opts.headers || {});
  return fetch(path, Object.assign({}, opts, { headers }));
}

async function doLogin() {
  ADMIN_KEY = document.getElementById("adminKeyInput").value.trim();
  const ok = await loadState();
  if (ok) {
    sessionStorage.setItem("gw_admin_key", ADMIN_KEY);
    document.getElementById("loginBox").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");
    if (!pollTimer) pollTimer = setInterval(loadState, 5000);
  } else {
    document.getElementById("loginErr").textContent = "Sai Admin Key hoặc lỗi kết nối.";
  }
}

function logout() {
  sessionStorage.removeItem("gw_admin_key");
  ADMIN_KEY = "";
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  location.reload();
}

async function loadState() {
  try {
    const res = await apiFetch("/admin/api/state");
    if (!res.ok) return false;
    const d = await res.json();
    renderState(d);
    return true;
  } catch { return false; }
}

function renderState(d) {
  document.getElementById("verBadge").textContent = "v" + d.version;
  document.getElementById("storageBadge").textContent = d.storageMode;
  const st = d.stats || {};
  const rate = st.requests ? ((st.success / st.requests) * 100).toFixed(1) : "100.0";
  document.getElementById("stReq").textContent = fmtNum(st.requests);
  document.getElementById("stRate").textContent = "Success: " + rate + "%";
  document.getElementById("stFailover").textContent = fmtNum(st.failovers);
  document.getElementById("stErr").textContent = "Errors: " + fmtNum(st.errors);
  document.getElementById("stTok").textContent = fmtNum((st.inputTokens||0) + (st.outputTokens||0));
  document.getElementById("stCache").textContent = "In: " + fmtNum(st.inputTokens) + " | Out: " + fmtNum(st.outputTokens) + " | Cache: " + fmtNum(st.cachedTokens);
  document.getElementById("stKv").textContent = "KV Cache: " + (d.kvEnabled ? "ON" : "OFF");

  let totalKeys = 0, healthyKeys = 0;
  const keyRows = [];
  for (const u of d.upstreams || []) {
    for (const k of u.keys || []) {
      totalKeys++;
      const rem = Math.max(0, Math.ceil((k.cooldownUntil - d.now) / 1000));
      let badge = '<span class="badge ok">HEALTHY</span>';
      if (rem > 0) {
        badge = rem > 300 ? '<span class="badge err">DEAD (' + Math.ceil(rem/60) + 'm)</span>' : '<span class="badge warn">COOLDOWN (' + rem + 's)</span>';
      } else { healthyKeys++; }
      keyRows.push('<tr><td><b>' + esc(u.name) + '</b> <span class="badge">' + esc(u.apiType) + '</span></td>'
        + '<td class="mono">' + esc(k.keyMask) + '</td><td>' + badge + '</td>'
        + '<td class="mono">' + (k.ewmaTtfbMs ? k.ewmaTtfbMs + 'ms' : '-') + '</td>'
        + '<td class="mono">' + k.okCount + ' / ' + k.errCount + '</td>'
        + '<td style="color:var(--muted);max-width:260px;overflow:hidden;text-overflow:ellipsis">' + esc(k.lastError || '-') + '</td>'
        + '<td><button onclick="resetKey(\\'' + esc(k.keyId) + '\\')">Unblock</button></td></tr>');
    }
  }
  document.getElementById("stKeys").textContent = healthyKeys + " / " + totalKeys + " sống";
  document.getElementById("keysTbody").innerHTML = keyRows.join("") || '<tr><td colspan="7" style="color:var(--muted)">Chưa có key nào</td></tr>';

  const vkRows = [];
  for (const [token, vk] of Object.entries(d.virtualKeys || {})) {
    vkRows.push('<tr><td><b>' + esc(vk.name) + '</b></td>'
      + '<td class="mono">' + esc(token) + ' <button onclick="navigator.clipboard.writeText(\\'' + esc(token) + '\\')">Copy</button></td>'
      + '<td class="mono">' + (vk.rpm > 0 ? vk.rpm + ' / phút' : 'Không giới hạn') + '</td>'
      + '<td>' + (vk.enabled ? '<span class="badge ok">ACTIVE</span>' : '<span class="badge err">DISABLED</span>') + '</td>'
      + '<td class="row-actions"><button onclick="vkAction(\\'toggle\\',\\'' + esc(token) + '\\')">Bật/Tắt</button>'
      + '<button class="danger" onclick="vkAction(\\'delete\\',\\'' + esc(token) + '\\')">Xóa</button></td></tr>');
  }
  document.getElementById("vkTbody").innerHTML = vkRows.join("") || '<tr><td colspan="5" style="color:var(--muted)">Chưa tạo Virtual Key nào</td></tr>';

  const logRows = (d.logs || []).map((l) => {
    const t = new Date(l.ts).toLocaleTimeString("vi-VN");
    const stBadge = l.status >= 200 && l.status < 300 && !l.error
      ? '<span class="badge ok">' + l.status + '</span>'
      : '<span class="badge err">' + l.status + '</span>';
    return '<tr><td class="mono">' + t + '</td><td>' + esc(l.client) + '</td><td class="mono">' + esc(l.model) + '</td>'
      + '<td>' + esc(l.upstream) + (l.failovers ? ' <span class="badge warn">+' + l.failovers + ' retry</span>' : '') + '</td>'
      + '<td class="mono">' + esc(l.keyMask) + '</td><td>' + stBadge + '</td>'
      + '<td class="mono">' + (l.ttfbMs || 0) + 'ms</td>'
      + '<td class="mono">' + fmtNum(l.inputTokens) + ' / ' + fmtNum(l.outputTokens) + ' / ' + fmtNum(l.cachedTokens) + '</td>'
      + '<td style="color:var(--muted)">' + esc(l.error || l.mode) + '</td></tr>';
  });
  document.getElementById("logsTbody").innerHTML = logRows.join("") || '<tr><td colspan="9" style="color:var(--muted)">Chưa có request nào</td></tr>';
}

async function resetKey(keyId) {
  await apiFetch("/admin/api/reset-key", { method: "POST", body: JSON.stringify({ keyId }) });
  loadState();
}
async function createVK() {
  const name = document.getElementById("vkName").value.trim() || "client";
  const rpm = Number(document.getElementById("vkRpm").value || 0);
  await apiFetch("/admin/api/virtual-keys", { method: "POST", body: JSON.stringify({ action: "create", name, rpm }) });
  document.getElementById("vkName").value = "";
  loadState();
}
async function vkAction(action, token) {
  await apiFetch("/admin/api/virtual-keys", { method: "POST", body: JSON.stringify({ action, token }) });
  loadState();
}
async function clearStats() {
  if (!confirm("Xóa toàn bộ thống kê và logs?")) return;
  await apiFetch("/admin/api/clear-stats", { method: "POST" });
  loadState();
}

// Tự đăng nhập nếu đã có key trong sessionStorage hoặc server không đặt Admin Key
(async () => {
  const ok = await loadState();
  if (ok) {
    document.getElementById("loginBox").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");
    pollTimer = setInterval(loadState, 5000);
  }
})();
</script>
</body>
</html>`;
}

// ============================================================================
// UTILITY HELPERS
// ============================================================================
function extractResponsesUsage(resp) {
  const u = resp?.usage || {};
  return {
    inputTokens: u.input_tokens || 0,
    outputTokens: u.output_tokens || 0,
    cachedTokens: u.input_tokens_details?.cached_tokens || 0
  };
}

function extractChatUsage(chat) {
  const u = chat?.usage || {};
  return {
    inputTokens: u.prompt_tokens || 0,
    outputTokens: u.completion_tokens || 0,
    cachedTokens: u.prompt_tokens_details?.cached_tokens || 0
  };
}

function extractAnyUsage(obj) {
  if (!obj || typeof obj !== "object") return null;
  if (obj.response?.usage) return extractResponsesUsage(obj.response);
  const u = obj.usage || obj.message?.usage;
  if (!u) return null;
  return {
    inputTokens: u.input_tokens ?? u.prompt_tokens ?? 0,
    outputTokens: u.output_tokens ?? u.completion_tokens ?? 0,
    cachedTokens: u.cache_read_input_tokens ?? u.input_tokens_details?.cached_tokens ?? u.prompt_tokens_details?.cached_tokens ?? 0
  };
}

async function readWithTimeout(reader, timeoutMs) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Stream idle timeout (${timeoutMs}ms)`)), timeoutMs);
  });
  try {
    return await Promise.race([reader.read(), timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("Request timeout")), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

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
    const cleanJsonStr = String(envConfig).replace(/[\u201C\u201D]/g, '"').trim();
    const parsed = JSON.parse(cleanJsonStr);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      return { error: "UPSTREAM_CONFIG phải là mảng JSON không rỗng!" };
    }
    return { data: parsed };
  } catch {
    return { error: "Lỗi cú pháp JSON trong biến UPSTREAM_CONFIG!" };
  }
}

function fallbackStaticModels(upstream, totalUpstreams) {
  if (!Array.isArray(upstream.models) || upstream.models.length === 0) return [];
  return upstream.models.map((id) => ({
    id: totalUpstreams > 1 ? `${id} (${upstream.name})` : id,
    object: "model",
    owned_by: upstream.name
  }));
}

function buildCleanHeaders(incomingHeaders, apiKey, hasBody = true, upstream = null) {
  const headers = new Headers();
  const skip = new Set([
    "host", "authorization", "x-api-key", "anthropic-api-key",
    "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "cf-ew-via", "cdn-loop",
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip",
    "content-length", "accept-encoding", "connection"
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

  // Hỗ trợ cả upstream chuẩn OpenAI (Bearer) và upstream chuẩn Anthropic native (x-api-key)
  if (resolveApiType(upstream) === "anthropic") {
    headers.set("x-api-key", apiKey);
    if (!headers.has("anthropic-version")) headers.set("anthropic-version", "2023-06-01");
  } else {
    headers.set("Authorization", `Bearer ${apiKey}`);
  }

  // Custom headers theo từng upstream (nếu có)
  if (upstream?.headers && typeof upstream.headers === "object") {
    for (const [k, v] of Object.entries(upstream.headers)) {
      headers.set(k, String(v));
    }
  }

  headers.set("Accept-Encoding", "identity");
  if (hasBody && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return headers;
}

function passthroughResponse(response, isEventStream, extraHeaders = {}) {
  const outHeaders = new Headers(response.headers);
  applyCors(outHeaders);
  for (const [k, v] of Object.entries(extraHeaders)) outHeaders.set(k, v);
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

function jsonResponse(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS, ...extraHeaders }
  });
}

function extractClientApiKey(request) {
  const auth = request.headers.get("authorization") || "";
  if (/^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, "").trim();
  const xKey = request.headers.get("x-api-key") || request.headers.get("anthropic-api-key");
  return xKey ? xKey.trim() : "";
}

function extractPlainText(content) {
  if (content === null || content === undefined) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((c) => typeof c === "string" ? c : (c?.text ?? (typeof c?.content === "string" ? c.content : "")))
      .filter(Boolean)
      .join("\n");
  }
  return String(content);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
