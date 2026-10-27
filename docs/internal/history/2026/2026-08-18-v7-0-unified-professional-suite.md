# Arenyxa v7.0 Unified Professional Suite

## Baseline

This increment is based on `Arenyxa_v7.0_MITM_Professional_Hardened_Source.zip` and preserves the frozen startup visual baseline.

## Unified professional workspace

Arenyxa now exposes one top-level `Professional Suite` instead of duplicating separate top-level shells for Proxy, MITM, Intelligence Studio, Workflow and Automation.

The suite contains five capability domains:

1. Packet Intelligence
   - Browser/network capture and the packet-analysis runtime packet-intelligence workbench.
   - PCAP/PCAPNG, protocol tree/bytes, display filtering, reassembly-aware dissection, Follow Stream, Expert Information, hierarchy/conversation/endpoint/statistics and export capabilities remain available through the existing hardened backend.

2. Intercept & Debug
   - intercepting-proxy request/response interception and editing, HTTPS CONNECT MITM, local CA, HTTP history and explicit remote-listener boundary.
   - The broader professional rule/replay capabilities are shared with the MITM domain so HTTP-debugging-style map-local, map-remote, rewrite, block/allow, replay and TLS controls do not require duplicated proxy engines.

3. MITM Automation
   - Official mitmdump bridge with regular/local/WireGuard/TUN/SOCKS5/DNS/transparent/reverse/upstream modes.
   - HTTP/WebSocket/TCP/UDP/DNS flows, interception, client/server replay, map local/remote, header/body modification, block/allow rules, HTTP/2, HTTP/3, TLS/QUIC, streaming, addons, protobuf definitions and client certificates.

4. Web Extraction
   - SmartPath, data-source discovery, Selector Studio/self-healing, Browser Recorder, HTTP Request Builder, GraphQL/WebSocket/SSE inspection, data quality, browser profiles, templates and distributed workers.
   - This consolidates the strongest advanced structured-extraction extraction capabilities without creating a second scraping runtime.

5. Workflow Automation
   - Workflow Designer and scheduler/run automation share one nested professional domain.
   - Existing DAG execution, failure edges, retries, cancellation/resume, checkpoints, variables/secrets, debugging, plugins, database nodes and distributed workers remain the workflow foundation for workflow-automation automation.

## Architecture rule

Professional capabilities are organized by task rather than vendor branding. Vendor-inspired features must reuse common Arenyxa backends and domain models. New large professional functions go into the corresponding domain inside Professional Suite unless a genuinely independent runtime boundary requires a new workbench.

## Compatibility

The former page implementations remain source-level components and are embedded by the unified suite. This avoids rewriting hardened packet, proxy, MITM, extraction and workflow engines while removing duplicated top-level navigation.
