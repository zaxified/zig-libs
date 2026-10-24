// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-mcp` (modules/mcp/tools/bench.zig): times the
// official Rust MCP SDK, rmcp 3.7.0 (pinned by Cargo.toml/Cargo.lock), over the
// session bytes the Zig program writes into the directory given as the first
// argument, for the one workload named by the second, through its public API
// only (`ServerHandler` implemented by hand, no proc-macros). Prints one line:
// name, ns/op, result count (tab-separated). One op = one whole session
// (`initialize`, `notifications/initialized`, then 64 requests of one kind)
// served by `ServerHandler::serve` over `tokio::io::duplex` (the SDK's
// newline-delimited JSON framing, `transport-async-rw`) on in-memory bytes,
// until the client side's EOF, the responses collected in a buffer. The
// handler is built once; each op gets a fresh session.
//
//	tools_call_echo   tool `echo`, input schema {text: string, required},
//	                  output schema {echo: string}, structured result
//	tools_list_20     20 tools, small input schemas
//	resources_read    one static 1 KiB text resource
//	prompts_get       one prompt with one required argument
//	initialize_only   handshake + 64 pings
//
// count = the number of response lines + the number of `"isError":true`
// occurrences in them (the Zig module and the SDK order fields differently, so
// response bytes are not compared).
//
// A session that produced a JSON-RPC error is refused (as on the Zig side).
//
// Deviation from the Go side: rmcp 3.7.0 has no input/output schema validation
// on the stdio path (`get_tool` is consulted only by its streamable-HTTP
// server; nothing in the crate validates arguments or structured results), so
// tools_call_echo does not validate the arguments (`get_tool` is implemented
// anyway) and the handler reads `text` itself. Go's SDK does validate both.
//
// Runtime: tokio RUNTIME_FLAVOR (set below), the faster of current_thread and
// multi_thread on this machine (measured with MCP_RS_RT=current|multi, ns/op
// current vs multi: echo 810k/1096k, list_20 2413k/2809k, resources 803k/1041k,
// prompts 573k/903k, initialize_only 341k/605k).
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, GetPromptResult, JsonObject, ListPromptsResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, Prompt, PromptArgument, PromptMessage,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, Role, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RUNTIME_FLAVOR: &str = "current";

fn obj(v: Value) -> JsonObject {
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Echo,
    List20,
    Resource,
    Prompt,
    Init,
}

struct Bench {
    kind: Kind,
    tools: Vec<Tool>,
    text: String,
}

impl Bench {
    fn new(name: &str) -> Bench {
        let mut tools = Vec::new();
        let kind = match name {
            "tools_call_echo" => {
                let input = obj(json!({
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                }));
                let output = obj(json!({
                    "type": "object",
                    "properties": {"echo": {"type": "string"}},
                    "required": ["echo"],
                }));
                tools.push(
                    Tool::new("echo", "Echo the text back", Arc::new(input))
                        .with_raw_output_schema(Arc::new(output)),
                );
                Kind::Echo
            }
            "tools_list_20" => {
                let input = Arc::new(obj(json!({
                    "type": "object",
                    "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
                    "required": ["a"],
                })));
                for i in 0..20 {
                    tools.push(Tool::new(
                        format!("tool_{i:02}"),
                        format!("Small tool number {i}"),
                        input.clone(),
                    ));
                }
                Kind::List20
            }
            "resources_read" => Kind::Resource,
            "prompts_get" => Kind::Prompt,
            "initialize_only" => Kind::Init,
            _ => {
                eprintln!("unknown workload {name}");
                std::process::exit(2);
            }
        };
        Bench { kind, tools, text: "0123456789abcdef".repeat(64) }
    }
}

impl ServerHandler for Bench {
    fn get_info(&self) -> ServerConfig {
        let caps = match self.kind {
            Kind::Echo | Kind::List20 => ServerCapabilities::builder().enable_tools().build(),
            Kind::Resource => ServerCapabilities::builder().enable_resources().build(),
            Kind::Prompt => ServerCapabilities::builder().enable_prompts().build(),
            Kind::Init => ServerCapabilities::builder().build(),
        };
        ServerConfig::new(caps)
            .with_server_info(rmcp::model::Implementation::new("bench", "1.0.0"))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools.iter().find(|t| t.name == name).cloned()
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if self.kind == Kind::Echo {
            let text = request
                .arguments
                .as_ref()
                .and_then(|a| a.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let mut r = CallToolResult::structured(json!({ "echo": text }));
            // `structured` also adds the JSON text copy, as Go's SDK does; only
            // the explicit `isError:false` is dropped, as Go omits it.
            r.is_error = None;
            return Ok(r.into());
        }
        Ok(CallToolResult::success(vec![ContentBlock::text("ok")]).into())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new("file:///doc.txt", "doc").with_mime_type("text/plain")
        ]))
    }

    async fn read_resource(
        &self,
        _request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            self.text.clone(),
            "file:///doc.txt",
        )
        .with_mime_type("text/plain")])
        .into())
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(ListPromptsResult::with_all_items(vec![Prompt::new(
            "greet",
            Some("Greet someone"),
            Some(vec![PromptArgument::new("name").with_required(true)]),
        )]))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let name = request
            .arguments
            .as_ref()
            .and_then(|a| a.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            Role::User,
            format!("Hello, {name}!"),
        )])
        .into())
    }
}

fn count_lines(b: &[u8]) -> usize {
    b.iter().filter(|&&c| c == b'\n').count()
}

fn count_sub(b: &[u8], pat: &[u8]) -> usize {
    b.windows(pat.len()).filter(|w| *w == pat).count()
}

/// One op: one whole session. The client side keeps its end open until every
/// request has been answered (the SDK runs handlers concurrently and abandons
/// the ones in flight at EOF), then drops it.
async fn session(h: &Arc<Bench>, wire: &[u8], want: usize, out: &mut Vec<u8>) -> usize {
    let (mut c_w, s_r) = tokio::io::duplex(1 << 22);
    let (s_w, mut c_r) = tokio::io::duplex(1 << 22);
    c_w.write_all(wire).await.unwrap();
    let svc = h.clone().serve((s_r, s_w)).await.unwrap();
    out.clear();
    let mut buf = vec![0u8; 1 << 16];
    let mut got = 0;
    while got < want {
        let n = c_r.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got += count_lines(&buf[..n]);
        out.extend_from_slice(&buf[..n]);
    }
    drop(c_w);
    svc.waiting().await.unwrap();
    if count_sub(out, br#""error":{"#) != 0 {
        panic!("the SDK answered a JSON-RPC error");
    }
    count_lines(out) + count_sub(out, br#""isError":true"#)
}

fn time_it(mut f: impl FnMut() -> usize) -> (f64, usize) {
    let mut sink = 0usize;
    let mut n = 1u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            sink = sink.wrapping_add(f());
        }
        if t.elapsed() > Duration::from_millis(100) {
            break;
        }
        n *= 2;
    }
    let mut best = Duration::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = f();
        }
        best = best.min(t.elapsed());
    }
    std::hint::black_box(sink);
    (best.as_nanos() as f64 / n as f64, count)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: mcp_rs_field <work dir> <workload>");
        std::process::exit(2);
    }
    let (dir, name) = (&args[1], &args[2]);
    let wire = match std::fs::read(format!("{dir}/{name}.wire")) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    eprintln!("rmcp 3.7.0 (tokio 1.54.1, {RUNTIME_FLAVOR} runtime)");

    let h = Arc::new(Bench::new(name));
    let want = wire
        .split(|&c| c == b'\n')
        .filter(|l| count_sub(l, br#""id""#) > 0)
        .count();
    let flavor = std::env::var("MCP_RS_RT").unwrap_or_else(|_| RUNTIME_FLAVOR.into());
    let rt = if flavor.starts_with('m') {
        tokio::runtime::Builder::new_multi_thread().enable_time().build().unwrap()
    } else {
        tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap()
    };
    let mut out = Vec::new();
    let (ns, count) = time_it(|| rt.block_on(session(&h, &wire, want, &mut out)));
    println!("{name}\t{ns:.1}\t{count}");
}
