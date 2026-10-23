// SPDX-License-Identifier: MIT

//! Tests for the FastAPI-parity members of `Info`: `servers`, the named-schema
//! registry (`components.schemas` + `$ref`), further security schemes,
//! per-operation `security`, and `route_extras` (header/cookie parameters,
//! examples). Each new API has an exact-output (golden) test; the documents
//! also go through `validateOpenApi31`, and the negative tests pin the typed
//! errors (dangling `$ref`, conflicting schema name, unknown scheme, ...).

const std = @import("std");
const router = @import("router");
const oa = @import("root.zig");

const testing = std.testing;
const Generator = oa.Generator;

fn build(routes: []const router.Route, info: oa.Info) ![]u8 {
    return Generator.buildRoutes(testing.allocator, routes, info);
}

/// Parse `json` and run the conformance checker over it.
fn check(json: []const u8) oa.ConformanceError!void {
    const parsed = std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{}) catch unreachable;
    defer parsed.deinit();
    return oa.validateOpenApi31(testing.allocator, parsed.value);
}

const user_schema = "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"integer\"}}}";

test "servers + components/schemas: a model used by two routes is emitted once and referenced" {
    const routes = [_]router.Route{
        .{ .method = .post, .pattern = "/users", .doc = &.{
            .request_schema = oa.schemaRef("User"),
            .responses = &.{.{ .status = 201, .description = "Created", .schema = oa.schemaRef("User") }},
        } },
        .{ .method = .get, .pattern = "/users/:id", .doc = &.{
            .responses = &.{.{ .status = 200, .description = "The user", .schema = oa.schemaRef("User") }},
        } },
    };
    const json = try build(&routes, .{
        .title = "T",
        .version = "1",
        .servers = &.{
            .{ .url = "https://api.example.com", .description = "Production" },
            .{ .url = "http://localhost:8080" },
        },
        // The repeat has other whitespace but the same body: folded, no conflict.
        .schemas = &.{
            .{ .name = "User", .schema = user_schema },
            .{ .name = "User", .schema = "{ \"type\": \"object\", \"properties\": { \"id\": { \"type\": \"integer\" } } }" },
        },
    });
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        \\{"openapi":"3.1.0","info":{"title":"T","version":"1"},"servers":[{"url":"https://api.example.com","description":"Production"},{"url":"http://localhost:8080"}],"paths":{"/users":{"post":{"operationId":"post_users","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/User"}}},"required":true},"responses":{"201":{"description":"Created","content":{"application/json":{"schema":{"$ref":"#/components/schemas/User"}}}}}}},"/users/{id}":{"get":{"operationId":"get_users_id","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"The user","content":{"application/json":{"schema":{"$ref":"#/components/schemas/User"}}}}}}}},"components":{"schemas":{"User":{"type":"object","properties":{"id":{"type":"integer"}}}}}}
    , json);
    try check(json);
}

test "security: every scheme kind, document-wide and per-operation selection" {
    const routes = [_]router.Route{
        .{ .method = .get, .pattern = "/a" },
        .{ .method = .get, .pattern = "/b" },
    };
    const json = try build(&routes, .{
        .title = "T",
        .version = "1",
        .bearer_auth = true,
        .security_schemes = &.{
            .{ .name = "apiKey", .description = "Service key", .kind = .{ .api_key = .{ .in = .header, .name = "X-API-Key" } } },
            .{ .name = "session", .kind = .{ .api_key = .{ .in = .cookie, .name = "sid" } } },
            .{ .name = "basicAuth", .kind = .http_basic },
            .{ .name = "jwt", .kind = .{ .http_bearer = .{ .format = "JWT" } } },
            .{ .name = "oauth", .kind = .{ .oauth2 = .{
                .implicit = .{ .authorization_url = "https://auth.example.com/authorize" },
                .client_credentials = .{ .token_url = "https://auth.example.com/token", .refresh_url = "https://auth.example.com/refresh" },
                .authorization_code = .{
                    .authorization_url = "https://auth.example.com/authorize",
                    .token_url = "https://auth.example.com/token",
                    .scopes = &.{.{ .name = "read", .description = "Read access" }},
                },
            } } },
            .{ .name = "oidc", .kind = .{ .openid_connect = "https://auth.example.com/.well-known/openid-configuration" } },
        },
        .security = &.{.{ .name = "apiKey" }},
        .route_extras = &.{
            .{ .method = .get, .pattern = "/a", .security = &.{.{ .name = "oauth", .scopes = &.{"read"} }} },
            .{ .method = .get, .pattern = "/b", .security = &.{} },
        },
    });
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        \\{"openapi":"3.1.0","info":{"title":"T","version":"1"},"security":[{"bearerAuth":[]},{"apiKey":[]}],"paths":{"/a":{"get":{"operationId":"get_a","responses":{"200":{"description":"Successful Response"}},"security":[{"oauth":["read"]}]}},"/b":{"get":{"operationId":"get_b","responses":{"200":{"description":"Successful Response"}},"security":[]}}},"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"},"apiKey":{"type":"apiKey","description":"Service key","name":"X-API-Key","in":"header"},"session":{"type":"apiKey","name":"sid","in":"cookie"},"basicAuth":{"type":"http","scheme":"basic"},"jwt":{"type":"http","scheme":"bearer","bearerFormat":"JWT"},"oauth":{"type":"oauth2","flows":{"implicit":{"authorizationUrl":"https://auth.example.com/authorize","scopes":{}},"clientCredentials":{"tokenUrl":"https://auth.example.com/token","refreshUrl":"https://auth.example.com/refresh","scopes":{}},"authorizationCode":{"authorizationUrl":"https://auth.example.com/authorize","tokenUrl":"https://auth.example.com/token","scopes":{"read":"Read access"}}}},"oidc":{"type":"openIdConnect","openIdConnectUrl":"https://auth.example.com/.well-known/openid-configuration"}}}}
    , json);
    try check(json);
}

test "route extras: header and cookie parameters, request and response examples" {
    const routes = [_]router.Route{
        .{ .method = .post, .pattern = "/items", .doc = &.{
            .query_schema = "{\"type\":\"object\",\"properties\":{\"q\":{\"type\":\"string\"}}}",
            .request_schema = "{\"type\":\"object\"}",
            .responses = &.{
                .{ .status = 201, .description = "Created", .schema = "{\"type\":\"object\"}" },
                .{ .status = 404, .description = "Missing" },
            },
        } },
    };
    const json = try build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{
            .method = .post,
            .pattern = "/items",
            .header_parameters = &.{
                .{ .name = "X-Request-Id", .description = "Trace id", .required = true },
                .{ .name = "X-Limit", .schema = "{\"type\":\"integer\"}" },
            },
            .cookie_parameters = &.{.{ .name = "session" }},
            .request_example = "{ \"name\": \"a\" }",
            .response_examples = &.{
                .{ .status = 201, .json = "{\"id\":1}" },
                .{ .status = 404, .json = "{\"detail\":\"nope\"}" },
            },
        }},
    });
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        \\{"openapi":"3.1.0","info":{"title":"T","version":"1"},"paths":{"/items":{"post":{"operationId":"post_items","parameters":[{"name":"q","in":"query","required":false,"schema":{"type":"string"}},{"name":"X-Request-Id","in":"header","description":"Trace id","required":true,"schema":{"type":"string"}},{"name":"X-Limit","in":"header","required":false,"schema":{"type":"integer"}},{"name":"session","in":"cookie","required":false,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object"},"example":{"name":"a"}}},"required":true},"responses":{"201":{"description":"Created","content":{"application/json":{"schema":{"type":"object"},"example":{"id":1}}}},"404":{"description":"Missing","content":{"application/json":{"example":{"detail":"nope"}}}}}}}}}
    , json);
    try check(json);
}

test "route extras: examples on an undocumented route and a body example without a schema" {
    const routes = [_]router.Route{
        .{ .method = .get, .pattern = "/h" },
        .{ .method = .post, .pattern = "/p" },
    };
    const json = try build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{
            .{ .method = .get, .pattern = "/h", .response_examples = &.{.{ .status = 200, .json = "[1,2]" }} },
            .{ .method = .post, .pattern = "/p", .request_example = "{\"a\":1}" },
        },
    });
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        \\{"openapi":"3.1.0","info":{"title":"T","version":"1"},"paths":{"/h":{"get":{"operationId":"get_h","responses":{"200":{"description":"Successful Response","content":{"application/json":{"example":[1,2]}}}}}},"/p":{"post":{"operationId":"post_p","requestBody":{"content":{"application/json":{"example":{"a":1}}},"required":true},"responses":{"200":{"description":"Successful Response"}}}}}}
    , json);
    try check(json);
}

test "unused: the new members leave the output byte-identical" {
    const routes = [_]router.Route{.{ .method = .get, .pattern = "/x" }};
    const plain = try build(&routes, .{ .title = "T", .version = "1" });
    defer testing.allocator.free(plain);
    const explicit = try build(&routes, .{
        .title = "T",
        .version = "1",
        .servers = &.{},
        .schemas = &.{},
        .security_schemes = &.{},
        .security = &.{},
        .route_extras = &.{},
    });
    defer testing.allocator.free(explicit);
    try testing.expectEqualStrings(plain, explicit);
    try testing.expectEqualStrings(
        \\{"openapi":"3.1.0","info":{"title":"T","version":"1"},"paths":{"/x":{"get":{"operationId":"get_x","responses":{"200":{"description":"Successful Response"}}}}}}
    , plain);
}

test "route extras: an entry for an excluded route is not an error and not emitted" {
    const routes = [_]router.Route{
        .{ .method = .get, .pattern = "/keep" },
        .{ .method = .get, .pattern = "/hidden" },
    };
    const json = try build(&routes, .{
        .title = "T",
        .version = "1",
        .include = struct {
            fn f(rt: router.Route) bool {
                return !std.mem.eql(u8, rt.pattern, "/hidden");
            }
        }.f,
        .route_extras = &.{.{ .method = .get, .pattern = "/hidden", .security = &.{} }},
    });
    defer testing.allocator.free(json);
    try testing.expect(std.mem.find(u8, json, "hidden") == null);
}

test "negative: dangling $ref is error.DanglingRef" {
    const routes = [_]router.Route{
        .{ .method = .post, .pattern = "/users", .doc = &.{ .request_schema = oa.schemaRef("Missing") } },
    };
    // No registry at all, and a registry that lacks the name.
    try testing.expectError(error.DanglingRef, build(&routes, .{ .title = "T", .version = "1" }));
    try testing.expectError(error.DanglingRef, build(&routes, .{
        .title = "T",
        .version = "1",
        .schemas = &.{.{ .name = "User", .schema = user_schema }},
    }));
}

test "negative: the same schema name with a different body is error.SchemaConflict" {
    const routes = [_]router.Route{.{ .method = .get, .pattern = "/x" }};
    try testing.expectError(error.SchemaConflict, build(&routes, .{
        .title = "T",
        .version = "1",
        .schemas = &.{
            .{ .name = "User", .schema = user_schema },
            .{ .name = "User", .schema = "{\"type\":\"string\"}" },
        },
    }));
}

test "negative: bad schema registry entries" {
    const routes = [_]router.Route{.{ .method = .get, .pattern = "/x" }};
    try testing.expectError(error.InvalidComponentSchema, build(&routes, .{
        .title = "T",
        .version = "1",
        .schemas = &.{.{ .name = "User", .schema = "{nope" }},
    }));
    try testing.expectError(error.InvalidComponentName, build(&routes, .{
        .title = "T",
        .version = "1",
        .schemas = &.{.{ .name = "bad name", .schema = "{}" }},
    }));
}

test "negative: a security requirement naming an undeclared scheme is error.UnknownSecurityScheme" {
    const routes = [_]router.Route{.{ .method = .get, .pattern = "/x" }};
    // Document-wide, with no schemes at all.
    try testing.expectError(error.UnknownSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .security = &.{.{ .name = "nope" }},
    }));
    // Document-wide, with other schemes declared.
    try testing.expectError(error.UnknownSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .bearer_auth = true,
        .security = &.{.{ .name = "nope" }},
    }));
    // Per operation.
    try testing.expectError(error.UnknownSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .bearer_auth = true,
        .route_extras = &.{.{ .method = .get, .pattern = "/x", .security = &.{.{ .name = "nope" }} }},
    }));
}

test "negative: security scheme declarations" {
    const routes = [_]router.Route{.{ .method = .get, .pattern = "/x" }};
    try testing.expectError(error.DuplicateSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .security_schemes = &.{
            .{ .name = "k", .kind = .http_basic },
            .{ .name = "k", .kind = .http_basic },
        },
    }));
    try testing.expectError(error.DuplicateSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .bearer_auth = true,
        .security_schemes = &.{.{ .name = "bearerAuth", .kind = .http_basic }},
    }));
    // OAuth2 without a flow, and a flow missing a URL its kind needs.
    try testing.expectError(error.InvalidSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .security_schemes = &.{.{ .name = "o", .kind = .{ .oauth2 = .{} } }},
    }));
    try testing.expectError(error.InvalidSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .security_schemes = &.{.{ .name = "o", .kind = .{ .oauth2 = .{
            .authorization_code = .{ .authorization_url = "https://a.example/auth" },
        } } }},
    }));
    try testing.expectError(error.InvalidSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .security_schemes = &.{.{ .name = "k", .kind = .{ .api_key = .{ .in = .query, .name = "" } } }},
    }));
    try testing.expectError(error.InvalidSecurityScheme, build(&routes, .{
        .title = "T",
        .version = "1",
        .security_schemes = &.{.{ .name = "o", .kind = .{ .openid_connect = "" } }},
    }));
    try testing.expectError(error.InvalidComponentName, build(&routes, .{
        .title = "T",
        .version = "1",
        .security_schemes = &.{.{ .name = "a b", .kind = .http_basic }},
    }));
}

test "negative: servers, route extras, UTF-8" {
    const routes = [_]router.Route{.{ .method = .get, .pattern = "/x" }};
    try testing.expectError(error.InvalidServer, build(&routes, .{
        .title = "T",
        .version = "1",
        .servers = &.{.{ .url = "" }},
    }));
    try testing.expectError(error.InvalidUtf8, build(&routes, .{
        .title = "T",
        .version = "1",
        .servers = &.{.{ .url = "https://a.example", .description = "bad \xff" }},
    }));
    // An entry for a route that is not registered.
    try testing.expectError(error.UnknownRouteExtra, build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{ .method = .get, .pattern = "/y" }},
    }));
    try testing.expectError(error.UnknownRouteExtra, build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{ .method = .post, .pattern = "/x" }},
    }));
    // An example for a status the route does not document (undocumented: only 200).
    try testing.expectError(error.UnknownRouteExtra, build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{ .method = .get, .pattern = "/x", .response_examples = &.{.{ .status = 500, .json = "{}" }} }},
    }));
    try testing.expectError(error.InvalidExample, build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{ .method = .get, .pattern = "/x", .request_example = "{nope" }},
    }));
    try testing.expectError(error.InvalidExample, build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{ .method = .get, .pattern = "/x", .response_examples = &.{.{ .status = 200, .json = "{nope" }} }},
    }));
    try testing.expectError(error.InvalidParameterSchema, build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{ .method = .get, .pattern = "/x", .header_parameters = &.{.{ .name = "X-A", .schema = "{nope" }} }},
    }));
    // A duplicated header parameter is the checker's DuplicateParameter.
    try testing.expectError(error.DuplicateParameter, build(&routes, .{
        .title = "T",
        .version = "1",
        .route_extras = &.{.{ .method = .get, .pattern = "/x", .header_parameters = &.{ .{ .name = "X-A" }, .{ .name = "X-A" } } }},
    }));
}

test "checker: JSON Pointer resolution of local $ref" {
    const head = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"},";
    // Escaped tokens (`~1` = `/`), array indices, and the path item itself.
    try check(head ++ "\"x-defs\":{\"a/b\":[{}]},\"paths\":{\"/x\":{\"get\":{\"responses\":{\"200\":{\"description\":\"d\"}}}}}," ++
        "\"x-use\":[{\"$ref\":\"#/x-defs/a~1b/0\"},{\"$ref\":\"#/paths/~1x/get\"},{\"$ref\":\"#\"}]}");
    // References to other documents are not followed.
    try check(head ++ "\"paths\":{},\"x-use\":{\"$ref\":\"other.json#/nope\"}}");
    // Missing member, array index out of range, descent into a scalar.
    try testing.expectError(error.DanglingRef, check(head ++ "\"paths\":{},\"x-use\":{\"$ref\":\"#/x-defs\"}}"));
    try testing.expectError(error.DanglingRef, check(head ++ "\"paths\":{},\"x-defs\":[1],\"x-use\":{\"$ref\":\"#/x-defs/1\"}}"));
    try testing.expectError(error.DanglingRef, check(head ++ "\"paths\":{},\"x-defs\":[1],\"x-use\":{\"$ref\":\"#/x-defs/0/y\"}}"));
    // `~0` is `~`, and a prefix of a key is not the key.
    try check(head ++ "\"paths\":{},\"x-defs\":{\"a~b\":1},\"x-use\":{\"$ref\":\"#/x-defs/a~0b\"}}");
    try testing.expectError(error.DanglingRef, check(head ++ "\"paths\":{},\"x-defs\":{\"a~b\":1},\"x-use\":{\"$ref\":\"#/x-defs/a\"}}"));
    try testing.expectError(error.DanglingRef, check(head ++ "\"paths\":{},\"x-defs\":{\"a\":1},\"x-use\":{\"$ref\":\"#/x-defs/ab\"}}"));
}

test "checker: servers, schemes and requirements in a hand-written document" {
    const head = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"},";
    try testing.expectError(error.InvalidServer, check(head ++ "\"servers\":[{\"description\":\"d\"}],\"paths\":{}}"));
    try testing.expectError(error.InvalidServer, check(head ++ "\"servers\":{},\"paths\":{}}"));
    try testing.expectError(error.InvalidSecurityScheme, check(head ++ "\"components\":{\"securitySchemes\":{\"k\":{\"type\":\"magic\"}}}}"));
    try testing.expectError(error.InvalidSecurityScheme, check(head ++ "\"components\":{\"securitySchemes\":{\"k\":{\"type\":\"apiKey\",\"name\":\"n\",\"in\":\"body\"}}}}"));
    try testing.expectError(error.InvalidSecurityScheme, check(head ++ "\"components\":{\"securitySchemes\":{\"k\":{\"type\":\"http\"}}}}"));
    try check(head ++ "\"components\":{\"securitySchemes\":{\"k\":{\"type\":\"mutualTLS\"}}},\"security\":[{\"k\":[]}]}");
    try testing.expectError(error.UnknownSecurityScheme, check(head ++ "\"components\":{\"securitySchemes\":{\"k\":{\"type\":\"mutualTLS\"}}},\"security\":[{\"j\":[]}]}"));
    // A requirement's value is a scope list.
    try testing.expectError(error.InvalidSecurityScheme, check(head ++ "\"components\":{\"securitySchemes\":{\"k\":{\"type\":\"mutualTLS\"}}},\"security\":[{\"k\":\"x\"}]}"));
    // Per-operation requirement against an undeclared scheme.
    try testing.expectError(error.UnknownSecurityScheme, check(head ++
        "\"paths\":{\"/x\":{\"get\":{\"security\":[{\"j\":[]}],\"responses\":{\"200\":{\"description\":\"d\"}}}}}}"));
}
