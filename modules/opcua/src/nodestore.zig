// SPDX-License-Identifier: MIT

//! The server-side address space (OPC 10000-3): a caller-owned node store
//! holding `Node`s of the standard node classes (Object, Variable, Method,
//! ObjectType, VariableType, ReferenceType, DataType, View), their attributes,
//! and the references between them (`Organizes`, `HasComponent`,
//! `HasProperty`, `HasTypeDefinition`, `HasSubtype`, …).
//!
//! Ownership: **the store owns every byte it holds.** `addNode`/`setValue`/
//! `writeAttribute` deep-copy their arguments with the store's allocator, so a
//! caller may build the address space from stack/`comptime` literals and drop
//! them. The copies are allocated exactly the way `encoding.Decoder` allocates,
//! so `encoding.free*` frees them — no bespoke free path.
//!
//! Reads borrow: `readAttribute` returns a `DataValue` pointing *into* the
//! store (no allocation), valid until the next mutation. The server encodes it
//! straight onto the wire; anything that must outlive a mutation (a monitored
//! item's last-reported value) deep-copies it with `dupDataValue`.
//!
//! References are stored on both endpoints (a forward `Reference` on the
//! source, an inverse one on the target) — the shape `Browse` with
//! `BrowseDirection.inverse`/`.both` needs, and the shape OPC 10000-3 §4.3.4
//! describes ("a Reference is visible from both Nodes it connects").

const std = @import("std");
const encoding = @import("encoding.zig");
const services = @import("services.zig");

pub const StoreError = std.mem.Allocator.Error;

/// Namespace-0 identifiers this module seeds/uses by name (OPC Foundation
/// UA-Nodeset `Schema/NodeIds.csv`, MIT License 1.00 — the same source
/// `services.type_id` was ground-truthed against).
pub const id = struct {
    // DataTypes
    pub const boolean: u32 = 1;
    pub const sbyte: u32 = 2;
    pub const byte: u32 = 3;
    pub const int16: u32 = 4;
    pub const uint16: u32 = 5;
    pub const int32: u32 = 6;
    pub const uint32: u32 = 7;
    pub const int64: u32 = 8;
    pub const uint64: u32 = 9;
    pub const float: u32 = 10;
    pub const double: u32 = 11;
    pub const string: u32 = 12;
    pub const date_time: u32 = 13;
    pub const guid: u32 = 14;
    pub const byte_string: u32 = 15;
    pub const xml_element: u32 = 16;
    pub const node_id: u32 = 17;
    pub const status_code: u32 = 19;
    pub const qualified_name: u32 = 20;
    pub const localized_text: u32 = 21;
    pub const structure: u32 = 22;
    pub const base_data_type: u32 = 24;
    pub const number: u32 = 26;
    pub const integer: u32 = 27;
    pub const uinteger: u32 = 28;
    pub const enumeration: u32 = 29;

    // ReferenceTypes
    pub const references: u32 = 31;
    pub const non_hierarchical_references: u32 = 32;
    pub const hierarchical_references: u32 = 33;
    pub const has_child: u32 = 34;
    pub const organizes: u32 = 35;
    pub const has_modelling_rule: u32 = 37;
    pub const has_type_definition: u32 = 40;
    pub const aggregates: u32 = 44;
    pub const has_subtype: u32 = 45;
    pub const has_property: u32 = 46;
    pub const has_component: u32 = 47;

    // ObjectTypes / VariableTypes
    pub const base_object_type: u32 = 58;
    pub const folder_type: u32 = 61;
    pub const base_variable_type: u32 = 62;
    pub const base_data_variable_type: u32 = 63;
    pub const property_type: u32 = 68;
    pub const server_type: u32 = 2004;
    pub const server_status_type: u32 = 2138;

    // Standard Objects / Variables
    pub const root_folder: u32 = 84;
    pub const objects_folder: u32 = 85;
    pub const types_folder: u32 = 86;
    pub const views_folder: u32 = 87;
    pub const object_types_folder: u32 = 88;
    pub const variable_types_folder: u32 = 89;
    pub const data_types_folder: u32 = 90;
    pub const reference_types_folder: u32 = 91;
    pub const build_info_data_type: u32 = 338;
    pub const server_state_data_type: u32 = 852;
    pub const server_status_data_type: u32 = 862;
    pub const server: u32 = 2253;
    pub const server_server_array: u32 = 2254;
    pub const server_namespace_array: u32 = 2255;
    pub const server_status: u32 = 2256;
    pub const server_status_start_time: u32 = 2257;
    pub const server_status_current_time: u32 = 2258;
    pub const server_status_state: u32 = 2259;
    pub const server_status_build_info: u32 = 2260;
    pub const server_service_level: u32 = 2267;
    pub const server_auditing: u32 = 2994;
    /// `ServerStatusDataType_Encoding_DefaultBinary` — the `ExtensionObject`
    /// TypeId the ServerStatus variable's value carries.
    pub const server_status_data_type_binary: u32 = 864;
    /// `BuildInfo_Encoding_DefaultBinary`.
    pub const build_info_binary: u32 = 340;
};

/// `AccessLevel`/`UserAccessLevel` bit mask (OPC 10000-3 §8.57).
pub const access_level = struct {
    pub const current_read: u8 = 1 << 0;
    pub const current_write: u8 = 1 << 1;
    pub const history_read: u8 = 1 << 2;
    pub const history_write: u8 = 1 << 3;
    pub const read_write: u8 = current_read | current_write;
};

/// `ValueRank` (OPC 10000-3 §8.6) — the values this module actually uses.
pub const value_rank = struct {
    pub const scalar_or_one_dimension: i32 = -3;
    pub const any: i32 = -2;
    pub const scalar: i32 = -1;
    pub const one_or_more_dimensions: i32 = 0;
    pub const one_dimension: i32 = 1;
};

/// `BrowseResultMask` bits (OPC 10000-4 §7.5) — which `ReferenceDescription`
/// fields a `Browse` caller asked to have filled in.
pub const result_mask = struct {
    pub const reference_type_id: u32 = 1 << 0;
    pub const is_forward: u32 = 1 << 1;
    pub const node_class: u32 = 1 << 2;
    pub const browse_name: u32 = 1 << 3;
    pub const display_name: u32 = 1 << 4;
    pub const type_definition: u32 = 1 << 5;
    pub const all: u32 = 0x3f;
};

pub fn n0(numeric: u32) encoding.NodeId {
    return .{ .numeric = .{ .namespace = 0, .id = numeric } };
}

// ── deep-copy helpers ───────────────────────────────────────────────────────
// Every one of these allocates exactly the way `encoding.Decoder` does, so the
// matching `encoding.free*` frees the result. They are the store's ingest path
// (caller memory -> store memory) and the server's "keep this past the next
// mutation" path (store memory -> monitored-item memory).

fn dupOptStr(a: std.mem.Allocator, s: ?[]const u8) StoreError!?[]const u8 {
    return if (s) |bytes| try a.dupe(u8, bytes) else null;
}

pub fn dupNodeId(a: std.mem.Allocator, v: encoding.NodeId) StoreError!encoding.NodeId {
    return switch (v) {
        .numeric => |n| .{ .numeric = n },
        .guid => |n| .{ .guid = n },
        .string => |n| .{ .string = .{ .namespace = n.namespace, .id = try dupOptStr(a, n.id) } },
        .byte_string => |n| .{ .byte_string = .{ .namespace = n.namespace, .id = try dupOptStr(a, n.id) } },
    };
}

pub fn dupExpandedNodeId(a: std.mem.Allocator, v: encoding.ExpandedNodeId) StoreError!encoding.ExpandedNodeId {
    return .{
        .node_id = try dupNodeId(a, v.node_id),
        .namespace_uri = try dupOptStr(a, v.namespace_uri),
        .server_index = v.server_index,
    };
}

pub fn dupQualifiedName(a: std.mem.Allocator, v: encoding.QualifiedName) StoreError!encoding.QualifiedName {
    return .{ .namespace_index = v.namespace_index, .name = try dupOptStr(a, v.name) };
}

pub fn dupLocalizedText(a: std.mem.Allocator, v: encoding.LocalizedText) StoreError!encoding.LocalizedText {
    return .{ .locale = try dupOptStr(a, v.locale), .text = try dupOptStr(a, v.text) };
}

pub fn dupExtensionObject(a: std.mem.Allocator, v: encoding.ExtensionObject) StoreError!encoding.ExtensionObject {
    return .{
        .type_id = try dupNodeId(a, v.type_id),
        .encoding = v.encoding,
        .body = if (v.body.len == 0) &.{} else try a.dupe(u8, v.body),
    };
}

fn dupOptStrArray(a: std.mem.Allocator, arr: ?[]const ?[]const u8) StoreError!?[]const ?[]const u8 {
    const items = arr orelse return null;
    const out = try a.alloc(?[]const u8, items.len);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |s| if (s) |bytes| a.free(bytes);
        a.free(out);
    }
    for (items, 0..) |s, i| {
        out[i] = try dupOptStr(a, s);
        filled = i + 1;
    }
    return out;
}

pub fn dupVariantScalar(a: std.mem.Allocator, v: encoding.VariantScalar) StoreError!encoding.VariantScalar {
    return switch (v) {
        .string => |s| .{ .string = try dupOptStr(a, s) },
        .byte_string => |s| .{ .byte_string = try dupOptStr(a, s) },
        .xml_element => |s| .{ .xml_element = try dupOptStr(a, s) },
        .node_id => |n| .{ .node_id = try dupNodeId(a, n) },
        .expanded_node_id => |n| .{ .expanded_node_id = try dupExpandedNodeId(a, n) },
        .qualified_name => |q| .{ .qualified_name = try dupQualifiedName(a, q) },
        .localized_text => |lt| .{ .localized_text = try dupLocalizedText(a, lt) },
        .extension_object => |eo| .{ .extension_object = try dupExtensionObject(a, eo) },
        else => v, // fixed-size scalars own no memory
    };
}

pub fn dupVariantArrayItems(a: std.mem.Allocator, v: encoding.VariantArrayItems) StoreError!encoding.VariantArrayItems {
    switch (v) {
        inline .boolean, .sbyte, .byte, .int16, .uint16, .int32, .uint32, .int64, .uint64, .float, .double, .date_time, .guid, .status_code => |arr, tag| {
            const items = arr orelse return @unionInit(encoding.VariantArrayItems, @tagName(tag), null);
            return @unionInit(encoding.VariantArrayItems, @tagName(tag), try a.dupe(@TypeOf(items[0]), items));
        },
        inline .string, .byte_string, .xml_element => |arr, tag| {
            return @unionInit(encoding.VariantArrayItems, @tagName(tag), try dupOptStrArray(a, arr));
        },
        inline .node_id, .expanded_node_id, .qualified_name, .localized_text, .extension_object => |arr, tag| {
            const items = arr orelse return @unionInit(encoding.VariantArrayItems, @tagName(tag), null);
            const Elem = @TypeOf(items[0]);
            const out = try a.alloc(Elem, items.len);
            errdefer a.free(out);
            for (items, 0..) |item, i| {
                out[i] = switch (Elem) {
                    encoding.NodeId => try dupNodeId(a, item),
                    encoding.ExpandedNodeId => try dupExpandedNodeId(a, item),
                    encoding.QualifiedName => try dupQualifiedName(a, item),
                    encoding.LocalizedText => try dupLocalizedText(a, item),
                    encoding.ExtensionObject => try dupExtensionObject(a, item),
                    else => unreachable,
                };
            }
            return @unionInit(encoding.VariantArrayItems, @tagName(tag), out);
        },
    }
}

pub fn dupVariant(a: std.mem.Allocator, v: encoding.Variant) StoreError!encoding.Variant {
    return switch (v) {
        .empty => .empty,
        .scalar => |s| .{ .scalar = try dupVariantScalar(a, s) },
        .array => |arr| .{ .array = .{
            .items = try dupVariantArrayItems(a, arr.items),
            .dimensions = if (arr.dimensions) |d| try a.dupe(i32, d) else null,
        } },
    };
}

pub fn dupDataValue(a: std.mem.Allocator, v: encoding.DataValue) StoreError!encoding.DataValue {
    return .{
        .value = if (v.value) |val| try dupVariant(a, val) else null,
        .status = v.status,
        .source_timestamp = v.source_timestamp,
        .source_pico_seconds = v.source_pico_seconds,
        .server_timestamp = v.server_timestamp,
        .server_pico_seconds = v.server_pico_seconds,
    };
}

// ── value comparison (the data-change trigger) ──────────────────────────────

fn optStrEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return (a == null) == (b == null);
    return std.mem.eql(u8, a.?, b.?);
}

fn scalarEql(a: encoding.VariantScalar, b: encoding.VariantScalar) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .string => optStrEql(a.string, b.string),
        .byte_string => optStrEql(a.byte_string, b.byte_string),
        .xml_element => optStrEql(a.xml_element, b.xml_element),
        .node_id => services.nodeIdEql(a.node_id, b.node_id),
        .expanded_node_id => services.nodeIdEql(a.expanded_node_id.node_id, b.expanded_node_id.node_id) and
            optStrEql(a.expanded_node_id.namespace_uri, b.expanded_node_id.namespace_uri),
        .qualified_name => a.qualified_name.namespace_index == b.qualified_name.namespace_index and
            optStrEql(a.qualified_name.name, b.qualified_name.name),
        .localized_text => optStrEql(a.localized_text.locale, b.localized_text.locale) and
            optStrEql(a.localized_text.text, b.localized_text.text),
        .extension_object => services.nodeIdEql(a.extension_object.type_id, b.extension_object.type_id) and
            std.mem.eql(u8, a.extension_object.body, b.extension_object.body),
        inline else => |av, tag| std.meta.eql(av, @field(b, @tagName(tag))),
    };
}

fn arrayItemsEql(a: encoding.VariantArrayItems, b: encoding.VariantArrayItems) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    switch (a) {
        inline .string, .byte_string, .xml_element => |arr, tag| {
            const other = @field(b, @tagName(tag));
            if (arr == null or other == null) return (arr == null) == (other == null);
            if (arr.?.len != other.?.len) return false;
            for (arr.?, other.?) |x, y| if (!optStrEql(x, y)) return false;
            return true;
        },
        inline .node_id, .expanded_node_id, .qualified_name, .localized_text, .extension_object => |arr, tag| {
            const other = @field(b, @tagName(tag));
            if (arr == null or other == null) return (arr == null) == (other == null);
            if (arr.?.len != other.?.len) return false;
            const Scalar = std.meta.Tag(encoding.VariantScalar);
            for (arr.?, other.?) |x, y| {
                const sx = @unionInit(encoding.VariantScalar, @tagName(@field(Scalar, @tagName(tag))), x);
                const sy = @unionInit(encoding.VariantScalar, @tagName(@field(Scalar, @tagName(tag))), y);
                if (!scalarEql(sx, sy)) return false;
            }
            return true;
        },
        .guid => |arr| {
            const other = b.guid;
            if (arr == null or other == null) return (arr == null) == (other == null);
            if (arr.?.len != other.?.len) return false;
            // `Guid` is a struct, so `std.mem.eql` (which needs `!=`) can't
            // compare it — element-wise `std.meta.eql` instead.
            for (arr.?, other.?) |x, y| if (!std.meta.eql(x, y)) return false;
            return true;
        },
        inline else => |arr, tag| {
            const other = @field(b, @tagName(tag));
            if (arr == null or other == null) return (arr == null) == (other == null);
            return std.mem.eql(@TypeOf(arr.?[0]), arr.?, other.?);
        },
    }
}

/// Value/quality equality — the MonitoringFilter this module implements
/// (OPC 10000-4 §5.12.1.4's default `DataChangeTrigger.StatusValue`:
/// timestamps alone never trigger a notification, a changed value or
/// StatusCode does).
pub fn dataValueChanged(a: encoding.DataValue, b: encoding.DataValue) bool {
    if ((a.status orelse 0) != (b.status orelse 0)) return true;
    if (a.value == null or b.value == null) return (a.value == null) != (b.value == null);
    const av = a.value.?;
    const bv = b.value.?;
    if (std.meta.activeTag(av) != std.meta.activeTag(bv)) return true;
    return switch (av) {
        .empty => false,
        .scalar => |s| !scalarEql(s, bv.scalar),
        .array => |arr| !arrayItemsEql(arr.items, bv.array.items),
    };
}

// ── nodes ───────────────────────────────────────────────────────────────────

/// One reference from the node holding it. `is_forward = false` is the
/// inverse half stored on the target node.
pub const Reference = struct {
    reference_type_id: encoding.NodeId,
    is_forward: bool,
    target_id: encoding.ExpandedNodeId,
};

/// Method implementation: invoked by the `Call` service (OPC 10000-4 §5.11.2).
/// `inputs` borrow the decoded request (valid for the call only); every
/// `outputs` element must be allocated with `allocator` (the server hands over
/// its per-request arena, so nothing has to be freed). Return a `StatusCode` —
/// `Good` (0) or e.g. `BadInvalidArgument` — rather than an error; the only
/// error channel is allocation failure.
pub const MethodFn = *const fn (
    user_context: ?*anyopaque,
    allocator: std.mem.Allocator,
    inputs: []const encoding.Variant,
    outputs: *std.ArrayList(encoding.Variant),
) StoreError!encoding.StatusCode;

pub const VariableAttributes = struct {
    value: encoding.DataValue = .{},
    data_type: encoding.NodeId = n0(id.base_data_type),
    value_rank: i32 = value_rank.scalar,
    array_dimensions: ?[]const u32 = null,
    access_level: u8 = access_level.current_read,
    user_access_level: u8 = access_level.current_read,
    minimum_sampling_interval: f64 = 0,
    historizing: bool = false,
};

pub const VariableTypeAttributes = struct {
    value: encoding.DataValue = .{},
    data_type: encoding.NodeId = n0(id.base_data_type),
    value_rank: i32 = value_rank.any,
    array_dimensions: ?[]const u32 = null,
    is_abstract: bool = false,
};

pub const MethodAttributes = struct {
    executable: bool = true,
    user_executable: bool = true,
    /// `null` = a Method node with no implementation: `Call` answers
    /// `BadNotImplemented` (the node still browses/reads normally).
    implementation: ?MethodFn = null,
    user_context: ?*anyopaque = null,
};

pub const ReferenceTypeAttributes = struct {
    is_abstract: bool = false,
    symmetric: bool = false,
    inverse_name: encoding.LocalizedText = .{},
};

/// Per-node-class attributes (OPC 10000-3 §5). The attributes every class
/// shares (NodeId/NodeClass/BrowseName/DisplayName/Description/WriteMask) live
/// on `Node` itself.
pub const Attributes = union(enum) {
    object: struct { event_notifier: u8 = 0 },
    variable: VariableAttributes,
    method: MethodAttributes,
    object_type: struct { is_abstract: bool = false },
    variable_type: VariableTypeAttributes,
    reference_type: ReferenceTypeAttributes,
    data_type: struct { is_abstract: bool = false },
    view: struct { contains_no_loops: bool = true, event_notifier: u8 = 0 },

    pub fn nodeClass(a: Attributes) services.NodeClass {
        return switch (a) {
            .object => .object,
            .variable => .variable,
            .method => .method,
            .object_type => .object_type,
            .variable_type => .variable_type,
            .reference_type => .reference_type,
            .data_type => .data_type,
            .view => .view,
        };
    }
};

pub const Node = struct {
    node_id: encoding.NodeId,
    browse_name: encoding.QualifiedName,
    display_name: encoding.LocalizedText,
    description: encoding.LocalizedText = .{},
    write_mask: u32 = 0,
    user_write_mask: u32 = 0,
    attributes: Attributes,
    references: std.ArrayList(Reference) = .empty,

    pub fn nodeClass(n: *const Node) services.NodeClass {
        return n.attributes.nodeClass();
    }
};

/// What `addNode` takes: the same shape as `Node` minus the reference list
/// (references are added with `addReference`), all of it borrowed — `addNode`
/// deep-copies before storing.
pub const NodeSpec = struct {
    node_id: encoding.NodeId,
    browse_name: encoding.QualifiedName,
    display_name: encoding.LocalizedText = .{},
    description: encoding.LocalizedText = .{},
    write_mask: u32 = 0,
    user_write_mask: u32 = 0,
    attributes: Attributes,
};

const NodeIdContext = struct {
    pub fn hash(_: NodeIdContext, key: encoding.NodeId) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&.{@intFromEnum(std.meta.activeTag(key))});
        switch (key) {
            .numeric => |v| {
                h.update(std.mem.asBytes(&v.namespace));
                h.update(std.mem.asBytes(&v.id));
            },
            .guid => |v| {
                h.update(std.mem.asBytes(&v.namespace));
                h.update(std.mem.asBytes(&v.id));
            },
            .string => |v| {
                h.update(std.mem.asBytes(&v.namespace));
                h.update(v.id orelse &.{});
            },
            .byte_string => |v| {
                h.update(std.mem.asBytes(&v.namespace));
                h.update(v.id orelse &.{});
            },
        }
        return h.final();
    }

    pub fn eql(_: NodeIdContext, a: encoding.NodeId, b: encoding.NodeId) bool {
        return services.nodeIdEql(a, b);
    }
};

pub const NodeMap = std.HashMapUnmanaged(encoding.NodeId, Node, NodeIdContext, std.hash_map.default_max_load_percentage);

pub const NodeStore = struct {
    allocator: std.mem.Allocator,
    nodes: NodeMap = .empty,
    /// The server's NamespaceArray (`Server_NamespaceArray`, i=2255): index 0
    /// is always `http://opcfoundation.org/UA/`.
    namespaces: std.ArrayList([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) NodeStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(s: *NodeStore) void {
        var it = s.nodes.iterator();
        while (it.next()) |entry| {
            freeNode(s.allocator, entry.value_ptr);
        }
        s.nodes.deinit(s.allocator);
        for (s.namespaces.items) |uri| s.allocator.free(uri);
        s.namespaces.deinit(s.allocator);
        s.* = undefined;
    }

    fn freeNode(a: std.mem.Allocator, n: *Node) void {
        encoding.freeNodeId(a, n.node_id);
        encoding.freeQualifiedName(a, n.browse_name);
        encoding.freeLocalizedText(a, n.display_name);
        encoding.freeLocalizedText(a, n.description);
        switch (n.attributes) {
            .variable => |v| {
                encoding.freeDataValue(a, v.value);
                encoding.freeNodeId(a, v.data_type);
                if (v.array_dimensions) |d| a.free(d);
            },
            .variable_type => |v| {
                encoding.freeDataValue(a, v.value);
                encoding.freeNodeId(a, v.data_type);
                if (v.array_dimensions) |d| a.free(d);
            },
            .reference_type => |v| encoding.freeLocalizedText(a, v.inverse_name),
            else => {},
        }
        for (n.references.items) |ref| {
            encoding.freeNodeId(a, ref.reference_type_id);
            encoding.freeExpandedNodeId(a, ref.target_id);
        }
        n.references.deinit(a);
    }

    /// Append a namespace URI to the NamespaceArray and return its index.
    /// Re-adding an existing URI returns the existing index.
    pub fn addNamespace(s: *NodeStore, uri: []const u8) StoreError!u16 {
        if (s.namespaceIndex(uri)) |existing| return existing;
        const owned = try s.allocator.dupe(u8, uri);
        errdefer s.allocator.free(owned);
        try s.namespaces.append(s.allocator, owned);
        return @intCast(s.namespaces.items.len - 1);
    }

    pub fn namespaceIndex(s: *const NodeStore, uri: []const u8) ?u16 {
        for (s.namespaces.items, 0..) |existing, i| {
            if (std.mem.eql(u8, existing, uri)) return @intCast(i);
        }
        return null;
    }

    /// Insert a node, deep-copying every field. Re-adding an existing NodeId
    /// replaces the node's attributes but keeps its references.
    pub fn addNode(s: *NodeStore, spec: NodeSpec) StoreError!void {
        const a = s.allocator;
        if (s.nodes.getPtr(spec.node_id)) |existing| {
            const replacement: Node = .{
                .node_id = existing.node_id,
                .browse_name = try dupQualifiedName(a, spec.browse_name),
                .display_name = try dupLocalizedText(a, spec.display_name),
                .description = try dupLocalizedText(a, spec.description),
                .write_mask = spec.write_mask,
                .user_write_mask = spec.user_write_mask,
                .attributes = try dupAttributes(a, spec.attributes),
                .references = existing.references,
            };
            // Free only what the replacement supersedes (not the node id, not
            // the references — both carried over above).
            encoding.freeQualifiedName(a, existing.browse_name);
            encoding.freeLocalizedText(a, existing.display_name);
            encoding.freeLocalizedText(a, existing.description);
            freeAttributes(a, existing.attributes);
            existing.* = replacement;
            return;
        }

        var node: Node = .{
            .node_id = try dupNodeId(a, spec.node_id),
            .browse_name = try dupQualifiedName(a, spec.browse_name),
            .display_name = try dupLocalizedText(a, spec.display_name),
            .description = try dupLocalizedText(a, spec.description),
            .write_mask = spec.write_mask,
            .user_write_mask = spec.user_write_mask,
            .attributes = try dupAttributes(a, spec.attributes),
        };
        errdefer freeNode(a, &node);
        try s.nodes.put(a, node.node_id, node);
    }

    fn dupAttributes(a: std.mem.Allocator, attrs: Attributes) StoreError!Attributes {
        return switch (attrs) {
            .variable => |v| .{ .variable = .{
                .value = try dupDataValue(a, v.value),
                .data_type = try dupNodeId(a, v.data_type),
                .value_rank = v.value_rank,
                .array_dimensions = if (v.array_dimensions) |d| try a.dupe(u32, d) else null,
                .access_level = v.access_level,
                .user_access_level = v.user_access_level,
                .minimum_sampling_interval = v.minimum_sampling_interval,
                .historizing = v.historizing,
            } },
            .variable_type => |v| .{ .variable_type = .{
                .value = try dupDataValue(a, v.value),
                .data_type = try dupNodeId(a, v.data_type),
                .value_rank = v.value_rank,
                .array_dimensions = if (v.array_dimensions) |d| try a.dupe(u32, d) else null,
                .is_abstract = v.is_abstract,
            } },
            .reference_type => |v| .{ .reference_type = .{
                .is_abstract = v.is_abstract,
                .symmetric = v.symmetric,
                .inverse_name = try dupLocalizedText(a, v.inverse_name),
            } },
            else => attrs, // no owned memory in the other classes
        };
    }

    fn freeAttributes(a: std.mem.Allocator, attrs: Attributes) void {
        switch (attrs) {
            .variable => |v| {
                encoding.freeDataValue(a, v.value);
                encoding.freeNodeId(a, v.data_type);
                if (v.array_dimensions) |d| a.free(d);
            },
            .variable_type => |v| {
                encoding.freeDataValue(a, v.value);
                encoding.freeNodeId(a, v.data_type);
                if (v.array_dimensions) |d| a.free(d);
            },
            .reference_type => |v| encoding.freeLocalizedText(a, v.inverse_name),
            else => {},
        }
    }

    pub fn getNode(s: *NodeStore, node_id: encoding.NodeId) ?*Node {
        return s.nodes.getPtr(node_id);
    }

    pub fn contains(s: *const NodeStore, node_id: encoding.NodeId) bool {
        return s.nodes.getKeyPtr(node_id) != null;
    }

    /// Add `source -HasSomeReference-> target` plus the inverse half on
    /// `target` — both endpoints must already exist.
    pub fn addReference(
        s: *NodeStore,
        source_id: encoding.NodeId,
        reference_type_id: encoding.NodeId,
        target_id: encoding.NodeId,
    ) StoreError!void {
        const a = s.allocator;
        const source = s.nodes.getPtr(source_id) orelse return;
        const forward: Reference = .{
            .reference_type_id = try dupNodeId(a, reference_type_id),
            .is_forward = true,
            .target_id = .{ .node_id = try dupNodeId(a, target_id) },
        };
        try source.references.append(a, forward);

        const target = s.nodes.getPtr(target_id) orelse return;
        const inverse: Reference = .{
            .reference_type_id = try dupNodeId(a, reference_type_id),
            .is_forward = false,
            .target_id = .{ .node_id = try dupNodeId(a, source_id) },
        };
        try target.references.append(a, inverse);
    }

    /// `true` if `candidate` is `base` or a transitive `HasSubtype` descendant
    /// of it — how `Browse`'s `include_subtypes` and the type hierarchy
    /// generally are resolved (OPC 10000-3 §5.3.3). Bounded: the walk visits
    /// at most `max_subtype_depth` levels so a hostile/cyclic store can't hang
    /// the server.
    pub fn isSubtypeOf(s: *NodeStore, candidate: encoding.NodeId, base: encoding.NodeId) bool {
        if (services.nodeIdEql(candidate, base)) return true;
        var current = candidate;
        var depth: usize = 0;
        while (depth < max_subtype_depth) : (depth += 1) {
            const node = s.nodes.getPtr(current) orelse return false;
            var parent: ?encoding.NodeId = null;
            for (node.references.items) |ref| {
                if (!ref.is_forward and services.nodeIdEql(ref.reference_type_id, n0(id.has_subtype))) {
                    parent = ref.target_id.node_id;
                    break;
                }
            }
            const p = parent orelse return false;
            if (services.nodeIdEql(p, base)) return true;
            current = p;
        }
        return false;
    }

    /// The node's TypeDefinition target (`HasTypeDefinition` forward
    /// reference), or `null` for a node class that has none.
    pub fn typeDefinition(s: *NodeStore, node_id: encoding.NodeId) ?encoding.NodeId {
        const node = s.nodes.getPtr(node_id) orelse return null;
        for (node.references.items) |ref| {
            if (ref.is_forward and services.nodeIdEql(ref.reference_type_id, n0(id.has_type_definition))) {
                return ref.target_id.node_id;
            }
        }
        return null;
    }

    /// Replace a Variable's Value attribute (the caller-driven "the sensor
    /// moved" path — a simulation's main entry point). Deep-copies `value`,
    /// frees the previous one. `source_timestamp`/`server_timestamp` of `null`
    /// leave the previous timestamps in place.
    pub fn setValue(
        s: *NodeStore,
        node_id: encoding.NodeId,
        value: encoding.Variant,
        timestamp: ?encoding.DateTime,
    ) StoreError!encoding.StatusCode {
        const node = s.nodes.getPtr(node_id) orelse return status.bad_node_id_unknown;
        switch (node.attributes) {
            .variable => |*v| {
                const copy = try dupVariant(s.allocator, value);
                encoding.freeDataValue(s.allocator, v.value);
                v.value = .{
                    .value = copy,
                    .status = 0,
                    .source_timestamp = timestamp,
                    .server_timestamp = timestamp,
                };
                return 0;
            },
            .variable_type => |*v| {
                const copy = try dupVariant(s.allocator, value);
                encoding.freeDataValue(s.allocator, v.value);
                v.value = .{ .value = copy, .status = 0, .source_timestamp = timestamp, .server_timestamp = timestamp };
                return 0;
            },
            else => return status.bad_attribute_id_invalid,
        }
    }

    /// Read one attribute (OPC 10000-4 §5.10.2). The returned `DataValue`
    /// **borrows** store memory — valid until the next mutation; deep-copy it
    /// with `dupDataValue` to keep it longer. A failure is reported the way
    /// the Read service reports it: a `DataValue` carrying only a Bad
    /// `status`, never an error.
    pub fn readAttribute(s: *NodeStore, node_id: encoding.NodeId, attribute: u32) encoding.DataValue {
        const node = s.nodes.getPtr(node_id) orelse return .{ .status = status.bad_node_id_unknown };
        return readNodeAttribute(node, attribute);
    }

    fn scalarValue(v: encoding.VariantScalar) encoding.DataValue {
        return .{ .value = .{ .scalar = v }, .status = 0 };
    }

    fn readNodeAttribute(node: *Node, attribute: u32) encoding.DataValue {
        const a = services.attribute_id;
        switch (attribute) {
            a.node_id => return scalarValue(.{ .node_id = node.node_id }),
            a.node_class => return scalarValue(.{ .int32 = @intCast(@intFromEnum(node.nodeClass())) }),
            a.browse_name => return scalarValue(.{ .qualified_name = node.browse_name }),
            a.display_name => return scalarValue(.{ .localized_text = node.display_name }),
            a.description => return scalarValue(.{ .localized_text = node.description }),
            a.write_mask => return scalarValue(.{ .uint32 = node.write_mask }),
            a.user_write_mask => return scalarValue(.{ .uint32 = node.user_write_mask }),
            else => {},
        }
        switch (node.attributes) {
            .object => |o| switch (attribute) {
                a.event_notifier => return scalarValue(.{ .byte = o.event_notifier }),
                else => {},
            },
            .variable => |v| switch (attribute) {
                a.value => {
                    if (v.access_level & access_level.current_read == 0) return .{ .status = status.bad_not_readable };
                    return v.value;
                },
                a.data_type => return scalarValue(.{ .node_id = v.data_type }),
                a.value_rank => return scalarValue(.{ .int32 = v.value_rank }),
                a.array_dimensions => {
                    const dims = v.array_dimensions orelse return .{ .status = status.bad_attribute_id_invalid };
                    return .{ .value = .{ .array = .{ .items = .{ .uint32 = dims } } }, .status = 0 };
                },
                a.access_level => return scalarValue(.{ .byte = v.access_level }),
                a.user_access_level => return scalarValue(.{ .byte = v.user_access_level }),
                a.minimum_sampling_interval => return scalarValue(.{ .double = v.minimum_sampling_interval }),
                a.historizing => return scalarValue(.{ .boolean = v.historizing }),
                else => {},
            },
            .method => |m| switch (attribute) {
                a.executable => return scalarValue(.{ .boolean = m.executable }),
                a.user_executable => return scalarValue(.{ .boolean = m.user_executable }),
                else => {},
            },
            .object_type => |o| switch (attribute) {
                a.is_abstract => return scalarValue(.{ .boolean = o.is_abstract }),
                else => {},
            },
            .variable_type => |v| switch (attribute) {
                a.value => return v.value,
                a.data_type => return scalarValue(.{ .node_id = v.data_type }),
                a.value_rank => return scalarValue(.{ .int32 = v.value_rank }),
                a.is_abstract => return scalarValue(.{ .boolean = v.is_abstract }),
                a.array_dimensions => {
                    const dims = v.array_dimensions orelse return .{ .status = status.bad_attribute_id_invalid };
                    return .{ .value = .{ .array = .{ .items = .{ .uint32 = dims } } }, .status = 0 };
                },
                else => {},
            },
            .reference_type => |r| switch (attribute) {
                a.is_abstract => return scalarValue(.{ .boolean = r.is_abstract }),
                a.symmetric => return scalarValue(.{ .boolean = r.symmetric }),
                a.inverse_name => return scalarValue(.{ .localized_text = r.inverse_name }),
                else => {},
            },
            .data_type => |d| switch (attribute) {
                a.is_abstract => return scalarValue(.{ .boolean = d.is_abstract }),
                else => {},
            },
            .view => |v| switch (attribute) {
                a.contains_no_loops => return scalarValue(.{ .boolean = v.contains_no_loops }),
                a.event_notifier => return scalarValue(.{ .byte = v.event_notifier }),
                else => {},
            },
        }
        return .{ .status = status.bad_attribute_id_invalid };
    }

    /// Write one attribute (OPC 10000-4 §5.10.4). Only the Value attribute of
    /// a Variable is writable in this implementation — everything else is
    /// `BadNotWritable`, which is exactly what a server that models an
    /// immutable type system should answer. Deep-copies on success.
    ///
    /// Two independent gates apply to the Value attribute, per OPC 10000-3
    /// §8.57: `AccessLevel` is the node's static, session-independent
    /// capability ("can this Variable ever be written") and `UserAccessLevel`
    /// is the effective, per-user capability the server advertises for the
    /// current session ("can *this* user write it"). A client is told about
    /// both (both are readable attributes); a write must honor both — clear
    /// static bit -> `BadNotWritable`, clear user bit -> `BadUserAccessDenied`.
    pub fn writeAttribute(
        s: *NodeStore,
        node_id: encoding.NodeId,
        attribute: u32,
        value: encoding.DataValue,
        now: encoding.DateTime,
    ) StoreError!encoding.StatusCode {
        const node = s.nodes.getPtr(node_id) orelse return status.bad_node_id_unknown;
        // Distinguish "that attribute does not exist on this node class"
        // (BadAttributeIdInvalid — e.g. Value on an Object) from "it exists
        // but this server won't let you write it" (BadNotWritable). The read
        // path already knows which attributes each class has; a Bad *read*
        // status other than BadAttributeIdInvalid (e.g. BadNotReadable on a
        // write-only Variable) is not a write objection.
        const probe = readNodeAttribute(node, attribute);
        if (probe.status == status.bad_attribute_id_invalid) return status.bad_attribute_id_invalid;
        if (attribute != services.attribute_id.value) return status.bad_not_writable;
        switch (node.attributes) {
            .variable => |*v| {
                if (v.access_level & access_level.current_write == 0) return status.bad_not_writable;
                if (v.user_access_level & access_level.current_write == 0) return status.bad_user_access_denied;
                const incoming = value.value orelse return status.bad_type_mismatch;
                if (!builtinTypeMatches(v.data_type, incoming)) return status.bad_type_mismatch;
                if (!valueRankMatches(v.value_rank, incoming)) return status.bad_type_mismatch;
                const copy = try dupVariant(s.allocator, incoming);
                encoding.freeDataValue(s.allocator, v.value);
                v.value = .{
                    .value = copy,
                    .status = value.status orelse 0,
                    // OPC 10000-4 §5.10.4.2: a server may ignore the client's
                    // timestamps. This one keeps a client-supplied
                    // SourceTimestamp (it is the client's claim about when the
                    // value was produced) and always stamps ServerTimestamp
                    // itself.
                    .source_timestamp = value.source_timestamp orelse now,
                    .server_timestamp = now,
                };
                return 0;
            },
            else => return status.bad_not_writable,
        }
    }

    /// Type check against the Variable's DataType attribute for the built-in
    /// (namespace-0, id 1..25) data types — the ones a `Variant` can name
    /// directly. Anything else (abstract types, structures, custom
    /// namespaces) accepts any value: this store has no type-hierarchy
    /// resolution for structured DataTypes.
    fn builtinTypeMatches(data_type: encoding.NodeId, v: encoding.Variant) bool {
        const dt = switch (data_type) {
            .numeric => |n| if (n.namespace == 0) n.id else return true,
            else => return true,
        };
        if (dt == 0 or dt > 25) return true;
        const actual: u32 = switch (v) {
            .empty => return true,
            .scalar => |s| builtinIdOfScalar(s),
            .array => |arr| builtinIdOfArray(arr.items),
        };
        if (actual == dt) return true;
        // The abstract numeric super-types a concrete value legitimately
        // satisfies (OPC 10000-3 §5.8.2 DataType hierarchy).
        return switch (dt) {
            id.base_data_type => true,
            id.number => actual >= 2 and actual <= 11,
            id.integer => (actual >= 2 and actual <= 9),
            id.uinteger => actual == 3 or actual == 5 or actual == 7 or actual == 9,
            id.enumeration => actual == id.int32,
            else => false,
        };
    }

    fn builtinIdOfScalar(s: encoding.VariantScalar) u32 {
        return switch (s) {
            .boolean => 1,
            .sbyte => 2,
            .byte => 3,
            .int16 => 4,
            .uint16 => 5,
            .int32 => 6,
            .uint32 => 7,
            .int64 => 8,
            .uint64 => 9,
            .float => 10,
            .double => 11,
            .string => 12,
            .date_time => 13,
            .guid => 14,
            .byte_string => 15,
            .xml_element => 16,
            .node_id => 17,
            .expanded_node_id => 18,
            .status_code => 19,
            .qualified_name => 20,
            .localized_text => 21,
            .extension_object => 22,
        };
    }

    fn builtinIdOfArray(items: encoding.VariantArrayItems) u32 {
        return switch (items) {
            .boolean => 1,
            .sbyte => 2,
            .byte => 3,
            .int16 => 4,
            .uint16 => 5,
            .int32 => 6,
            .uint32 => 7,
            .int64 => 8,
            .uint64 => 9,
            .float => 10,
            .double => 11,
            .string => 12,
            .date_time => 13,
            .guid => 14,
            .byte_string => 15,
            .xml_element => 16,
            .node_id => 17,
            .expanded_node_id => 18,
            .status_code => 19,
            .qualified_name => 20,
            .localized_text => 21,
            .extension_object => 22,
        };
    }

    fn valueRankMatches(rank: i32, v: encoding.Variant) bool {
        return switch (v) {
            .empty => true,
            .scalar => rank == value_rank.scalar or rank == value_rank.any or rank == value_rank.scalar_or_one_dimension,
            .array => rank != value_rank.scalar,
        };
    }

    // ── convenience builders ────────────────────────────────────────────────

    /// Add an Object node under `parent` (`Organizes` by default, or
    /// `HasComponent`), typed `type_definition`.
    pub fn addObject(s: *NodeStore, opts: struct {
        node_id: encoding.NodeId,
        parent_id: encoding.NodeId,
        reference_type_id: encoding.NodeId = n0(id.organizes),
        type_definition: encoding.NodeId = n0(id.base_object_type),
        browse_name: encoding.QualifiedName,
        display_name: encoding.LocalizedText = .{},
        description: encoding.LocalizedText = .{},
        event_notifier: u8 = 0,
    }) StoreError!void {
        try s.addNode(.{
            .node_id = opts.node_id,
            .browse_name = opts.browse_name,
            .display_name = if (opts.display_name.text == null) .{ .text = opts.browse_name.name } else opts.display_name,
            .description = opts.description,
            .attributes = .{ .object = .{ .event_notifier = opts.event_notifier } },
        });
        try s.addReference(opts.parent_id, opts.reference_type_id, opts.node_id);
        try s.addReference(opts.node_id, n0(id.has_type_definition), opts.type_definition);
    }

    /// Add a folder (an Object typed `FolderType`) under `parent`.
    pub fn addFolder(s: *NodeStore, opts: struct {
        node_id: encoding.NodeId,
        parent_id: encoding.NodeId,
        browse_name: encoding.QualifiedName,
        display_name: encoding.LocalizedText = .{},
    }) StoreError!void {
        try s.addObject(.{
            .node_id = opts.node_id,
            .parent_id = opts.parent_id,
            .type_definition = n0(id.folder_type),
            .browse_name = opts.browse_name,
            .display_name = opts.display_name,
        });
    }

    /// Add a Variable node under `parent`.
    pub fn addVariable(s: *NodeStore, opts: struct {
        node_id: encoding.NodeId,
        parent_id: encoding.NodeId,
        reference_type_id: encoding.NodeId = n0(id.has_component),
        type_definition: encoding.NodeId = n0(id.base_data_variable_type),
        browse_name: encoding.QualifiedName,
        display_name: encoding.LocalizedText = .{},
        description: encoding.LocalizedText = .{},
        value: encoding.Variant = .empty,
        data_type: encoding.NodeId = n0(id.base_data_type),
        value_rank: i32 = value_rank.scalar,
        access_level: u8 = access_level.current_read,
        /// The effective, per-user `AccessLevel` (OPC 10000-3 §8.57) —
        /// `null` (the default) mirrors `access_level`, matching this
        /// server's historical behavior where the two were never
        /// distinguishable. Set explicitly to advertise (and enforce) a
        /// user-level capability narrower than the static one, e.g. a
        /// Variable that is statically read/write but read-only for the
        /// current user.
        user_access_level: ?u8 = null,
        timestamp: ?encoding.DateTime = null,
    }) StoreError!void {
        try s.addNode(.{
            .node_id = opts.node_id,
            .browse_name = opts.browse_name,
            .display_name = if (opts.display_name.text == null) .{ .text = opts.browse_name.name } else opts.display_name,
            .description = opts.description,
            .attributes = .{ .variable = .{
                .value = .{
                    .value = opts.value,
                    .status = 0,
                    .source_timestamp = opts.timestamp,
                    .server_timestamp = opts.timestamp,
                },
                .data_type = opts.data_type,
                .value_rank = opts.value_rank,
                .access_level = opts.access_level,
                .user_access_level = opts.user_access_level orelse opts.access_level,
            } },
        });
        try s.addReference(opts.parent_id, opts.reference_type_id, opts.node_id);
        try s.addReference(opts.node_id, n0(id.has_type_definition), opts.type_definition);
    }

    /// Add a Method node under `parent` (`HasComponent`, per OPC 10000-3
    /// §5.7: a Method is always a component of the Object it is called on).
    pub fn addMethod(s: *NodeStore, opts: struct {
        node_id: encoding.NodeId,
        parent_id: encoding.NodeId,
        browse_name: encoding.QualifiedName,
        display_name: encoding.LocalizedText = .{},
        implementation: ?MethodFn = null,
        user_context: ?*anyopaque = null,
        executable: bool = true,
        /// The effective, per-user `Executable` — `null` (the default)
        /// mirrors `executable`. `Call` already honors both bits
        /// (`server.zig`), so this only makes the narrower user-level
        /// capability expressible, exactly as `user_access_level` does for
        /// Variables.
        user_executable: ?bool = null,
    }) StoreError!void {
        try s.addNode(.{
            .node_id = opts.node_id,
            .browse_name = opts.browse_name,
            .display_name = if (opts.display_name.text == null) .{ .text = opts.browse_name.name } else opts.display_name,
            .attributes = .{ .method = .{
                .executable = opts.executable,
                .user_executable = opts.user_executable orelse opts.executable,
                .implementation = opts.implementation,
                .user_context = opts.user_context,
            } },
        });
        try s.addReference(opts.parent_id, n0(id.has_component), opts.node_id);
    }

    // ── the standard namespace-0 skeleton ───────────────────────────────────

    /// Seed the standard namespace-0 nodes a client needs to browse from
    /// `RootFolder` (i=84) down to a user variable and to resolve the
    /// reference/type hierarchy on the way: the four top folders, the type
    /// folders, the ReferenceType tree, the base Object/Variable types, the
    /// built-in DataTypes, and the Server object with ServerArray/
    /// NamespaceArray/ServerStatus (+ StartTime/CurrentTime/State/BuildInfo).
    ///
    /// This is a deliberately *minimal* ns0: it is the browsable skeleton, not
    /// the full ~2000-node standard nodeset (which is a generated artifact of
    /// the OPC Foundation NodeSet2 XML — out of scope here; see SPEC.md).
    pub fn addStandardNodes(s: *NodeStore, opts: struct {
        /// `Server_ServerStatus_StartTime` and the initial CurrentTime.
        start_time: encoding.DateTime = 0,
        product_name: []const u8 = "zig-libs opcua server",
        product_uri: []const u8 = "urn:zig-libs:opcua:server",
        manufacturer_name: []const u8 = "zig-libs",
        software_version: []const u8 = "0.1.0",
        build_number: []const u8 = "0",
    }) StoreError!void {
        _ = try s.addNamespace(opc_ua_namespace_uri);

        // ── ReferenceTypes (added first: addReference targets must exist).
        try s.addNode(.{
            .node_id = n0(id.references),
            .browse_name = .{ .namespace_index = 0, .name = "References" },
            .display_name = .{ .text = "References" },
            .attributes = .{ .reference_type = .{ .is_abstract = true, .symmetric = true } },
        });
        const ref_types = [_]struct { u32, []const u8, []const u8, u32, bool, bool }{
            // id, browse name, inverse name, supertype, abstract, symmetric
            .{ id.hierarchical_references, "HierarchicalReferences", "InverseHierarchicalReferences", id.references, true, false },
            .{ id.non_hierarchical_references, "NonHierarchicalReferences", "InverseNonHierarchicalReferences", id.references, true, true },
            .{ id.has_child, "HasChild", "ChildOf", id.hierarchical_references, true, false },
            .{ id.organizes, "Organizes", "OrganizedBy", id.hierarchical_references, false, false },
            .{ id.aggregates, "Aggregates", "AggregatedBy", id.has_child, true, false },
            .{ id.has_subtype, "HasSubtype", "SubtypeOf", id.has_child, false, false },
            .{ id.has_property, "HasProperty", "PropertyOf", id.aggregates, false, false },
            .{ id.has_component, "HasComponent", "ComponentOf", id.aggregates, false, false },
            .{ id.has_type_definition, "HasTypeDefinition", "TypeDefinitionOf", id.non_hierarchical_references, false, false },
            .{ id.has_modelling_rule, "HasModellingRule", "ModellingRuleOf", id.non_hierarchical_references, false, false },
        };
        for (ref_types) |rt| {
            try s.addNode(.{
                .node_id = n0(rt[0]),
                .browse_name = .{ .namespace_index = 0, .name = rt[1] },
                .display_name = .{ .text = rt[1] },
                .attributes = .{ .reference_type = .{
                    .is_abstract = rt[4],
                    .symmetric = rt[5],
                    .inverse_name = .{ .text = rt[2] },
                } },
            });
        }
        for (ref_types) |rt| try s.addReference(n0(rt[3]), n0(id.has_subtype), n0(rt[0]));

        // ── ObjectTypes / VariableTypes.
        try s.addNode(.{
            .node_id = n0(id.base_object_type),
            .browse_name = .{ .namespace_index = 0, .name = "BaseObjectType" },
            .display_name = .{ .text = "BaseObjectType" },
            .attributes = .{ .object_type = .{} },
        });
        try s.addNode(.{
            .node_id = n0(id.folder_type),
            .browse_name = .{ .namespace_index = 0, .name = "FolderType" },
            .display_name = .{ .text = "FolderType" },
            .attributes = .{ .object_type = .{} },
        });
        try s.addNode(.{
            .node_id = n0(id.server_type),
            .browse_name = .{ .namespace_index = 0, .name = "ServerType" },
            .display_name = .{ .text = "ServerType" },
            .attributes = .{ .object_type = .{} },
        });
        try s.addReference(n0(id.base_object_type), n0(id.has_subtype), n0(id.folder_type));
        try s.addReference(n0(id.base_object_type), n0(id.has_subtype), n0(id.server_type));

        try s.addNode(.{
            .node_id = n0(id.base_variable_type),
            .browse_name = .{ .namespace_index = 0, .name = "BaseVariableType" },
            .display_name = .{ .text = "BaseVariableType" },
            .attributes = .{ .variable_type = .{ .is_abstract = true } },
        });
        try s.addNode(.{
            .node_id = n0(id.base_data_variable_type),
            .browse_name = .{ .namespace_index = 0, .name = "BaseDataVariableType" },
            .display_name = .{ .text = "BaseDataVariableType" },
            .attributes = .{ .variable_type = .{} },
        });
        try s.addNode(.{
            .node_id = n0(id.property_type),
            .browse_name = .{ .namespace_index = 0, .name = "PropertyType" },
            .display_name = .{ .text = "PropertyType" },
            .attributes = .{ .variable_type = .{} },
        });
        try s.addNode(.{
            .node_id = n0(id.server_status_type),
            .browse_name = .{ .namespace_index = 0, .name = "ServerStatusType" },
            .display_name = .{ .text = "ServerStatusType" },
            .attributes = .{ .variable_type = .{ .data_type = n0(id.server_status_data_type) } },
        });
        try s.addReference(n0(id.base_variable_type), n0(id.has_subtype), n0(id.base_data_variable_type));
        try s.addReference(n0(id.base_variable_type), n0(id.has_subtype), n0(id.property_type));
        try s.addReference(n0(id.base_data_variable_type), n0(id.has_subtype), n0(id.server_status_type));

        // ── DataTypes.
        try s.addNode(.{
            .node_id = n0(id.base_data_type),
            .browse_name = .{ .namespace_index = 0, .name = "BaseDataType" },
            .display_name = .{ .text = "BaseDataType" },
            .attributes = .{ .data_type = .{ .is_abstract = true } },
        });
        const data_types = [_]struct { u32, []const u8, u32, bool }{
            .{ id.boolean, "Boolean", id.base_data_type, false },
            .{ id.number, "Number", id.base_data_type, true },
            .{ id.integer, "Integer", id.number, true },
            .{ id.uinteger, "UInteger", id.integer, true },
            .{ id.enumeration, "Enumeration", id.base_data_type, true },
            .{ id.sbyte, "SByte", id.integer, false },
            .{ id.int16, "Int16", id.integer, false },
            .{ id.int32, "Int32", id.integer, false },
            .{ id.int64, "Int64", id.integer, false },
            .{ id.byte, "Byte", id.uinteger, false },
            .{ id.uint16, "UInt16", id.uinteger, false },
            .{ id.uint32, "UInt32", id.uinteger, false },
            .{ id.uint64, "UInt64", id.uinteger, false },
            .{ id.float, "Float", id.number, false },
            .{ id.double, "Double", id.number, false },
            .{ id.string, "String", id.base_data_type, false },
            .{ id.date_time, "DateTime", id.base_data_type, false },
            .{ id.guid, "Guid", id.base_data_type, false },
            .{ id.byte_string, "ByteString", id.base_data_type, false },
            .{ id.xml_element, "XmlElement", id.base_data_type, false },
            .{ id.node_id, "NodeId", id.base_data_type, false },
            .{ id.status_code, "StatusCode", id.base_data_type, false },
            .{ id.qualified_name, "QualifiedName", id.base_data_type, false },
            .{ id.localized_text, "LocalizedText", id.base_data_type, false },
            .{ id.structure, "Structure", id.base_data_type, true },
            .{ id.server_state_data_type, "ServerState", id.enumeration, false },
            .{ id.build_info_data_type, "BuildInfo", id.structure, false },
            .{ id.server_status_data_type, "ServerStatusDataType", id.structure, false },
        };
        for (data_types) |dt| {
            try s.addNode(.{
                .node_id = n0(dt[0]),
                .browse_name = .{ .namespace_index = 0, .name = dt[1] },
                .display_name = .{ .text = dt[1] },
                .attributes = .{ .data_type = .{ .is_abstract = dt[3] } },
            });
        }
        for (data_types) |dt| try s.addReference(n0(dt[2]), n0(id.has_subtype), n0(dt[0]));

        // ── the four top-level folders.
        try s.addNode(.{
            .node_id = n0(id.root_folder),
            .browse_name = .{ .namespace_index = 0, .name = "Root" },
            .display_name = .{ .text = "Root" },
            .attributes = .{ .object = .{} },
        });
        try s.addReference(n0(id.root_folder), n0(id.has_type_definition), n0(id.folder_type));
        const folders = [_]struct { u32, []const u8 }{
            .{ id.objects_folder, "Objects" },
            .{ id.types_folder, "Types" },
            .{ id.views_folder, "Views" },
        };
        for (folders) |f| {
            try s.addFolder(.{
                .node_id = n0(f[0]),
                .parent_id = n0(id.root_folder),
                .browse_name = .{ .namespace_index = 0, .name = f[1] },
            });
        }
        const type_folders = [_]struct { u32, []const u8, u32 }{
            .{ id.object_types_folder, "ObjectTypes", id.base_object_type },
            .{ id.variable_types_folder, "VariableTypes", id.base_variable_type },
            .{ id.data_types_folder, "DataTypes", id.base_data_type },
            .{ id.reference_types_folder, "ReferenceTypes", id.references },
        };
        for (type_folders) |tf| {
            try s.addFolder(.{
                .node_id = n0(tf[0]),
                .parent_id = n0(id.types_folder),
                .browse_name = .{ .namespace_index = 0, .name = tf[1] },
            });
            try s.addReference(n0(tf[0]), n0(id.organizes), n0(tf[2]));
        }

        // ── the Server object.
        try s.addObject(.{
            .node_id = n0(id.server),
            .parent_id = n0(id.objects_folder),
            .type_definition = n0(id.server_type),
            .browse_name = .{ .namespace_index = 0, .name = "Server" },
            .display_name = .{ .text = "Server" },
        });
        try s.addVariable(.{
            .node_id = n0(id.server_server_array),
            .parent_id = n0(id.server),
            .reference_type_id = n0(id.has_property),
            .type_definition = n0(id.property_type),
            .browse_name = .{ .namespace_index = 0, .name = "ServerArray" },
            .value = .{ .array = .{ .items = .{ .string = &.{opts.product_uri} } } },
            .data_type = n0(id.string),
            .value_rank = value_rank.one_dimension,
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_namespace_array),
            .parent_id = n0(id.server),
            .reference_type_id = n0(id.has_property),
            .type_definition = n0(id.property_type),
            .browse_name = .{ .namespace_index = 0, .name = "NamespaceArray" },
            .value = .{ .array = .{ .items = .{ .string = &.{opc_ua_namespace_uri} } } },
            .data_type = n0(id.string),
            .value_rank = value_rank.one_dimension,
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_status),
            .parent_id = n0(id.server),
            .type_definition = n0(id.server_status_type),
            .browse_name = .{ .namespace_index = 0, .name = "ServerStatus" },
            .data_type = n0(id.server_status_data_type),
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_status_start_time),
            .parent_id = n0(id.server_status),
            .browse_name = .{ .namespace_index = 0, .name = "StartTime" },
            .value = .{ .scalar = .{ .date_time = opts.start_time } },
            .data_type = n0(id.date_time),
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_status_current_time),
            .parent_id = n0(id.server_status),
            .browse_name = .{ .namespace_index = 0, .name = "CurrentTime" },
            .value = .{ .scalar = .{ .date_time = opts.start_time } },
            .data_type = n0(id.date_time),
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_status_state),
            .parent_id = n0(id.server_status),
            .browse_name = .{ .namespace_index = 0, .name = "State" },
            .value = .{ .scalar = .{ .int32 = 0 } }, // ServerState.Running
            .data_type = n0(id.server_state_data_type),
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_status_build_info),
            .parent_id = n0(id.server_status),
            .browse_name = .{ .namespace_index = 0, .name = "BuildInfo" },
            .data_type = n0(id.build_info_data_type),
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_service_level),
            .parent_id = n0(id.server),
            .reference_type_id = n0(id.has_property),
            .type_definition = n0(id.property_type),
            .browse_name = .{ .namespace_index = 0, .name = "ServiceLevel" },
            .value = .{ .scalar = .{ .byte = 255 } },
            .data_type = n0(id.byte),
            .timestamp = opts.start_time,
        });
        try s.addVariable(.{
            .node_id = n0(id.server_auditing),
            .parent_id = n0(id.server),
            .reference_type_id = n0(id.has_property),
            .type_definition = n0(id.property_type),
            .browse_name = .{ .namespace_index = 0, .name = "Auditing" },
            .value = .{ .scalar = .{ .boolean = false } },
            .data_type = n0(id.boolean),
            .timestamp = opts.start_time,
        });

        try s.refreshServerStatus(.{
            .start_time = opts.start_time,
            .current_time = opts.start_time,
            .product_name = opts.product_name,
            .product_uri = opts.product_uri,
            .manufacturer_name = opts.manufacturer_name,
            .software_version = opts.software_version,
            .build_number = opts.build_number,
            .build_date = opts.start_time,
        });
    }

    pub const ServerStatusInfo = struct {
        start_time: encoding.DateTime,
        current_time: encoding.DateTime,
        product_name: []const u8 = "zig-libs opcua server",
        product_uri: []const u8 = "urn:zig-libs:opcua:server",
        manufacturer_name: []const u8 = "zig-libs",
        software_version: []const u8 = "0.1.0",
        build_number: []const u8 = "0",
        build_date: encoding.DateTime = 0,
        /// `ServerState` (OPC 10000-5 §12.6): 0 = Running.
        state: i32 = 0,
        seconds_till_shutdown: u32 = 0,
    };

    /// Re-encode `Server_ServerStatus` (i=2256) and `..._BuildInfo` (i=2260)
    /// as their `ExtensionObject` values, and refresh CurrentTime (i=2258).
    /// Caller-driven — this store owns no clock (see the module's "no owned
    /// timers" invariant); a simulation calls this from its own loop.
    pub fn refreshServerStatus(s: *NodeStore, info: ServerStatusInfo) StoreError!void {
        var build_info_bytes = std.Io.Writer.Allocating.init(s.allocator);
        defer build_info_bytes.deinit();
        var bi = encoding.Encoder.init(&build_info_bytes.writer);
        encodeBuildInfo(&bi, info) catch return error.OutOfMemory;

        var status_bytes = std.Io.Writer.Allocating.init(s.allocator);
        defer status_bytes.deinit();
        var st = encoding.Encoder.init(&status_bytes.writer);
        encodeServerStatus(&st, info) catch return error.OutOfMemory;

        _ = try s.setValue(n0(id.server_status_build_info), .{ .scalar = .{ .extension_object = .{
            .type_id = n0(id.build_info_binary),
            .encoding = .byte_string,
            .body = build_info_bytes.writer.buffered(),
        } } }, info.current_time);
        _ = try s.setValue(n0(id.server_status), .{ .scalar = .{ .extension_object = .{
            .type_id = n0(id.server_status_data_type_binary),
            .encoding = .byte_string,
            .body = status_bytes.writer.buffered(),
        } } }, info.current_time);
        _ = try s.setValue(n0(id.server_status_current_time), .{ .scalar = .{ .date_time = info.current_time } }, info.current_time);
    }

    /// `BuildInfo` (OPC 10000-5 §12.4) in OPC UA Binary field order.
    fn encodeBuildInfo(e: *encoding.Encoder, info: ServerStatusInfo) encoding.EncodeError!void {
        try e.encodeString(info.product_uri);
        try e.encodeString(info.manufacturer_name);
        try e.encodeString(info.product_name);
        try e.encodeString(info.software_version);
        try e.encodeString(info.build_number);
        try e.encodeDateTime(info.build_date);
    }

    /// `ServerStatusDataType` (OPC 10000-5 §12.10) in OPC UA Binary field
    /// order: StartTime, CurrentTime, State, BuildInfo (inline structure —
    /// not an ExtensionObject: a structured *field* of a structure is encoded
    /// inline, OPC 10000-6 §5.2.6), SecondsTillShutdown, ShutdownReason.
    fn encodeServerStatus(e: *encoding.Encoder, info: ServerStatusInfo) encoding.EncodeError!void {
        try e.encodeDateTime(info.start_time);
        try e.encodeDateTime(info.current_time);
        try e.encodeInt32(info.state);
        try encodeBuildInfo(e, info);
        try e.encodeUInt32(info.seconds_till_shutdown);
        try e.encodeLocalizedText(.{});
    }

    /// Re-publish the NamespaceArray variable from `namespaces` — call after
    /// `addNamespace` so a client's `Read` of i=2255 stays in sync.
    pub fn refreshNamespaceArray(s: *NodeStore) StoreError!void {
        const items = try s.allocator.alloc(?[]const u8, s.namespaces.items.len);
        defer s.allocator.free(items);
        for (s.namespaces.items, 0..) |uri, i| items[i] = uri;
        _ = try s.setValue(n0(id.server_namespace_array), .{ .array = .{ .items = .{ .string = items } } }, null);
    }
};

pub const opc_ua_namespace_uri = "http://opcfoundation.org/UA/";

/// Bound on `isSubtypeOf`'s upward walk — a store built with a reference cycle
/// (only reachable through the caller-facing `addReference`, which does not
/// check for one) must not hang the server.
const max_subtype_depth: usize = 64;

/// The StatusCode table (OPC Foundation UA-Nodeset `Schema/StatusCode.csv`,
/// MIT License 1.00) — re-exported from `services` so a caller reading this
/// store's results never has to reach across modules for the constants.
pub const status = services.status;

// ── tests ──

const testing = std.testing;

fn testStore() !NodeStore {
    var s = NodeStore.init(testing.allocator);
    errdefer s.deinit();
    try s.addStandardNodes(.{ .start_time = 132_223_104_000_000_000 });
    return s;
}

test "standard nodes: RootFolder browses down to Objects/Server and the type folders" {
    var s = try testStore();
    defer s.deinit();

    const root = s.getNode(n0(id.root_folder)).?;
    try testing.expectEqualStrings("Root", root.browse_name.name.?);
    try testing.expectEqual(services.NodeClass.object, root.nodeClass());

    var found_objects = false;
    var found_types = false;
    var found_views = false;
    for (root.references.items) |ref| {
        if (!ref.is_forward) continue;
        if (!services.nodeIdEql(ref.reference_type_id, n0(id.organizes))) continue;
        if (services.nodeIdEql(ref.target_id.node_id, n0(id.objects_folder))) found_objects = true;
        if (services.nodeIdEql(ref.target_id.node_id, n0(id.types_folder))) found_types = true;
        if (services.nodeIdEql(ref.target_id.node_id, n0(id.views_folder))) found_views = true;
    }
    try testing.expect(found_objects and found_types and found_views);

    // Objects -> Server, and Server is typed ServerType.
    const objects = s.getNode(n0(id.objects_folder)).?;
    var found_server = false;
    for (objects.references.items) |ref| {
        if (ref.is_forward and services.nodeIdEql(ref.target_id.node_id, n0(id.server))) found_server = true;
    }
    try testing.expect(found_server);
    try testing.expect(services.nodeIdEql(s.typeDefinition(n0(id.server)).?, n0(id.server_type)));
}

test "standard nodes: the inverse half of every reference is stored on the target" {
    var s = try testStore();
    defer s.deinit();
    const objects = s.getNode(n0(id.objects_folder)).?;
    var found_inverse_root = false;
    for (objects.references.items) |ref| {
        if (!ref.is_forward and services.nodeIdEql(ref.target_id.node_id, n0(id.root_folder))) found_inverse_root = true;
    }
    try testing.expect(found_inverse_root);
}

test "isSubtypeOf walks the HasSubtype hierarchy (and stops at unrelated types)" {
    var s = try testStore();
    defer s.deinit();
    try testing.expect(s.isSubtypeOf(n0(id.has_component), n0(id.hierarchical_references)));
    try testing.expect(s.isSubtypeOf(n0(id.organizes), n0(id.references)));
    try testing.expect(s.isSubtypeOf(n0(id.has_component), n0(id.has_component)));
    try testing.expect(!s.isSubtypeOf(n0(id.organizes), n0(id.has_component)));
    try testing.expect(!s.isSubtypeOf(n0(id.has_type_definition), n0(id.hierarchical_references)));
}

test "readAttribute: node/class/browse-name/value + BadNodeIdUnknown / BadAttributeIdInvalid" {
    var s = try testStore();
    defer s.deinit();

    const dv = s.readAttribute(n0(id.server_status_current_time), services.attribute_id.value);
    try testing.expectEqual(@as(encoding.StatusCode, 0), dv.status.?);
    try testing.expectEqual(@as(encoding.DateTime, 132_223_104_000_000_000), dv.value.?.scalar.date_time);

    const cls = s.readAttribute(n0(id.server), services.attribute_id.node_class);
    try testing.expectEqual(@as(i32, @intFromEnum(services.NodeClass.object)), cls.value.?.scalar.int32);

    const missing = s.readAttribute(n0(999_999), services.attribute_id.value);
    try testing.expectEqual(status.bad_node_id_unknown, missing.status.?);

    // An Object node has no Value attribute.
    const bad_attr = s.readAttribute(n0(id.server), services.attribute_id.value);
    try testing.expectEqual(status.bad_attribute_id_invalid, bad_attr.status.?);
}

test "writeAttribute: Good on a writable variable, BadNotWritable / BadTypeMismatch otherwise" {
    var s = try testStore();
    defer s.deinit();
    const ns = try s.addNamespace("urn:zig-libs:opcua:test");
    const var_id: encoding.NodeId = .{ .string = .{ .namespace = ns, .id = "the.answer" } };
    try s.addVariable(.{
        .node_id = var_id,
        .parent_id = n0(id.objects_folder),
        .browse_name = .{ .namespace_index = ns, .name = "the answer" },
        .value = .{ .scalar = .{ .int32 = 42 } },
        .data_type = n0(id.int32),
        .access_level = access_level.read_write,
    });

    try testing.expectEqual(status.good, try s.writeAttribute(var_id, services.attribute_id.value, .{ .value = .{ .scalar = .{ .int32 = 43 } } }, 1000));
    try testing.expectEqual(@as(i32, 43), s.readAttribute(var_id, services.attribute_id.value).value.?.scalar.int32);
    try testing.expectEqual(@as(encoding.DateTime, 1000), s.readAttribute(var_id, services.attribute_id.value).server_timestamp.?);

    // Wrong built-in type for the declared DataType.
    try testing.expectEqual(status.bad_type_mismatch, try s.writeAttribute(var_id, services.attribute_id.value, .{ .value = .{ .scalar = .{ .string = "nope" } } }, 1000));
    // A read-only standard node.
    try testing.expectEqual(status.bad_not_writable, try s.writeAttribute(n0(id.server_status_current_time), services.attribute_id.value, .{ .value = .{ .scalar = .{ .date_time = 5 } } }, 1000));
    // A non-Value attribute of an existing node.
    try testing.expectEqual(status.bad_not_writable, try s.writeAttribute(var_id, services.attribute_id.display_name, .{ .value = .{ .scalar = .{ .localized_text = .{ .text = "x" } } } }, 1000));
    // An attribute the node class does not have at all.
    try testing.expectEqual(status.bad_attribute_id_invalid, try s.writeAttribute(n0(id.server), services.attribute_id.value, .{ .value = .{ .scalar = .{ .int32 = 1 } } }, 1000));
    // A node that does not exist.
    try testing.expectEqual(status.bad_node_id_unknown, try s.writeAttribute(n0(999_999), services.attribute_id.value, .{ .value = .{ .scalar = .{ .int32 = 1 } } }, 1000));
}

test "writeAttribute: AccessLevel and UserAccessLevel are enforced independently" {
    var s = try testStore();
    defer s.deinit();
    const ns = try s.addNamespace("urn:zig-libs:opcua:test");

    // Both the static AccessLevel and the per-user UserAccessLevel allow
    // writing: the write must go through.
    const both_id: encoding.NodeId = .{ .string = .{ .namespace = ns, .id = "both" } };
    try s.addVariable(.{
        .node_id = both_id,
        .parent_id = n0(id.objects_folder),
        .browse_name = .{ .namespace_index = ns, .name = "both" },
        .value = .{ .scalar = .{ .int32 = 1 } },
        .data_type = n0(id.int32),
        .access_level = access_level.read_write,
        .user_access_level = access_level.read_write,
    });
    try testing.expectEqual(status.good, try s.writeAttribute(both_id, services.attribute_id.value, .{ .value = .{ .scalar = .{ .int32 = 2 } } }, 1000));

    // Static AccessLevel forbids writing (read-only node type), even though
    // UserAccessLevel alone would allow it -> BadNotWritable.
    const static_only_id: encoding.NodeId = .{ .string = .{ .namespace = ns, .id = "static_only" } };
    try s.addVariable(.{
        .node_id = static_only_id,
        .parent_id = n0(id.objects_folder),
        .browse_name = .{ .namespace_index = ns, .name = "static_only" },
        .value = .{ .scalar = .{ .int32 = 1 } },
        .data_type = n0(id.int32),
        .access_level = access_level.current_read,
        .user_access_level = access_level.read_write,
    });
    try testing.expectEqual(status.bad_not_writable, try s.writeAttribute(static_only_id, services.attribute_id.value, .{ .value = .{ .scalar = .{ .int32 = 2 } } }, 1000));

    // Static AccessLevel allows writing, but the current user's effective
    // UserAccessLevel does not -> BadUserAccessDenied. This is the case the
    // server used to get wrong: it advertised UserAccessLevel to clients but
    // never enforced it, so a write went through even with the user-level
    // write bit clear.
    const user_denied_id: encoding.NodeId = .{ .string = .{ .namespace = ns, .id = "user_denied" } };
    try s.addVariable(.{
        .node_id = user_denied_id,
        .parent_id = n0(id.objects_folder),
        .browse_name = .{ .namespace_index = ns, .name = "user_denied" },
        .value = .{ .scalar = .{ .int32 = 1 } },
        .data_type = n0(id.int32),
        .access_level = access_level.read_write,
        .user_access_level = access_level.current_read,
    });
    try testing.expectEqual(status.bad_user_access_denied, try s.writeAttribute(user_denied_id, services.attribute_id.value, .{ .value = .{ .scalar = .{ .int32 = 2 } } }, 1000));
    // The value must be unchanged: the write was refused, not merely
    // reported as refused.
    try testing.expectEqual(@as(i32, 1), s.readAttribute(user_denied_id, services.attribute_id.value).value.?.scalar.int32);

    // Backward compatibility: omitting `user_access_level` mirrors
    // `access_level`, exactly like before this attribute could be set
    // independently.
    const default_id: encoding.NodeId = .{ .string = .{ .namespace = ns, .id = "default_mirrors_access" } };
    try s.addVariable(.{
        .node_id = default_id,
        .parent_id = n0(id.objects_folder),
        .browse_name = .{ .namespace_index = ns, .name = "default_mirrors_access" },
        .value = .{ .scalar = .{ .int32 = 1 } },
        .data_type = n0(id.int32),
        .access_level = access_level.read_write,
    });
    try testing.expectEqual(status.good, try s.writeAttribute(default_id, services.attribute_id.value, .{ .value = .{ .scalar = .{ .int32 = 2 } } }, 1000));
}

test "setValue deep-copies (the caller's buffer may die immediately after)" {
    var s = try testStore();
    defer s.deinit();
    const var_id = n0(60_000);
    try s.addVariable(.{
        .node_id = var_id,
        .parent_id = n0(id.objects_folder),
        .browse_name = .{ .namespace_index = 0, .name = "text" },
        .data_type = n0(id.string),
    });
    {
        var scratch: [8]u8 = "hello!!\x00".*;
        _ = try s.setValue(var_id, .{ .scalar = .{ .string = scratch[0..6] } }, 7);
        @memset(&scratch, 0xaa); // the caller's buffer is gone/overwritten
    }
    try testing.expectEqualStrings("hello!", s.readAttribute(var_id, services.attribute_id.value).value.?.scalar.string.?);
}

test "dataValueChanged: value and status trigger, timestamps alone do not" {
    const a: encoding.DataValue = .{ .value = .{ .scalar = .{ .int32 = 1 } }, .status = 0, .server_timestamp = 100 };
    const b: encoding.DataValue = .{ .value = .{ .scalar = .{ .int32 = 1 } }, .status = 0, .server_timestamp = 200 };
    try testing.expect(!dataValueChanged(a, b));
    const c: encoding.DataValue = .{ .value = .{ .scalar = .{ .int32 = 2 } }, .status = 0 };
    try testing.expect(dataValueChanged(a, c));
    const d: encoding.DataValue = .{ .value = .{ .scalar = .{ .int32 = 1 } }, .status = 0x8034_0000 };
    try testing.expect(dataValueChanged(a, d));
    const e: encoding.DataValue = .{ .value = .{ .scalar = .{ .string = "x" } }, .status = 0 };
    try testing.expect(dataValueChanged(a, e));
    // String arrays compare element-wise.
    const f: encoding.DataValue = .{ .value = .{ .array = .{ .items = .{ .string = &.{ "a", "b" } } } }, .status = 0 };
    const g: encoding.DataValue = .{ .value = .{ .array = .{ .items = .{ .string = &.{ "a", "b" } } } }, .status = 0 };
    const h: encoding.DataValue = .{ .value = .{ .array = .{ .items = .{ .string = &.{ "a", "c" } } } }, .status = 0 };
    try testing.expect(!dataValueChanged(f, g));
    try testing.expect(dataValueChanged(f, h));
}

test "dup helpers round-trip through encoding.free* (no leak, no double free)" {
    const a = testing.allocator;
    const original: encoding.DataValue = .{
        .value = .{ .array = .{
            .items = .{ .localized_text = &.{ .{ .locale = "en", .text = "one" }, .{ .text = "two" } } },
            .dimensions = &.{2},
        } },
        .status = 0,
    };
    const copy = try dupDataValue(a, original);
    defer encoding.freeDataValue(a, copy);
    try testing.expect(!dataValueChanged(original, copy));

    const nid: encoding.NodeId = .{ .string = .{ .namespace = 3, .id = "some.node" } };
    const nid_copy = try dupNodeId(a, nid);
    defer encoding.freeNodeId(a, nid_copy);
    try testing.expect(services.nodeIdEql(nid, nid_copy));
}

test "addNamespace / refreshNamespaceArray keeps i=2255 in sync" {
    var s = try testStore();
    defer s.deinit();
    const ns = try s.addNamespace("urn:zig-libs:opcua:test");
    try testing.expectEqual(@as(u16, 1), ns);
    try testing.expectEqual(@as(u16, 1), try s.addNamespace("urn:zig-libs:opcua:test")); // idempotent
    try s.refreshNamespaceArray();
    const dv = s.readAttribute(n0(id.server_namespace_array), services.attribute_id.value);
    const arr = dv.value.?.array.items.string.?;
    try testing.expectEqual(@as(usize, 2), arr.len);
    try testing.expectEqualStrings(opc_ua_namespace_uri, arr[0].?);
    try testing.expectEqualStrings("urn:zig-libs:opcua:test", arr[1].?);
}

test "refreshServerStatus re-encodes i=2256 as a ServerStatusDataType ExtensionObject" {
    var s = try testStore();
    defer s.deinit();
    try s.refreshServerStatus(.{ .start_time = 100, .current_time = 500 });
    const dv = s.readAttribute(n0(id.server_status), services.attribute_id.value);
    const eo = dv.value.?.scalar.extension_object;
    try testing.expect(services.nodeIdEql(eo.type_id, n0(id.server_status_data_type_binary)));
    var r: std.Io.Reader = .fixed(eo.body);
    var d = encoding.Decoder.init(&r, testing.allocator);
    try testing.expectEqual(@as(encoding.DateTime, 100), try d.decodeDateTime());
    try testing.expectEqual(@as(encoding.DateTime, 500), try d.decodeDateTime());
    try testing.expectEqual(@as(i32, 0), try d.decodeInt32()); // ServerState.Running
    // CurrentTime (i=2258) tracks the same clock value.
    try testing.expectEqual(@as(encoding.DateTime, 500), s.readAttribute(n0(id.server_status_current_time), services.attribute_id.value).value.?.scalar.date_time);
}

test "addNode twice replaces attributes but keeps references" {
    var s = try testStore();
    defer s.deinit();
    const nid = n0(61_000);
    try s.addVariable(.{
        .node_id = nid,
        .parent_id = n0(id.objects_folder),
        .browse_name = .{ .namespace_index = 0, .name = "v" },
        .value = .{ .scalar = .{ .int32 = 1 } },
        .data_type = n0(id.int32),
    });
    const refs_before = s.getNode(nid).?.references.items.len;
    try s.addNode(.{
        .node_id = nid,
        .browse_name = .{ .namespace_index = 0, .name = "v2" },
        .attributes = .{ .variable = .{ .value = .{ .value = .{ .scalar = .{ .int32 = 9 } }, .status = 0 }, .data_type = n0(id.int32) } },
    });
    try testing.expectEqualStrings("v2", s.getNode(nid).?.browse_name.name.?);
    try testing.expectEqual(refs_before, s.getNode(nid).?.references.items.len);
    try testing.expectEqual(@as(i32, 9), s.readAttribute(nid, services.attribute_id.value).value.?.scalar.int32);
}
