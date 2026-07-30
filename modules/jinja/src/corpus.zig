// SPDX-License-Identifier: MIT
//! The conformance corpus: templates + contexts, rendered by BOTH this module
//! and Python Jinja2 and compared byte for byte.
//!
//! It is deliberately weighted towards the parts that are easy to get subtly
//! wrong and hard to notice — whitespace control combinations, `loop` inside
//! nested loops, `{% set %}` scoping in a loop body, floor division and modulo
//! on negatives, filter argument evaluation, and autoescape interacting with
//! `|safe` — rather than towards the parts a smoke test already covers.
//!
//! One table, two consumers: `reference_test.zig` (live Python) and
//! `golden_test.zig` (committed output of that same Python). Adding a case here
//! makes both oracles cover it; the golden test fails until the golden file is
//! regenerated, which is the intended friction.

const std = @import("std");

pub const Case = struct {
    name: []const u8,
    template: []const u8,
    /// The render context, as JSON (so the Python side gets it verbatim).
    context: []const u8 = "{}",
    autoescape: bool = false,
    /// `true` selects `StrictUndefined` on the Python side and `.strict` here;
    /// `false` selects the reference's default `Undefined` and `.lenient`.
    strict: bool = false,
    trim_blocks: bool = false,
    lstrip_blocks: bool = false,
    keep_trailing_newline: bool = false,
    /// The reference is expected to raise. We then require that we fail too —
    /// with any error, since the exception *types* are Python's, not ours.
    expect_error: bool = false,
};

pub const cases = [_]Case{
    // ── literal text, comments ──────────────────────────────────────────────
    .{ .name = "plain_text", .template = "hello world" },
    .{ .name = "text_with_braces", .template = "a { b } c {not-a-tag} d" },
    .{ .name = "comment_removed", .template = "a{# nothing #}b" },
    .{ .name = "comment_multiline", .template = "a{# one\ntwo #}b" },
    .{ .name = "trailing_newline_dropped", .template = "line\n" },
    .{ .name = "trailing_newline_kept", .template = "line\n", .keep_trailing_newline = true },
    .{ .name = "crlf_trailing_dropped", .template = "line\r\n" },

    // ── output of every scalar kind ─────────────────────────────────────────
    .{ .name = "out_string", .template = "{{ s }}", .context = "{\"s\": \"hi\"}" },
    .{ .name = "out_int", .template = "{{ n }}", .context = "{\"n\": 42}" },
    .{ .name = "out_negative_int", .template = "{{ n }}", .context = "{\"n\": -7}" },
    .{ .name = "out_true", .template = "{{ true }}|{{ True }}|{{ false }}" },
    .{ .name = "out_none", .template = "[{{ none }}]|[{{ None }}]" },
    .{ .name = "out_float_integral", .template = "{{ 1.0 }}|{{ 3.0 }}|{{ -2.0 }}" },
    .{ .name = "out_float_repr", .template = "{{ 0.1 }}|{{ 1.5 }}|{{ 2 / 3 }}" },
    .{ .name = "out_float_exponent", .template = "{{ 1e16 }}|{{ 1e15 }}|{{ 1e-5 }}|{{ 1e-4 }}" },
    .{ .name = "out_float_big", .template = "{{ 1e100 }}|{{ 1.5e-8 }}" },
    .{ .name = "out_list_repr", .template = "{{ [1, 'a', true, none] }}" },
    .{ .name = "out_dict_repr", .template = "{{ {'a': 1, 'b': [2, 3]} }}" },
    .{ .name = "out_nested_repr", .template = "{{ d }}", .context = "{\"d\": {\"k\": [\"a\", 1.5, null]}}" },
    .{ .name = "out_str_repr_quotes", .template = "{{ [\"it's\", 'say \"hi\"', 'a\\nb'] }}" },

    // ── arithmetic, the negative-operand corners ────────────────────────────
    .{ .name = "arith_basic", .template = "{{ 1 + 2 }}|{{ 5 - 8 }}|{{ 3 * 4 }}" },
    .{ .name = "true_division_is_float", .template = "{{ 4 / 2 }}|{{ 7 / 2 }}|{{ -7 / 2 }}" },
    .{ .name = "floordiv_negatives", .template = "{{ 7 // 2 }}|{{ -7 // 2 }}|{{ 7 // -2 }}|{{ -7 // -2 }}" },
    .{ .name = "mod_negatives", .template = "{{ 7 % 2 }}|{{ -7 % 2 }}|{{ 7 % -2 }}|{{ -7 % -2 }}" },
    .{ .name = "mod_float", .template = "{{ 7.5 % 2 }}|{{ -7.5 % 2 }}" },
    .{ .name = "floordiv_float", .template = "{{ 7.5 // 2 }}|{{ -7.5 // 2 }}" },
    .{ .name = "power", .template = "{{ 2 ** 10 }}|{{ 2 ** 0 }}|{{ 2 ** -1 }}" },
    .{ .name = "unary_minus_binds_after_pow", .template = "{{ -2 ** 2 }}" },
    .{ .name = "precedence_mixed", .template = "{{ 1 + 2 * 3 - 4 / 2 }}" },
    .{ .name = "string_concat_plus", .template = "{{ 'a' + 'b' }}" },
    .{ .name = "tilde_concat_mixed", .template = "{{ 'n=' ~ 5 ~ '/' ~ true }}" },
    .{ .name = "string_repeat", .template = "{{ '-' * 5 }}|{{ 3 * 'ab' }}" },
    .{ .name = "list_concat_repeat", .template = "{{ [1] + [2, 3] }}|{{ [0] * 3 }}" },
    .{ .name = "div_by_zero_errors", .template = "{{ 1 / 0 }}", .expect_error = true },
    .{ .name = "mod_by_zero_errors", .template = "{{ 1 % 0 }}", .expect_error = true },

    // ── comparison and logic ────────────────────────────────────────────────
    .{ .name = "compare_ops", .template = "{{ 1 < 2 }}|{{ 2 <= 2 }}|{{ 3 > 4 }}|{{ 3 >= 3 }}|{{ 1 == 1.0 }}|{{ 'a' != 'b' }}" },
    .{ .name = "compare_chained", .template = "{{ 1 < 2 < 3 }}|{{ 1 < 3 < 2 }}|{{ 3 > 2 > 1 }}" },
    .{ .name = "compare_strings", .template = "{{ 'abc' < 'abd' }}|{{ 'B' < 'a' }}" },
    .{ .name = "compare_lists", .template = "{{ [1, 2] < [1, 3] }}|{{ [1] < [1, 0] }}" },
    .{ .name = "logic_returns_operand", .template = "[{{ 0 or 'x' }}]|[{{ '' or none }}]|[{{ 1 and 2 }}]|[{{ 0 and 2 }}]" },
    .{ .name = "not_binds_looser_than_compare", .template = "{{ not 1 == 2 }}" },
    .{ .name = "in_operator", .template = "{{ 2 in [1,2,3] }}|{{ 'ell' in 'hello' }}|{{ 'a' in {'a': 1} }}|{{ 5 not in [1] }}" },
    .{ .name = "conditional_expression", .template = "{{ 'yes' if 1 else 'no' }}|{{ 'yes' if 0 else 'no' }}" },
    .{ .name = "conditional_nested", .template = "{{ 'a' if n > 5 else 'b' if n > 2 else 'c' }}", .context = "{\"n\": 4}" },
    .{ .name = "compare_mismatched_types_errors", .template = "{{ 1 < 'a' }}", .expect_error = true },

    // ── indexing, slicing, attributes ───────────────────────────────────────
    .{ .name = "attribute_access", .template = "{{ d.a.b }}", .context = "{\"d\": {\"a\": {\"b\": 7}}}" },
    .{ .name = "subscript_string_key", .template = "{{ d['a'] }}", .context = "{\"d\": {\"a\": 1}}" },
    .{ .name = "subscript_int", .template = "{{ l[0] }}|{{ l[-1] }}", .context = "{\"l\": [10, 20, 30]}" },
    .{ .name = "dot_integer_index", .template = "{{ l.1 }}", .context = "{\"l\": [10, 20, 30]}" },
    .{ .name = "string_index", .template = "{{ s[0] }}|{{ s[-1] }}", .context = "{\"s\": \"hello\"}" },
    .{ .name = "slice_basic", .template = "{{ l[1:3] }}|{{ l[:2] }}|{{ l[2:] }}", .context = "{\"l\": [0,1,2,3,4]}" },
    .{ .name = "slice_negative_and_step", .template = "{{ l[-2:] }}|{{ l[::2] }}|{{ l[::-1] }}", .context = "{\"l\": [0,1,2,3,4]}" },
    .{ .name = "slice_string", .template = "{{ s[1:4] }}|{{ s[::-1] }}", .context = "{\"s\": \"abcdef\"}" },
    .{ .name = "missing_key_is_undefined", .template = "[{{ d.nope }}]", .context = "{\"d\": {}}" },
    .{ .name = "index_out_of_range_is_undefined", .template = "[{{ l[9] }}]", .context = "{\"l\": [1]}" },

    // ── literals ────────────────────────────────────────────────────────────
    .{ .name = "list_literal", .template = "{{ [1, 2, 3]|join('-') }}" },
    .{ .name = "dict_literal_trailing_close", .template = "{{ {'a': 1}['a'] }}" },
    .{ .name = "adjacent_string_literals", .template = "{{ 'foo' 'bar' }}" },
    .{ .name = "string_escapes", .template = "{{ 'a\\tb\\nc' }}|{{ \"q\\\"q\" }}" },
    .{ .name = "number_forms", .template = "{{ 0x1f }}|{{ 0o17 }}|{{ 0b101 }}|{{ 1_000 }}|{{ 1.5e2 }}" },

    // ── filters ─────────────────────────────────────────────────────────────
    .{ .name = "filter_upper_lower", .template = "{{ 'MiXed'|upper }}|{{ 'MiXed'|lower }}" },
    .{ .name = "filter_capitalize_title", .template = "{{ 'hello world'|capitalize }}|{{ 'hello world'|title }}" },
    .{ .name = "filter_trim", .template = "[{{ '  pad  '|trim }}]|[{{ 'xxhixx'|trim('x') }}]" },
    .{ .name = "filter_length_count", .template = "{{ [1,2,3]|length }}|{{ 'abc'|count }}|{{ {'a':1}|length }}" },
    .{ .name = "filter_join_attribute", .template = "{{ rows|join(', ', attribute='n') }}", .context = "{\"rows\": [{\"n\": 1}, {\"n\": 2}]}" },
    .{ .name = "filter_join_plain", .template = "{{ ['a','b']|join }}|{{ [1,2]|join('+') }}" },
    .{ .name = "filter_replace", .template = "{{ 'aaa'|replace('a','b') }}|{{ 'aaa'|replace('a','b',2) }}" },
    .{ .name = "filter_default", .template = "[{{ missing|default('D') }}]|[{{ ''|default('D') }}]|[{{ ''|default('D', true) }}]" },
    .{ .name = "filter_default_short", .template = "{{ nope|d(5) }}" },
    .{ .name = "filter_int_float", .template = "{{ '42'|int }}|{{ 'x'|int }}|{{ 'x'|int(9) }}|{{ '1.9'|int }}|{{ 3.9|int }}|{{ '2.5'|float }}|{{ 'x'|float(1.5) }}" },
    .{ .name = "filter_abs_round", .template = "{{ -3|abs }}|{{ 2.5|round }}|{{ 3.5|round }}|{{ 2.675|round(2) }}|{{ 2.1|round(0,'ceil') }}|{{ 2.9|round(0,'floor') }}" },
    .{ .name = "filter_round_ties_and_precision", .template = "{{ 0.5|round }}|{{ 1.5|round }}|{{ -2.5|round }}|{{ 1.005|round(2) }}|{{ 2.345|round(2) }}|{{ 0.078125|round(5) }}|{{ 1234|round(-2) }}|{{ 1250|round(-2) }}" },
    .{ .name = "filter_first_last_list", .template = "{{ 'abc'|list }}|{{ [1,2,3]|first }}|{{ [1,2,3]|last }}" },
    .{ .name = "filter_reverse", .template = "{{ [1,2,3]|reverse|list }}|{{ 'abc'|reverse }}" },
    .{ .name = "filter_sort_default_is_case_insensitive", .template = "{{ ['b','A','c']|sort|join(',') }}" },
    .{ .name = "filter_sort_case_sensitive", .template = "{{ ['b','A','c']|sort(case_sensitive=true)|join(',') }}" },
    .{ .name = "filter_sort_reverse_attribute", .template = "{{ rows|sort(reverse=true, attribute='n')|map(attribute='n')|join(',') }}", .context = "{\"rows\": [{\"n\": 2}, {\"n\": 3}, {\"n\": 1}]}" },
    .{ .name = "filter_min_max", .template = "{{ [3,1,2]|min }}|{{ [3,1,2]|max }}|{{ ['b','A']|min }}" },
    .{ .name = "filter_sum", .template = "{{ [1,2,3]|sum }}|{{ rows|sum(attribute='n') }}|{{ []|sum }}", .context = "{\"rows\": [{\"n\": 1}, {\"n\": 2}]}" },
    .{ .name = "filter_unique", .template = "{{ ['a','A','b','a']|unique|join(',') }}|{{ ['a','A','b']|unique(true)|join(',') }}" },
    .{ .name = "filter_batch", .template = "{{ [1,2,3,4,5]|batch(2)|list }}|{{ [1,2,3]|batch(2, 0)|list }}" },
    .{ .name = "filter_slice", .template = "{{ [1,2,3,4,5]|slice(3)|list }}" },
    .{ .name = "filter_indent", .template = "[{{ 'a\\nb\\nc'|indent(2) }}]" },
    .{ .name = "filter_indent_first", .template = "[{{ 'a\\nb'|indent(2, true) }}]" },
    .{ .name = "filter_center", .template = "[{{ 'ab'|center(7) }}]" },
    .{ .name = "filter_truncate", .template = "{{ 'the quick brown fox jumps'|truncate(12) }}|{{ 'the quick brown fox jumps'|truncate(12, true) }}" },
    .{ .name = "filter_wordcount", .template = "{{ 'a b  c\\nd'|wordcount }}" },
    .{ .name = "filter_striptags", .template = "{{ '<b>bold</b>  and &amp; more'|striptags }}" },
    .{ .name = "filter_string", .template = "{{ 42|string + '!' }}" },
    .{ .name = "filter_items", .template = "{{ d|items|list }}", .context = "{\"d\": {\"b\": 1, \"a\": 2}}" },
    .{ .name = "filter_dictsort", .template = "{{ d|dictsort }}|{{ d|dictsort(by='value') }}", .context = "{\"d\": {\"b\": 1, \"A\": 2}}" },
    .{ .name = "filter_map_name", .template = "{{ ['a','b']|map('upper')|join(',') }}" },
    .{ .name = "filter_map_attribute", .template = "{{ rows|map(attribute='n')|join(',') }}", .context = "{\"rows\": [{\"n\": 1}, {\"n\": 2}]}" },
    .{ .name = "filter_select_reject", .template = "{{ [1,2,3,4]|select('odd')|list }}|{{ [1,2,3,4]|reject('odd')|list }}" },
    .{ .name = "filter_select_truthy", .template = "{{ [0,1,'',2]|select|list }}" },
    .{ .name = "filter_selectattr", .template = "{{ rows|selectattr('ok')|map(attribute='n')|join(',') }}", .context = "{\"rows\": [{\"n\": 1, \"ok\": true}, {\"n\": 2, \"ok\": false}]}" },
    .{ .name = "filter_selectattr_test", .template = "{{ rows|selectattr('n','gt',1)|map(attribute='n')|join(',') }}", .context = "{\"rows\": [{\"n\": 1}, {\"n\": 2}, {\"n\": 3}]}" },
    .{ .name = "filter_rejectattr", .template = "{{ rows|rejectattr('n','eq',2)|map(attribute='n')|join(',') }}", .context = "{\"rows\": [{\"n\": 1}, {\"n\": 2}]}" },
    .{ .name = "filter_chain", .template = "{{ '  Hello  '|trim|lower|replace('l','L') }}" },
    .{ .name = "filter_urlencode", .template = "{{ 'a b/c?d=e'|urlencode }}" },
    .{ .name = "filter_tojson_scalars", .template = "{{ d|tojson }}", .context = "{\"d\": {\"b\": 1, \"a\": \"x\", \"c\": [true, null, 1.5]}}" },
    .{ .name = "filter_tojson_escapes", .template = "{{ s|tojson }}", .context = "{\"s\": \"<a>&'\\\"\\n\"}" },
    .{ .name = "filter_tojson_indent", .template = "{{ d|tojson(2) }}", .context = "{\"d\": {\"a\": [1, 2]}}" },
    .{ .name = "filter_arg_evaluation_order", .template = "{{ 'x'|replace(a, b) }}", .context = "{\"a\": \"x\", \"b\": \"y\"}" },
    .{ .name = "filter_on_expression", .template = "{{ (1 + 2)|string }}" },

    // ── tests ───────────────────────────────────────────────────────────────
    .{ .name = "test_defined_undefined", .template = "{{ a is defined }}|{{ b is defined }}|{{ b is undefined }}", .context = "{\"a\": 1}" },
    .{ .name = "test_none", .template = "{{ n is none }}|{{ n is not none }}|{{ x is none }}", .context = "{\"n\": null, \"x\": 1}" },
    .{ .name = "test_types", .template = "{{ 1 is integer }}|{{ 1.0 is float }}|{{ 1 is number }}|{{ 'a' is string }}|{{ [1] is sequence }}|{{ {'a':1} is mapping }}|{{ true is boolean }}" },
    .{ .name = "test_even_odd_divisibleby", .template = "{{ 4 is even }}|{{ 4 is odd }}|{{ 9 is divisibleby(3) }}|{{ 9 is divisibleby 4 }}" },
    .{ .name = "test_comparison_tests", .template = "{{ 1 is eq 1 }}|{{ 1 is equalto(2) }}|{{ 3 is gt 2 }}|{{ 3 is le 3 }}" },
    .{ .name = "test_in", .template = "{{ 2 is in([1,2]) }}|{{ 'z' is in 'abc' }}" },
    .{ .name = "test_upper_lower", .template = "{{ 'AB' is upper }}|{{ 'Ab' is upper }}|{{ 'ab' is lower }}" },
    .{ .name = "test_negated_in_condition", .template = "{% if x is not defined %}no{% else %}yes{% endif %}" },

    // ── if ──────────────────────────────────────────────────────────────────
    .{ .name = "if_elif_else", .template = "{% if n > 5 %}big{% elif n > 2 %}mid{% else %}small{% endif %}", .context = "{\"n\": 3}" },
    .{ .name = "if_falsey_values", .template = "{% if [] %}a{% endif %}{% if {} %}b{% endif %}{% if '' %}c{% endif %}{% if 0 %}d{% endif %}{% if none %}e{% endif %}-" },
    .{ .name = "if_nested", .template = "{% if a %}{% if b %}ab{% else %}a{% endif %}{% endif %}", .context = "{\"a\": true, \"b\": false}" },

    // ── for and the loop object ─────────────────────────────────────────────
    .{ .name = "for_basic", .template = "{% for x in l %}{{ x }},{% endfor %}", .context = "{\"l\": [1,2,3]}" },
    .{ .name = "for_else_empty", .template = "{% for x in l %}{{ x }}{% else %}none{% endfor %}", .context = "{\"l\": []}" },
    .{ .name = "for_over_dict_yields_keys", .template = "{% for k in d %}{{ k }},{% endfor %}", .context = "{\"d\": {\"b\": 1, \"a\": 2}}" },
    .{ .name = "for_over_items_unpack", .template = "{% for k, v in d.items() %}{{ k }}={{ v }};{% endfor %}", .context = "{\"d\": {\"b\": 1, \"a\": 2}}" },
    .{ .name = "for_over_string", .template = "{% for c in 'abc' %}[{{ c }}]{% endfor %}" },
    .{ .name = "for_loop_fields", .template = "{% for x in l %}{{ loop.index }}/{{ loop.index0 }}/{{ loop.revindex }}/{{ loop.revindex0 }}/{{ loop.first }}/{{ loop.last }}/{{ loop.length }} {% endfor %}", .context = "{\"l\": [\"a\",\"b\",\"c\"]}" },
    .{ .name = "for_loop_previtem_nextitem", .template = "{% for x in l %}[{{ loop.previtem|default('-') }}<{{ x }}>{{ loop.nextitem|default('-') }}]{% endfor %}", .context = "{\"l\": [1,2,3]}" },
    .{ .name = "for_loop_cycle", .template = "{% for x in l %}{{ loop.cycle('odd','even') }} {% endfor %}", .context = "{\"l\": [1,2,3,4,5]}" },
    .{ .name = "for_loop_changed", .template = "{% for x in l %}{{ loop.changed(x) }} {% endfor %}", .context = "{\"l\": [1,1,2,2,1]}" },
    .{ .name = "for_nested_loop_shadows", .template = "{% for a in outer %}{% for b in inner %}{{ a }}{{ b }}:{{ loop.index }}/{{ loop.length }} {% endfor %}|{% endfor %}", .context = "{\"outer\": [\"x\",\"y\"], \"inner\": [1,2]}" },
    .{ .name = "for_nested_outer_loop_saved", .template = "{% for a in outer %}{% set ol = loop %}{% for b in inner %}{{ ol.index }}.{{ loop.index }} {% endfor %}{% endfor %}", .context = "{\"outer\": [\"x\",\"y\"], \"inner\": [1,2]}" },
    .{ .name = "for_filtered_length", .template = "{% for x in l if x is odd %}{{ x }}:{{ loop.index }}/{{ loop.length }} {% endfor %}", .context = "{\"l\": [1,2,3,4,5]}" },
    .{ .name = "for_filtered_else", .template = "{% for x in l if x > 10 %}{{ x }}{% else %}none{% endfor %}", .context = "{\"l\": [1,2]}" },
    .{ .name = "for_over_range", .template = "{% for i in range(3) %}{{ i }}{% endfor %}|{% for i in range(2, 8, 3) %}{{ i }}{% endfor %}|{% for i in range(3, 0, -1) %}{{ i }}{% endfor %}" },
    .{ .name = "for_over_undefined_is_empty_lenient", .template = "[{% for x in nope %}{{ x }}{% endfor %}]" },
    .{ .name = "for_over_undefined_errors_strict", .template = "{% for x in nope %}{{ x }}{% endfor %}", .strict = true, .expect_error = true },

    // ── set and scoping ─────────────────────────────────────────────────────
    .{ .name = "set_basic", .template = "{% set x = 5 %}{{ x }}" },
    .{ .name = "set_tuple", .template = "{% set a, b = [1, 2] %}{{ a }}{{ b }}" },
    .{ .name = "set_in_if_leaks", .template = "{% set x = 1 %}{% if true %}{% set x = 2 %}{% endif %}{{ x }}" },
    .{ .name = "set_in_for_does_not_leak", .template = "{% set t = 0 %}{% for x in [1,2,3] %}{% set t = t + x %}{% endfor %}{{ t }}" },
    .{ .name = "set_in_for_visible_within_loop", .template = "{% for x in [1,2,3] %}{% set t = x * 2 %}{{ t }}{% endfor %}" },
    .{ .name = "namespace_survives_loop", .template = "{% set ns = namespace(total=0) %}{% for x in [1,2,3] %}{% set ns.total = ns.total + x %}{% endfor %}{{ ns.total }}" },
    .{ .name = "set_block", .template = "{% set greeting %}hi {{ name }}{% endset %}[{{ greeting }}]", .context = "{\"name\": \"bob\"}" },
    .{ .name = "set_block_filtered", .template = "{% set g | upper %}hi{% endset %}[{{ g }}]" },
    .{ .name = "with_scope", .template = "{% with a = 1 %}{{ a }}{% endwith %}[{{ a|default('gone') }}]" },
    .{ .name = "filter_block", .template = "{% filter upper %}quiet{% endfilter %}" },
    .{ .name = "loop_var_does_not_leak", .template = "{% for x in [1] %}{% endfor %}[{{ x|default('gone') }}]" },

    // ── raw ─────────────────────────────────────────────────────────────────
    .{ .name = "raw_block", .template = "{% raw %}{{ not_a_var }} {% if %}{% endraw %}" },
    .{ .name = "raw_with_whitespace_control", .template = "a  {%- raw -%}  {{x}}  {%- endraw -%}  b" },

    // ── whitespace control ──────────────────────────────────────────────────
    .{ .name = "ws_dash_left", .template = "a   {%- if true %}b{% endif %}" },
    .{ .name = "ws_dash_right", .template = "{% if true -%}   b{% endif %}" },
    .{ .name = "ws_dash_both", .template = "a\n  {%- if true -%}  \n b\n  {%- endif -%}  \nc" },
    .{ .name = "ws_output_dash", .template = "a   {{- 'x' -}}   b" },
    .{ .name = "ws_comment_dash", .template = "a   {#- c -#}   b" },
    .{ .name = "ws_trim_blocks", .template = "{% if true %}\nline\n{% endif %}\ntail", .trim_blocks = true },
    .{ .name = "ws_trim_blocks_off", .template = "{% if true %}\nline\n{% endif %}\ntail" },
    .{ .name = "ws_lstrip_blocks", .template = "x\n    {% if true %}\n  body\n    {% endif %}\ny", .lstrip_blocks = true },
    .{ .name = "ws_both_options", .template = "x\n    {% if true %}\n  body\n    {% endif %}\ny", .trim_blocks = true, .lstrip_blocks = true },
    .{ .name = "ws_plus_defeats_trim", .template = "{% if true +%}\nline\n{% endif %}", .trim_blocks = true },
    .{ .name = "ws_lstrip_not_for_output_tags", .template = "x\n    {{ 1 }}\ny", .lstrip_blocks = true, .trim_blocks = true },
    .{ .name = "ws_dash_beats_options", .template = "x\n    {%- if true -%}\nbody\n{%- endif %}\ny", .trim_blocks = true, .lstrip_blocks = true },
    .{ .name = "ws_realistic_config", .template = "interface {{ i }}\n{%- for v in vlans %}\n vlan {{ v }}\n{%- endfor %}\n!\n", .context = "{\"i\": \"Gi0/1\", \"vlans\": [10, 20]}" },
    .{ .name = "ws_loop_trim_blocks", .template = "{% for v in l %}\n{{ v }}\n{% endfor %}", .context = "{\"l\": [1,2]}", .trim_blocks = true, .lstrip_blocks = true },

    // ── undefined behaviour ─────────────────────────────────────────────────
    .{ .name = "undefined_renders_empty_lenient", .template = "[{{ missing }}]" },
    .{ .name = "undefined_is_falsey_lenient", .template = "{% if missing %}yes{% else %}no{% endif %}" },
    .{ .name = "undefined_attribute_errors_lenient", .template = "{{ missing.attr }}", .expect_error = true },
    .{ .name = "undefined_arithmetic_errors_lenient", .template = "{{ missing + 1 }}", .expect_error = true },
    .{ .name = "undefined_iteration_is_empty_lenient", .template = "[{{ missing|list }}]" },
    .{ .name = "undefined_default_filter_lenient", .template = "{{ missing|default('ok') }}" },
    .{ .name = "strict_output_errors", .template = "[{{ missing }}]", .strict = true, .expect_error = true },
    .{ .name = "strict_if_errors", .template = "{% if missing %}a{% endif %}", .strict = true, .expect_error = true },
    .{ .name = "strict_defined_test_still_works", .template = "{{ missing is defined }}|{{ missing is undefined }}", .strict = true },
    .{ .name = "strict_default_filter_still_works", .template = "{{ missing|default('ok') }}", .strict = true },
    .{ .name = "strict_present_value_fine", .template = "{{ a }}", .context = "{\"a\": 1}", .strict = true },

    // ── autoescape ──────────────────────────────────────────────────────────
    .{ .name = "escape_off_passes_through", .template = "{{ s }}", .context = "{\"s\": \"<b>&'\\\"\"}" },
    .{ .name = "escape_on_escapes", .template = "{{ s }}", .context = "{\"s\": \"<b>&'\\\"\"}", .autoescape = true },
    .{ .name = "escape_on_safe", .template = "{{ s|safe }}", .context = "{\"s\": \"<b>\"}", .autoescape = true },
    .{ .name = "escape_filter_when_off", .template = "{{ s|escape }}", .context = "{\"s\": \"<b>\"}" },
    .{ .name = "escape_safe_then_escape_is_noop", .template = "{{ s|safe|escape }}", .context = "{\"s\": \"<b>\"}", .autoescape = true },
    .{ .name = "escape_forceescape_double", .template = "{{ s|safe|forceescape }}", .context = "{\"s\": \"<b>\"}", .autoescape = true },
    .{ .name = "escape_markup_concat", .template = "{{ (s|safe) ~ t }}", .context = "{\"s\": \"<b>\", \"t\": \"<i>\"}", .autoescape = true },
    .{ .name = "escape_markup_add", .template = "{{ (s|safe) + t }}", .context = "{\"s\": \"<b>\", \"t\": \"<i>\"}", .autoescape = true },
    .{ .name = "escape_join_escapes_items", .template = "{{ l|join('<>') }}", .context = "{\"l\": [\"<a>\", \"<b>\"]}", .autoescape = true },
    .{ .name = "escape_upper_preserves_markup", .template = "{{ s|safe|upper }}", .context = "{\"s\": \"<b>x\"}", .autoescape = true },
    .{ .name = "escape_non_string_values", .template = "{{ l }}", .context = "{\"l\": [\"<a>\"]}", .autoescape = true },
    .{ .name = "escape_set_block_is_markup", .template = "{% set b %}{{ s }}{% endset %}{{ b }}", .context = "{\"s\": \"<b>\"}", .autoescape = true },
    .{ .name = "escape_tojson_is_safe", .template = "{{ d|tojson }}", .context = "{\"d\": {\"k\": \"<v>\"}}", .autoescape = true },
    .{ .name = "escape_xmlattr", .template = "<a{{ d|xmlattr }}>", .context = "{\"d\": {\"href\": \"a&b\", \"n\": null}}", .autoescape = true },

    // ── methods on values ───────────────────────────────────────────────────
    .{ .name = "string_methods", .template = "{{ s.upper() }}|{{ s.startswith('he') }}|{{ s.split('l')|list }}|{{ s.replace('l','L') }}|{{ s.find('ll') }}", .context = "{\"s\": \"hello\"}" },
    .{ .name = "dict_methods", .template = "{{ d.keys()|list }}|{{ d.values()|list }}|{{ d.get('a') }}|{{ d.get('z', 'dflt') }}", .context = "{\"d\": {\"a\": 1, \"b\": 2}}" },
    .{ .name = "list_methods", .template = "{{ l.count(1) }}|{{ l.index(2) }}", .context = "{\"l\": [1,1,2]}" },
    .{ .name = "string_join_method", .template = "{{ '-'.join(['a','b']) }}" },

    // ── globals ─────────────────────────────────────────────────────────────
    .{ .name = "global_range_repr", .template = "{{ range(3)|list }}" },
    .{ .name = "global_dict", .template = "{{ dict(a=1, b=2) }}" },

    // ── further corners found worth pinning while the live oracle was up ────
    .{ .name = "bool_arithmetic", .template = "{{ true + true }}|{{ true * 3 }}|{{ false + 1 }}" },
    .{ .name = "conditional_without_else", .template = "[{{ 'a' if false }}]|[{{ 'a' if true }}]" },
    .{ .name = "undefined_equality_lenient", .template = "{{ missing == missing }}|{{ missing == none }}|{{ missing == 1 }}" },
    .{ .name = "sum_with_start", .template = "{{ [1,2,3]|sum(start=10) }}" },
    .{ .name = "concat_with_none", .template = "[{{ none ~ 'x' }}]|[{{ 1 ~ 2 }}]" },
    .{ .name = "map_string_then_join", .template = "{{ [1,2]|map('string')|join('+') }}|{{ 'abc'|list|join('') }}" },
    .{ .name = "loop_index_inside_if", .template = "{% for x in l %}{% if x > 1 %}{{ loop.index }};{% endif %}{% endfor %}", .context = "{\"l\": [1,2,3]}" },
    .{ .name = "nested_loop_first_last", .template = "{% for a in [1,2] %}{% for b in [1,2] %}{{ loop.first }}{{ loop.last }} {% endfor %}{{ loop.first }}{{ loop.last }}|{% endfor %}" },
    .{ .name = "filter_default_then_arithmetic", .template = "{{ (missing|default(1)) + 1 }}" },
    .{ .name = "autoescape_filter_block", .template = "{% filter upper %}{{ s }}{% endfilter %}", .context = "{\"s\": \"<b>\"}", .autoescape = true },
    .{ .name = "dict_items_render_directly", .template = "{{ d.items()|list }}", .context = "{\"d\": {\"a\": 1}}" },
    .{ .name = "slice_step_zero_errors", .template = "{{ l[::0] }}", .context = "{\"l\": [1,2]}", .expect_error = true },
    .{ .name = "string_multiplied_by_zero", .template = "[{{ 'ab' * 0 }}]|[{{ 'ab' * -1 }}]" },
    .{ .name = "chained_filters_on_dict", .template = "{{ d|dictsort|first }}", .context = "{\"d\": {\"b\": 1, \"a\": 2}}" },
    .{ .name = "whitespace_only_template", .template = "   \n   " },
    .{ .name = "tag_at_very_start_and_end", .template = "{{ 1 }}mid{{ 2 }}" },

    // ── realistic device-configuration templates ────────────────────────────
    .{
        .name = "config_interfaces",
        .template =
        \\hostname {{ host }}
        \\!
        \\{% for i in interfaces %}
        \\interface {{ i.name }}
        \\{% if i.description is defined %}
        \\ description {{ i.description }}
        \\{% endif %}
        \\{% if i.address %}
        \\ ip address {{ i.address }} {{ i.mask }}
        \\{% else %}
        \\ no ip address
        \\{% endif %}
        \\ {{ 'shutdown' if i.shutdown else 'no shutdown' }}
        \\!
        \\{% endfor %}
        ,
        .context =
        \\{"host": "sw1", "interfaces": [
        \\  {"name": "Gi0/1", "description": "uplink", "address": "10.0.0.1", "mask": "255.255.255.0", "shutdown": false},
        \\  {"name": "Gi0/2", "address": null, "shutdown": true}
        \\]}
        ,
        .trim_blocks = true,
        .lstrip_blocks = true,
    },
    .{
        .name = "config_acl_with_namespace",
        .template =
        \\{% set ns = namespace(seq=10) %}
        \\{% for r in rules %}
        \\{{ ns.seq }} {{ r.action }} {{ r.proto|default('ip') }} {{ r.src }} {{ r.dst }}
        \\{% set ns.seq = ns.seq + 10 %}
        \\{% endfor %}
        ,
        .context =
        \\{"rules": [{"action": "permit", "src": "any", "dst": "any"},
        \\           {"action": "deny", "proto": "tcp", "src": "10.0.0.0/8", "dst": "any"}]}
        ,
        .trim_blocks = true,
        .lstrip_blocks = true,
    },
    .{
        .name = "config_json_payload",
        .template = "{\"name\": {{ name|tojson }}, \"tags\": {{ tags|tojson }}}",
        .context = "{\"name\": \"a\\\"b\", \"tags\": [\"x\", \"y\"]}",
    },
};

test "corpus names are unique" {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(std.testing.allocator);
    for (cases) |c| {
        const gop = try seen.getOrPut(std.testing.allocator, c.name);
        try std.testing.expect(!gop.found_existing);
    }
}

/// Serialize the corpus the way `testdata/reference.py` expects to read it.
pub fn toJson(gpa: std.mem.Allocator) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;
    try w.writeAll("[");
    for (cases, 0..) |c, i| {
        if (i != 0) try w.writeAll(",\n");
        try w.writeAll("{\"name\":");
        try std.json.Stringify.value(c.name, .{}, w);
        try w.writeAll(",\"template\":");
        try std.json.Stringify.value(c.template, .{}, w);
        try w.writeAll(",\"context\":");
        try std.json.Stringify.value(c.context, .{}, w);
        try w.print(
            ",\"autoescape\":{},\"strict\":{},\"trim_blocks\":{},\"lstrip_blocks\":{},\"keep_trailing_newline\":{},\"expect_error\":{}}}",
            .{ c.autoescape, c.strict, c.trim_blocks, c.lstrip_blocks, c.keep_trailing_newline, c.expect_error },
        );
    }
    try w.writeAll("]\n");
    return aw.toOwnedSlice();
}
