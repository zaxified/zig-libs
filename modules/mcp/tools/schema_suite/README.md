# schema_suite

Vectors for `src/schema_check.zig` (JSON Schema 2020-12 subset), from the
JSON-Schema-Test-Suite (MIT, Julian Berman), commit
55719286c33ae0d1823bfb65fea10338a19bc37c. `extract.py` keeps the cases inside
the subset (see the header of `src/schema_suite_vectors.zig` for counts).

    D=.zig-cache/schema-suite/tests; S=55719286c33ae0d1823bfb65fea10338a19bc37c; mkdir -p $D
    for f in $(sed -n '/^FILES/,/split/p' modules/mcp/tools/schema_suite/extract.py | tr -d '"=)' | sed 's/FILES//;s/\.split(//;s/^ *//' | tr '\n' ' '); do
      curl -sfL -o $D/$f.json https://raw.githubusercontent.com/json-schema-org/JSON-Schema-Test-Suite/$S/tests/draft2020-12/$f.json; done
    python3 -I modules/mcp/tools/schema_suite/extract.py $D modules/mcp/src/schema_suite_vectors.zig $S
    zig fmt modules/mcp/src/schema_suite_vectors.zig
