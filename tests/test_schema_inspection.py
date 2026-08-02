from core.schema_inspection import (
    MAX_SCHEMA_DEPTH,
    MAX_SCHEMA_NODES,
    inspect_tool_input_schema,
)
from core.metadata_inspection import inspect_tool_list_payload


def test_valid_2020_schema_with_local_defs_is_accepted():
    result = inspect_tool_input_schema(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "$defs": {"path": {"type": "string"}},
            "properties": {"path": {"$ref": "#/$defs/path"}},
            "oneOf": [{"required": ["path"]}, {"required": []}],
        }
    )

    assert result.valid is True
    assert result.external_ref_count == 0


def test_external_refs_are_counted_but_never_resolved():
    result = inspect_tool_input_schema(
        {"type": "object", "properties": {"value": {"$ref": "https://example.test/schema"}}}
    )

    assert result.valid is True
    assert result.external_ref_count == 1


def test_invalid_schema_keyword_is_rejected():
    result = inspect_tool_input_schema({"type": "not-a-json-schema-type"})

    assert result.valid is False
    assert "JSON Schema 2020-12" in result.issues[0]


def test_schema_depth_and_node_bounds_are_rejected():
    nested: dict = {"type": "string"}
    for _ in range(MAX_SCHEMA_DEPTH + 2):
        nested = {"properties": {"nested": nested}}
    deep_result = inspect_tool_input_schema(nested)
    assert deep_result.valid is False
    assert any("depth" in issue for issue in deep_result.issues)

    broad = {"properties": {f"field_{index}": {"type": "string"} for index in range(MAX_SCHEMA_NODES)}}
    broad_result = inspect_tool_input_schema(broad)
    assert broad_result.valid is False
    assert any("node" in issue for issue in broad_result.issues)


def test_tool_list_blocks_malformed_input_schema():
    result = inspect_tool_list_payload(
        {
            "result": {
                "tools": [
                    {
                        "name": "bad_schema",
                        "inputSchema": {"type": "not-a-json-schema-type"},
                    }
                ]
            }
        }
    )

    assert result is not None
    assert result.allowed is False
    assert result.rule_matches[0].rule_id == "META-SCHEMA"
