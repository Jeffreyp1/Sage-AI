from app.mcp.contracts import (
    AIContextBundleInput,
    AIContextBundleOutput,
    FindingInput,
    MCP_TOOL_NAMES,
    UNSAFE_TOOL_NAME_FRAGMENTS,
    ValidateAIOutputInput,
    ValidateReportInput,
    ListFindingsInput,
    MAX_FINDINGS_LIMIT,
    ScanRepoInput,
    ToolContract,
    tool_contracts,
)
from pydantic import ValidationError


def test_mcp_contract_exposes_only_safe_initial_tools():
    contracts = tool_contracts()
    names = [contract.name for contract in contracts]

    assert names == list(MCP_TOOL_NAMES)
    assert "scan_repo" in names
    assert "list_findings" in names
    assert "get_finding_evidence" in names
    assert "get_remediation_context" in names
    assert "get_ai_context_bundle" in names
    assert "validate_ai_output" in names
    assert "validate_report" in names

    for name in names:
        lowered = name.lower()
        for unsafe_fragment in UNSAFE_TOOL_NAME_FRAGMENTS:
            assert unsafe_fragment not in lowered


def test_mcp_contract_has_schema_for_every_tool():
    for contract in tool_contracts():
        assert isinstance(contract, ToolContract)
        assert contract.description
        input_schema = contract.input_model.model_json_schema()
        output_schema = contract.output_model.model_json_schema()
        assert input_schema["type"] == "object"
        assert output_schema["type"] == "object"


def test_scan_repo_input_defaults_are_local_and_bounded():
    request = ScanRepoInput()

    assert request.repo_path == "."
    assert request.offline is False
    assert request.max_findings == 10


def test_scan_repo_input_uses_clear_repo_path_argument():
    request = ScanRepoInput.model_validate({"repo_path": "demo-repos/payments-api"})
    schema = ScanRepoInput.model_json_schema()

    assert request.repo_path == "demo-repos/payments-api"
    assert "repo_path" in schema["properties"]
    assert "path" not in schema["properties"]


def test_list_findings_input_rejects_limit_above_contract_bound():
    try:
        ListFindingsInput(scan_id="scan_123", limit=1000)
    except ValidationError as error:
        message = str(error)
    else:
        raise AssertionError("ListFindingsInput should reject limits above the contract bound")

    assert "less than or equal to 50" in message


def test_list_findings_schema_exposes_limit_maximum():
    schema = ListFindingsInput.model_json_schema()

    assert schema["properties"]["limit"]["maximum"] == MAX_FINDINGS_LIMIT


def test_mcp_string_inputs_expose_max_length_bounds():
    for contract in tool_contracts():
        schema = contract.input_model.model_json_schema()
        for property_schema in schema["properties"].values():
            if property_schema.get("type") == "string":
                assert property_schema["maxLength"] <= 512


def test_mcp_string_inputs_reject_overlong_values():
    long_value = "x" * 513

    for model_type, payload in (
        (ScanRepoInput, {"repo_path": long_value}),
        (ListFindingsInput, {"scan_id": long_value}),
        (FindingInput, {"scan_id": "scan-test", "task_id": long_value}),
        (ValidateAIOutputInput, {"scan_id": "scan-test", "task_id": long_value, "ai_output": {}}),
        (ValidateReportInput, {"report_path": long_value}),
    ):
        try:
            model_type.model_validate(payload)
        except ValidationError as error:
            assert "string_too_long" in str(error)
        else:
            raise AssertionError("%s should reject overlong strings" % model_type.__name__)


def test_ai_context_bundle_output_exposes_ai_request_and_prompt_contract():
    schema = AIContextBundleOutput.model_json_schema()

    assert "bundle" in schema["properties"]
    assert "scan_id" in schema["properties"]
    assert "task_id" in schema["properties"]


def test_ai_context_bundle_input_supports_optional_rag_retrieval():
    request = AIContextBundleInput.model_validate(
        {
            "scan_id": "scan-test",
            "task_id": "task-archive-utils",
            "include_rag": True,
            "top_k": 3,
        }
    )
    schema = AIContextBundleInput.model_json_schema()

    assert request.include_rag is True
    assert request.top_k == 3
    assert schema["properties"]["top_k"]["minimum"] == 1
    assert schema["properties"]["top_k"]["maximum"] == 10


def test_validate_ai_output_input_supports_optional_rag_retrieval():
    request = ValidateAIOutputInput.model_validate(
        {
            "scan_id": "scan-test",
            "task_id": "task-archive-utils",
            "ai_output": {},
            "include_rag": True,
            "top_k": 3,
        }
    )
    schema = ValidateAIOutputInput.model_json_schema()

    assert request.include_rag is True
    assert request.top_k == 3
    assert schema["properties"]["top_k"]["minimum"] == 1
    assert schema["properties"]["top_k"]["maximum"] == 10
