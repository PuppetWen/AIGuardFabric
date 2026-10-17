"""Optional protocol classifiers; they do not alter or serialize business results."""


def mcp_result(value):
    """Classify an explicit decoded MCP result or JSON-RPC response, including isError."""
    if type(value) is not dict:
        return "unknown"
    if "jsonrpc" in value:
        if value["jsonrpc"] != "2.0" or "id" not in value or ("result" in value) == ("error" in value):
            return "unknown"
        if "error" in value:
            error = value["error"]
            return "error" if (type(error) is dict and type(error.get("code")) is int
                               and isinstance(error.get("message"), str)) else "unknown"
        value = value.get("result")
        if type(value) is not dict:
            return "unknown"
    content = value.get("content")
    if type(content) is not list or any(type(item) is not dict or item.get("type") not in {
            "text", "image", "audio", "resource", "resource_link"} for item in content):
        return "unknown"
    failed = value.get("isError", False)
    return "error" if failed is True else "success" if failed is False else "unknown"
