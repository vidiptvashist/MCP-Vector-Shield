import logging

logger = logging.getLogger("mcp_vector_shield")


def verify_tool_metadata(tool_schema: dict) -> bool:
    """
    Default hook to verify tool metadata.
    Returns True if the tool is safe/allowed, False if it is blocked or malicious.

    You can customize or replace this function with your own security validation rules.
    """
    name = tool_schema.get("name", "")
    description = tool_schema.get("description", "")
    input_schema = tool_schema.get("inputSchema", {})

    # 1. Basic validation of required properties
    if not name:
        logger.warning("Rejected tool: missing name.")
        return False

    # 2. Block lists for tool names (e.g. system commands, bash, unsafe scripts)
    unsafe_keywords = {"exec", "shell", "eval", "system", "run_cmd", "sh", "bash", "command"}
    normalized_name = name.lower().replace("_", "").replace("-", "")
    for keyword in unsafe_keywords:
        if keyword in normalized_name:
            logger.warning(f"Rejected tool '{name}': name contains suspicious keyword '{keyword}'.")
            return False

    # 3. Analyze description for dangerous intents
    unsafe_desc_keywords = {"execute arbitrary", "run shell", "eval python", "system command"}
    normalized_desc = description.lower()
    for keyword in unsafe_desc_keywords:
        if keyword in normalized_desc:
            logger.warning(
                f"Rejected tool '{name}': description contains suspicious phrase '{keyword}'."
            )
            return False

    # 4. Check inputSchema properties for shell execution params
    properties = input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
    if properties:
        unsafe_param_names = {"command", "cmd", "shell", "script", "code"}
        for p_name in properties:
            if p_name.lower() in unsafe_param_names:
                logger.warning(
                    f"Rejected tool '{name}': schema defines suspicious input parameter '{p_name}'."
                )
                return False

    logger.debug(f"Approved tool '{name}'.")
    return True
