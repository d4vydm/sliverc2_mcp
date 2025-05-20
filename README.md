# A Simple MCP Sliver server written in Python

A simple MCP server for the Sliver C2 framework. 

## Requirements
- uv
- "python>=3.10"
- "sliver-py>=0.0.19",
- "mcp[cli]>=1.2.0",

## Claude Dekstop config
```
"sliver_mcp": {
    "command": "/Users/<user>/.local/bin/uv",
    "args": [
        "--directory",
        "sliverc2_mcp",
        "run",
        "sliverc2_mcp.py",
        "--operator-config-file",
        "sliver_operator.cfg"
    ]
}
```

## Acknowledgments
Built on the great work done in https://github.com/moloch--/sliver-py
