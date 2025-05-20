# A Simple MCP Sliver server written in Python

A simple MCP server for the Sliver C2 framework. 


## Requirements
- uv
- "python>=3.10"
- "sliver-py>=0.0.19",
- "mcp[cli]>=1.2.0",


## Tools
MCP server currently has following tools:
- list_beacons
- list_sessions
- change_directory
- list_files
- upload_file
- download_file
- run_cmd_command
- run_ps_command
- run_shellcode
- list_processes
- impersonate
- run_as
- read_registry_value
- dump_process_memory


## Claude Dekstop config
```
"sliverc2_mcp": {
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


## Usage
Sliverc2_mcp requires valid sliver operator configuration file to communicate to Sliver C2 server over mTLS.


## Acknowledgments
Built on the great work done in https://github.com/moloch--/sliver-py
