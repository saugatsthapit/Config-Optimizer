import logging
import os
import shutil
import asyncio
import uuid
import time
from fastapi import FastAPI, File, UploadFile, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
from fastapi import Form
import urllib.parse
import subprocess
import tempfile 
import os
import json

SESSION_TIMEOUT = 5900  # 5 seconds for testing
session_last_access = {}

TEMP_DIR = "/root/Audit/temp"
MAX_FILE_SIZE = 1024 * 1024  # 1 MB limit

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

@app.on_event("startup")
async def start_cleanup_task():
    asyncio.create_task(cleanup_sessions())

# Add a new endpoint to check the session status
@app.get("/check-session")
async def check_session(request: Request):
    session_id = request.cookies.get('session_id')
    if session_id and os.path.exists(os.path.join(TEMP_DIR, session_id)):
        return JSONResponse(content={"message": "Session active"})
    return JSONResponse(status_code=401, content={"message": "Session expired"})

# Modify the cleanup_sessions function
async def cleanup_sessions():
    logger.info("Session cleanup task started.")
    while True:
        try:
            await asyncio.sleep(900)  # Check every minute
            current_time = time.time()
            for session_id, last_access in list(session_last_access.items()):
                if current_time - last_access > SESSION_TIMEOUT:
                    session_dir = os.path.join(TEMP_DIR, session_id)
                    shutil.rmtree(session_dir, ignore_errors=True)
                    del session_last_access[session_id]
                    logger.info(f"Session {session_id} expired and deleted.")
                    # Here, you may also need to handle the logic for notifying the frontend or handling cookie deletion
        except Exception as e:
            logger.error(f"An error occurred in cleanup_sessions: {e}")


def read_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def find_matched_rules(directory, rule_criteria, exclude_rule_name=None):
    matched_rules = []
    if not rule_criteria:
        return matched_rules

    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            file_path = os.path.join(directory, filename)
            data = read_json_file(file_path)
            if data is not None:
                def check_rule(rule, parent_name=''):
                    if 'name' in rule and rule.get('criteria', []) == rule_criteria and rule['name'] != exclude_rule_name:
                        matched_name = f"Parent: {rule['name']}" if not parent_name else f"- Child of {parent_name}: {rule['name']}"
                        matched_rules.append(matched_name)
                    for child in rule.get('children', []):
                        check_rule(child, rule.get('name', 'Unknown'))

                check_rule(data)
    return matched_rules

def search(directory):
    results = []

    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            file_path = os.path.join(directory, filename)
            data = read_json_file(file_path)
            if data is not None:
                def process_rule(rule, parent_name=''):
                    if 'name' in rule and rule.get('criteria', []):
                        rule_name = rule['name']
                        matched_rules = find_matched_rules(directory, rule.get('criteria', []), rule['name'])
                        for matched_rule in matched_rules:
                            results.append({
                                'triggered_rule': rule_name,
                                'matched_rule': matched_rule
                            })
                        for child in rule.get('children', []):
                            process_rule(child, rule_name)

                process_rule(data)
    
    return results

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    return response

@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_file_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    with open(html_file_path, 'r') as file:
        html_content = file.read()
    return HTMLResponse(content=html_content)

@app.post("/upload-edgerc")
async def upload_edgerc(request: Request, file: UploadFile = File(...)):
    session_id = request.cookies.get('session_id')

    # Check if the session ID exists and if the session directory exists
    if session_id and os.path.exists(os.path.join(TEMP_DIR, session_id)):
        session_dir = os.path.join(TEMP_DIR, session_id)
        session_last_access[session_id] = time.time()  # Update last access time
    else:
        # Create a new session ID and directory
        session_id = str(uuid.uuid4())
        session_dir = os.path.join(TEMP_DIR, session_id)
        os.makedirs(session_dir, exist_ok=True)
        session_last_access[session_id] = time.time()

    file_path = os.path.join(session_dir, 'edgerc')
    
    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)
    if file_size > MAX_FILE_SIZE:
        return JSONResponse(status_code=413, content={"message": "File size exceeds limit."})
    
    if Path(file.filename).suffix:
        return JSONResponse(status_code=400, content={"message": "Please upload the edgerc file without any extension."})

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        logger.info(f".edgerc file uploaded successfully to {file_path}")

        # Send success response with new or updated session cookie
        response = JSONResponse(content={"message": "File uploaded successfully."})
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response
    except Exception as e:
        logger.error(f"An error occurred during file upload: {e}")
        return JSONResponse(status_code=500, content={"message": f"An error occurred: {e}"})

@app.post("/submit-config")
async def submit_config(request: Request, config_name: str = Form(...), account_switch_key: str = Form(...)):
    # Log the received data
    logger.info(f"Received configuration name: {config_name}, Account switch key: {account_switch_key}")

    session_id = request.cookies.get('session_id')

    # Check if the session ID exists and if the session directory exists
    if session_id and os.path.exists(os.path.join(TEMP_DIR, session_id)):
        session_dir = os.path.join(TEMP_DIR, session_id)
        session_last_access[session_id] = time.time()  # Update last access time
    else:
        return JSONResponse(status_code=401, content={"message": "Session expired"})

    # Set the custom PATH environment variable to include the NVM Node.js directory
    node_bin_dir = '/root/.nvm/versions/node/v20.10.0/bin'
    os.environ['PATH'] = f"{node_bin_dir}:{os.environ['PATH']}"

    # Prepare the command with the correct `--edgerc` option
    command = [
        "akamai",
        "property-manager",
        "--edgerc",  # Add the --edgerc option
        os.path.join(session_dir, 'edgerc'),  # Include the edgerc file path
        "--accountSwitchKey",
        account_switch_key,
        "import",
        "-p",
        config_name
    ]

    # Initialize stdout and stderr variables
    stdout, stderr = "", ""
    response_message = ""  # Initialize response_message outside the if-else block
    stderr = ""

    try:
        config_dir = os.path.join(session_dir, config_name)
        
        akamai_cmd = '/usr/local/bin/akamai'
        
        # Check if config_dir already exists
        if not os.path.exists(config_dir):
            # Log the full command
            logger.info(f"Executing command: {' '.join(command)}")

            os.chdir(session_dir)

            # Change to async subprocess call
            process = await asyncio.create_subprocess_exec(
                akamai_cmd, 'property-manager', '--edgerc', os.path.join(session_dir, 'edgerc'),
                '--accountSwitchKey', account_switch_key, 'import', '-p', config_name,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            # Wait for the external process to finish
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                # Command executed successfully
                response_message = "Configuration imported successfully."

                # Change the working directory to the config_name directory
                os.chdir(config_dir)

                # Set the config-snippets directory as the search directory
                search_dir = os.path.join(config_dir, 'config-snippets')

                # Call the search function on the config-snippets directory
                matched_rules = search(search_dir)
                
                # Log success message
                logger.info("Configuration import successful.")
                
                # Log the matched rules
                logger.info(f"Matched Rule: {matched_rules}")
                logger.info(f"Command Output: {stdout.decode()}")
            else:
                # Command failed
                response_message = f"Error executing the command: {stderr.decode()}"
                
                # Log error message
                logger.error(response_message)

        else:
            os.chdir(config_dir)

            # Set the config-snippets directory as the search directory
            search_dir = os.path.join(config_dir, 'config-snippets')

            # Call the search function on the config-snippets directory
            matched_rules = search(search_dir)
        
            # Log success message
            logger.info("Configuration import successful.")
            logger.info(f"Matched Rule: {matched_rules}")

        # Log the command output
        logger.info(f"Command Output: {stdout}")
        

        return JSONResponse(content={"message": response_message, "matched_rules": matched_rules})
    except asyncio.CancelledError:
        logger.error("Command execution was cancelled.")
        return JSONResponse(status_code=500, content={"message": "Command execution cancelled."})
    except Exception as e:
        # Log the error message
        logger.exception("An unexpected error occurred during command execution.")
        return JSONResponse(status_code=500, content={"message": f"An unexpected error occurred: {e}"})

