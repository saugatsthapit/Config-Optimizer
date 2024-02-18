import logging
import os
import shutil
import asyncio
import uuid
import time
from fastapi import FastAPI, File, Response, UploadFile, Request, Query, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pathlib import Path
from fastapi import Form
import urllib.parse
import subprocess
import tempfile 
import io
import json
import pytesseract
from PIL import Image

SESSION_TIMEOUT = 5900  # 5 seconds for testing
session_last_access = {}

TEMP_DIR = "/root/Audit/temp"
MAX_FILE_SIZE = 1024 * 1024  # 1 MB limit
DATASTREAM_DIR = 'datastream_logs'
os.makedirs(DATASTREAM_DIR, exist_ok=True)

pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'  

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

# Calculate the path to the 'frontend' directory from 'backend/app.py'
current_file_path = os.path.dirname(__file__)  # Path to the directory where app.py is located
frontend_dir = os.path.join(current_file_path, '..', 'frontend')  # Navigate up one level and into 'frontend'

# Serve static files from the 'frontend' directory
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")




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
async def log_request_data(request: Request, call_next):
    session_id = request.headers.get("x-session-id")
    if session_id:
        session_dir = os.path.join(DATASTREAM_DIR, session_id)
        os.makedirs(session_dir, exist_ok=True)
        with open(os.path.join(session_dir, 'log.txt'), 'a') as f:
            f.write(f"Logged request to {request.url.path}\n")
    
    response = await call_next(request)
    return response


@app.get("/", response_class=HTMLResponse)
async def read_root():
    try:
        html_file_path = os.path.join(frontend_dir, 'index.html')
        with open(html_file_path, 'r') as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Index.html not found")


@app.get("/datastream", response_class=HTMLResponse)
async def read_datastream(request: Request):
    session_id = request.headers.get("x-session-id")
    if not session_id:
        session_id = str(uuid.uuid4())

    try:
        html_file_path = os.path.join(frontend_dir, 'datastream.html')
        with open(html_file_path, 'r') as file:
            html_content = file.read()
            html_content = html_content.replace("<!--SESSION_ID-->", session_id)
        
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Datastream.html not found")


@app.get("/image-text", response_class=HTMLResponse)
async def read_datastream(request: Request):
    try:
        html_file_path = os.path.join(frontend_dir, 'imagetext.html')
        with open(html_file_path, 'r') as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="imagetext.html not found")
    
@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile = File(...)):
    image_bytes = await file.read()
    image = Image.open(io.BytesIO(image_bytes))
    text = pytesseract.image_to_string(image)
    return JSONResponse(content={"text": text})


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

@app.get("/{session_id}")
async def get_logs(session_id: str):
    session_log_path = os.path.join(DATASTREAM_DIR, session_id, 'log.txt')
    if os.path.exists(session_log_path):
        return FileResponse(session_log_path)
    else:
        return Response(content="No logs found for this session.", status_code=404)

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

