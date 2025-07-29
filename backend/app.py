# app.py
# Optimized and secured Flask web server.

import os
import uuid
import shutil
import io
import logging
from contextlib import contextmanager
from flask import Flask, request, send_from_directory, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

import stego_core

# --- Basic Setup ---
logging.basicConfig(level=logging.INFO)
app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# --- Configuration ---
TEMP_FOLDER = os.path.join(os.getcwd(), 'temp_files')
CLEANUP_DELAY_SECONDS = 600 # 10 minutes
os.makedirs(TEMP_FOLDER, exist_ok=True)

# --- Context Manager for Temporary Directories ---

@contextmanager
def temp_session_folder():
    """Context manager to create and automatically clean up a temporary session folder."""
    request_id = str(uuid.uuid4())
    folder_path = os.path.join(TEMP_FOLDER, request_id)
    os.makedirs(folder_path)
    app.logger.info(f"Created session folder: {folder_path}")
    try:
        yield folder_path, request_id
    finally:
        try:
            shutil.rmtree(folder_path)
            app.logger.info(f"Cleaned up session folder: {folder_path}")
        except Exception as e:
            app.logger.error(f"Error during final cleanup of {folder_path}: {e}")

# --- API Endpoints ---

@app.route('/')
def serve_index():
    """Serves the main index.html file."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/embed', methods=['POST'])
def embed_api():
    """Handles the embedding of a secret file into a cover file."""
    if 'coverFile' not in request.files or 'secretFile' not in request.files:
        return jsonify({"error": "Cover and secret files are required."}), 400
    if not request.form.get('password'):
        return jsonify({"error": "Password is required."}), 400

    cover_file = request.files['coverFile']
    secret_file = request.files['secretFile']
    password = request.form['password']
    message = request.form.get('message')

    try:
        with temp_session_folder() as (session_folder, _):
            # Securely save uploaded files
            cover_filename = secure_filename(cover_file.filename)
            secret_filename = secure_filename(secret_file.filename)
            cover_path = os.path.join(session_folder, cover_filename)
            secret_path = os.path.join(session_folder, secret_filename)
            cover_file.save(cover_path)
            secret_file.save(secret_path)

            # Prepare output path and perform steganography
            output_filename = f"stego_{cover_filename}"
            output_path = os.path.join(session_folder, output_filename)
            stego_core.hide_data(cover_path, secret_path, password, output_path, message=message)

            # Read the generated file into a memory buffer for sending
            with open(output_path, 'rb') as f:
                buffer = io.BytesIO(f.read())
        
        # The temp folder is now deleted by the context manager.
        # Send the file from the memory buffer, avoiding file lock issues.
        return send_file(
            buffer,
            as_attachment=True,
            download_name=output_filename,
            mimetype='application/octet-stream'
        )

    except ValueError as e:
        app.logger.warning(f"Embedding failed due to bad input: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.error("An exception occurred during embedding:", exc_info=True)
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/extract', methods=['POST'])
def extract_api():
    """Handles the extraction of a secret file from a stego file."""
    if 'stegoFile' not in request.files:
        return jsonify({"error": "Stego file is required."}), 400
    if not request.form.get('password'):
        return jsonify({"error": "Password is required."}), 400

    stego_file = request.files['stegoFile']
    password = request.form['password']
    
    # Delayed cleanup requires a more manual folder management approach
    request_id = str(uuid.uuid4())
    session_folder = os.path.join(TEMP_FOLDER, request_id)
    os.makedirs(session_folder)

    try:
        stego_filename = secure_filename(stego_file.filename)
        stego_path = os.path.join(session_folder, stego_filename)
        stego_file.save(stego_path)

        filedata, original_filename, message = stego_core.extract_data(stego_path, password)

        if filedata is None or original_filename is None:
            shutil.rmtree(session_folder) # Clean up immediately on failure
            return jsonify({"error": "Extraction failed. Wrong password or corrupt file."}), 400
        
        # Save the extracted file to be served by the download endpoint
        output_path = os.path.join(session_folder, secure_filename(original_filename))
        with open(output_path, 'wb') as f:
            f.write(filedata)

        # Schedule the folder for deletion after a delay
        shutil.rmtree(session_folder) # For this implementation, we will remove it right away.
        # A better implementation would be to use a background task queue like Celery.

        return jsonify({
            "message": message,
            "filename": original_filename,
            "filedata_b64": base64.b64encode(filedata).decode('utf-8') # Send data directly
        })

    except Exception as e:
        app.logger.error("An exception occurred during extraction:", exc_info=True)
        if os.path.exists(session_folder):
            shutil.rmtree(session_folder)
        return jsonify({"error": "An internal server error occurred."}), 500

# The download endpoint is removed in favor of sending data directly in the JSON response.

if __name__ == '__main__':
    import base64 # Add this import if you run this file directly
    app.run(debug=True, port=5000)