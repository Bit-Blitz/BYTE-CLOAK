# app.py
# The Flask web server with the final fix for file locking issues.

import os
import uuid
import shutil
from flask import Flask, request, send_from_directory, jsonify, after_this_request
from flask_cors import CORS
import logging
import threading

import stego_core

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

TEMP_FOLDER = os.path.join(os.getcwd(), 'temp_files')
os.makedirs(TEMP_FOLDER, exist_ok=True)

def schedule_delayed_cleanup(folder_path, delay_seconds=600):
    def cleanup():
        try:
            shutil.rmtree(folder_path)
            app.logger.info(f"[DELAYED] Cleaned up session folder: {folder_path}")
        except Exception as e:
            app.logger.error(f"[DELAYED] Error cleaning up session folder {folder_path}: {e}")
    timer = threading.Timer(delay_seconds, cleanup)
    timer.daemon = True
    timer.start()

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/embed', methods=['POST'])
def embed_api():
    app.logger.info("Received request for /api/embed")
    request_id = str(uuid.uuid4())
    session_folder = os.path.join(TEMP_FOLDER, request_id)
    os.makedirs(session_folder)

    try:
        if 'coverFile' not in request.files or 'secretFile' not in request.files:
            return jsonify({"error": "Cover and secret files are required."}), 400
        
        cover_file = request.files['coverFile']
        secret_file = request.files['secretFile']
        password = request.form.get('password')
        message = request.form.get('message')  # New: get optional message

        if not password:
            return jsonify({"error": "Password is required."}), 400

        cover_path = os.path.join(session_folder, cover_file.filename)
        secret_path = os.path.join(session_folder, secret_file.filename)
        output_filename = "stego_" + cover_file.filename
        output_path = os.path.join(session_folder, output_filename)

        cover_file.save(cover_path)
        secret_file.save(secret_path)

        stego_core.hide_data(cover_path, secret_path, password, output_path, message=message)
        
        @after_this_request
        def cleanup(response):
            try:
                shutil.rmtree(session_folder)
                app.logger.info(f"Successfully cleaned up session folder: {session_folder}")
            except Exception as e:
                app.logger.error(f"Error cleaning up session folder {session_folder}: {e}")
            return response

        return send_from_directory(session_folder, output_filename, as_attachment=True)

    except Exception as e:
        app.logger.error("An exception occurred during embedding:", exc_info=True)
        if os.path.exists(session_folder):
            shutil.rmtree(session_folder)
        return jsonify({"error": "An internal server error occurred. Check the server logs for details."}), 500


@app.route('/api/extract', methods=['POST'])
def extract_api():
    app.logger.info("Received request for /api/extract")
    request_id = str(uuid.uuid4())
    session_folder = os.path.join(TEMP_FOLDER, request_id)
    os.makedirs(session_folder)

    try:
        if 'stegoFile' not in request.files:
            return jsonify({"error": "Stego file is required."}), 400
        
        stego_file = request.files['stegoFile']
        password = request.form.get('password')
        
        stego_path = os.path.join(session_folder, stego_file.filename)
        stego_file.save(stego_path)

        # Updated: extract_data returns (filedata, filename, message)
        filedata, original_filename, message = stego_core.extract_data(stego_path, password)

        if filedata is None or original_filename is None:
            shutil.rmtree(session_folder)
            return jsonify({"error": "Extraction failed. Wrong password, corrupt file, or missing filename."}), 400
        
        output_filename = original_filename
        output_path = os.path.join(session_folder, output_filename)
        with open(output_path, 'wb') as f:
            f.write(filedata)

        # Schedule delayed cleanup (10 minutes)
        schedule_delayed_cleanup(session_folder, delay_seconds=600)

        # Instead of sending the file directly, return a JSON with the message and a download endpoint
        return jsonify({
            "message": message,
            "filename": output_filename,
            "download_url": f"/api/download/{request_id}/{output_filename}"
        })

    except Exception as e:
        app.logger.error("An exception occurred during extraction:", exc_info=True)
        if os.path.exists(session_folder):
            shutil.rmtree(session_folder)
        return jsonify({"error": "An internal server error occurred. Check the server logs for details."}), 500

# New endpoint to download the extracted file after extraction
@app.route('/api/download/<session_id>/<filename>', methods=['GET'])
def download_extracted_file(session_id, filename):
    session_folder = os.path.join(TEMP_FOLDER, session_id)
    return send_from_directory(session_folder, filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
