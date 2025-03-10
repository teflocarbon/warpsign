import os
import logging
from pathlib import Path
from flask import Flask, request, render_template, jsonify, url_for
from warpsign.logger import get_console

# Disable Flask's default logging
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

# Create console object for our own logging
console = get_console()

# Simple flag to track completion
DONE = False
UPLOADED_CERTS = {"development": False, "distribution": False}

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.absolute()
TEMPLATE_DIR = SCRIPT_DIR / "templates"
STATIC_DIR = SCRIPT_DIR / "static"

# Create Flask app
app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
)

# Enable debug mode when running directly
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.route("/")
def index():
    try:
        return render_template("index.html")
    except Exception as e:
        return f"Error loading template: {str(e)}<br>Template directory: {TEMPLATE_DIR}<br>Static directory: {STATIC_DIR}"


@app.route("/debug")
def debug():
    """Debug endpoint to check if the server is running and paths are correct"""
    template_exists = (TEMPLATE_DIR / "index.html").exists()
    css_exists = (STATIC_DIR / "css" / "styles.css").exists()
    js_exists = (STATIC_DIR / "js" / "main.js").exists()

    return jsonify(
        {
            "server": "running",
            "script_dir": str(SCRIPT_DIR),
            "template_dir": str(TEMPLATE_DIR),
            "static_dir": str(STATIC_DIR),
            "template_exists": template_exists,
            "css_exists": css_exists,
            "js_exists": js_exists,
        }
    )


@app.route("/upload/<cert_type>", methods=["POST"])
def upload_certificate(cert_type):
    global UPLOADED_CERTS

    if cert_type not in ["development", "distribution"]:
        return jsonify({"success": False, "error": "Invalid certificate type"})

    if "certificate" not in request.files:
        return jsonify({"success": False, "error": "No file part"})

    file = request.files["certificate"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No selected file"})

    password = request.form.get("password", "")

    try:
        # Ensure base directory exists
        cert_dir = Path(app.config["CERT_BASE_DIR"]) / cert_type
        if not cert_dir.exists():
            cert_dir.mkdir(parents=True, exist_ok=True)

        # Save certificate file
        cert_path = cert_dir / "cert.p12"
        file.save(cert_path)

        # Save password to file
        pass_path = cert_dir / "cert_pass.txt"
        with open(pass_path, "w") as f:
            f.write(password)

        # Mark this certificate type as uploaded
        UPLOADED_CERTS[cert_type] = True

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/shutdown", methods=["POST"])
def shutdown():
    """Mark the upload as done"""
    global DONE
    DONE = True
    return jsonify({"success": True})


def start_certificate_server(port, cert_base_dir):
    """Start the Flask server for certificate uploads."""
    app.config["CERT_BASE_DIR"] = cert_base_dir

    # Reset flags
    global DONE, UPLOADED_CERTS
    DONE = False
    UPLOADED_CERTS = {"development": False, "distribution": False}

    # Check if template and static files exist before starting
    if not (TEMPLATE_DIR / "index.html").exists():
        console.print(
            f"[yellow]WARNING:[/] Template file not found at {TEMPLATE_DIR / 'index.html'}"
        )
    if not (STATIC_DIR / "css" / "styles.css").exists():
        console.print(
            f"[yellow]WARNING:[/] CSS file not found at {STATIC_DIR / 'css' / 'styles.css'}"
        )
    if not (STATIC_DIR / "js" / "main.js").exists():
        console.print(
            f"[yellow]WARNING:[/] JS file not found at {STATIC_DIR / 'js' / 'main.js'}"
        )

    # Start the server - without the default logging
    app.run(host="127.0.0.1", port=port, debug=False)


def is_done():
    """Check if the user has clicked done"""
    return DONE


def get_uploaded_certs():
    """Get which certificates have been uploaded"""
    return UPLOADED_CERTS
