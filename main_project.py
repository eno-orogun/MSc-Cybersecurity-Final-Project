import sqlite3
import json
import os
import datetime
import subprocess
import hashlib
import time

# --- Configuration ---
DATABASE_FILE = '/home/student/project/db/user_activity.db'  # path to user activity dabatabse 
APK_STORAGE_DIR = '/home/student/project/apks'              # path Where pulled APKs will be stored
JADX_BINARY_PATH = '/home/Downloads/jadx_bin'                  # Path to the project JADX executable
MOBSF_REPORT_BASE_DIR = '/home/student/project/Mobile-Security-Framework-MobSF/mobsf/MobSF/uploads/' # path Where MobSF stores its reports 
MOBSF_SERVER_URL = 'http://127.0.0.1:8000'                   # url for accessing MobSF GUI on web browsers
MOBSF_API_KEY = 'ec926a47e9f8362ffc7feadea9ac9bed1cb4bb78e27366b4cab6f33022976b4a'           # MobSF API Key 


# --- Database Management Functions ---

def connect_db():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

def create_all_tables():
    """Creates all necessary tables if they don't exist."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        # users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # avd_sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS avd_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                avd_name TEXT NOT NULL,
                start_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                end_time TEXT,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );
        """)
        # apk_downloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS apk_downloads (
                apk_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                package_name TEXT NOT NULL,
                app_name TEXT,
                version_name TEXT,
                version_code INTEGER,
                source_store TEXT NOT NULL,
                download_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                file_path_on_avd TEXT,
                md5_hash TEXT,
                sha256_hash TEXT,
                FOREIGN KEY (session_id) REFERENCES avd_sessions(session_id)
            );
        """)
        # user_actions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_actions (
                action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                apk_id INTEGER,
                action_type TEXT NOT NULL,
                action_details TEXT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES avd_sessions(session_id),
                FOREIGN KEY (apk_id) REFERENCES apk_downloads(apk_id)
            );
        """)
        # static_analysis_results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS static_analysis_results (
                analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_id INTEGER NOT NULL,
                analysis_tool TEXT NOT NULL,
                analysis_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                findings_summary TEXT,
                detailed_results_path TEXT,
                json_results TEXT,
                FOREIGN KEY (apk_id) REFERENCES apk_downloads(apk_id)
            );
        """)
        # dynamic_analysis_results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dynamic_analysis_results (
                dynamic_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_id INTEGER NOT NULL,
                analysis_tool TEXT NOT NULL DEFAULT 'MobSF',
                analysis_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                mobsf_report_url TEXT,
                network_traffic_summary TEXT,
                api_calls_summary TEXT,
                permissions_used_runtime TEXT,
                sensitive_data_leaks TEXT,
                screenshots_path TEXT,
                logcat_output_path TEXT,
                json_raw_results_path TEXT,
                risk_score REAL,
                notes TEXT,
                FOREIGN KEY (apk_id) REFERENCES apk_downloads(apk_id)
            );
        """)
        conn.commit()
        print("All database tables ensured to exist.")
    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")
    finally:
        conn.close()

def get_or_create_user(username):
    """Gets user_id for a username, creates if not exists."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user:
            return user['user_id']
        else:
            cursor.execute("INSERT INTO users (username) VALUES (?)", (username,))
            conn.commit()
            print(f"User '{username}' created.")
            return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error getting/creating user: {e}")
        return None
    finally:
        conn.close()

def start_avd_session(user_id, avd_name, notes=None):
    """Logs the start of an AVD session."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO avd_sessions (user_id, avd_name, notes)
            VALUES (?, ?, ?)
        """, (user_id, avd_name, notes))
        conn.commit()
        session_id = cursor.lastrowid
        print(f"AVD session started (ID: {session_id}) for AVD: {avd_name}")
        return session_id
    except sqlite3.Error as e:
        print(f"Database error starting AVD session: {e}")
        return None
    finally:
        conn.close()

def end_avd_session(session_id):
    """Logs the end time of an AVD session."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE avd_sessions SET end_time = CURRENT_TIMESTAMP WHERE session_id = ?
        """, (session_id,))
        conn.commit()
        print(f"AVD session {session_id} ended.")
    except sqlite3.Error as e:
        print(f"Database error ending AVD session: {e}")
    finally:
        conn.close()

def log_apk_download(session_id, package_name, app_name, version_name, version_code, source_store, file_path_on_avd, md5_hash, sha256_hash):
    """Logs details of an APK download/installation."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO apk_downloads (session_id, package_name, app_name, version_name, version_code, source_store, file_path_on_avd, md5_hash, sha256_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, package_name, app_name, version_name, version_code, source_store, file_path_on_avd, md5_hash, sha256_hash))
        conn.commit()
        apk_id = cursor.lastrowid
        print(f"APK '{app_name}' ({package_name}) logged (ID: {apk_id}).")
        return apk_id
    except sqlite3.Error as e:
        print(f"Database error logging APK download: {e}")
        return None
    finally:
        conn.close()

def log_user_action(session_id, action_type, action_details, apk_id=None):
    """Logs a specific user action within an AVD session."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_actions (session_id, apk_id, action_type, action_details)
            VALUES (?, ?, ?, ?)
        """, (session_id, apk_id, action_type, action_details))
        conn.commit()
        print(f"Logged action: '{action_type}' (Details: {action_details[:50]}...)")
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error logging user action: {e}")
        return None
    finally:
        conn.close()

def log_static_analysis_result(apk_id, analysis_tool, findings_summary, detailed_results_path, json_results=None):
    """Logs the results of static analysis."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO static_analysis_results (apk_id, analysis_tool, findings_summary, detailed_results_path, json_results)
            VALUES (?, ?, ?, ?, ?)
        """, (apk_id, analysis_tool, findings_summary, detailed_results_path, json_results))
        conn.commit()
        print(f"Static analysis result logged for APK ID: {apk_id} using {analysis_tool}.")
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error logging static analysis result: {e}")
        return None
    finally:
        conn.close()

def log_dynamic_analysis_result(
    apk_id,
    mobsf_report_url,
    network_traffic_summary,
    api_calls_summary,
    permissions_used_runtime,
    sensitive_data_leaks,
    screenshots_path,
    logcat_output_path,
    json_raw_results_path,
    risk_score,
    notes=None
):
    """Inserts a new dynamic analysis result into the database."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO dynamic_analysis_results (
                apk_id, analysis_tool, mobsf_report_url, network_traffic_summary,
                api_calls_summary, permissions_used_runtime, sensitive_data_leaks,
                screenshots_path, logcat_output_path, json_raw_results_path,
                risk_score, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            apk_id,
            'MobSF',
            mobsf_report_url,
            api_calls_summary, 
            network_traffic_summary, # crosscheck on dynamics_analysis_results table
            permissions_used_runtime, # crosscheck on dynamics_analysis_results table
            sensitive_data_leaks,
            screenshots_path,
            logcat_output_path,
            json_raw_results_path,
            risk_score,
            notes
        ))
        conn.commit()
        print(f"Dynamic analysis result logged for APK ID: {apk_id}")
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error logging dynamic analysis result: {e}")
        return None
    finally:
        conn.close()

# --- MobSF JSON Parsing and Summarization Logic ---

def parse_mobsf_dynamic_json(json_file_path):
    """
    Parses a MobSF dynamic analysis JSON report and extracts summarized data.
    """
    if not os.path.exists(json_file_path):
        print(f"Error: MobSF JSON report not found at {json_file_path}")
        return None

    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        risk_score = report_data.get('score', 0)
        app_name = report_data.get('app_name', 'N/A')
        package_name = report_data.get('package_name', 'N/A')
        version_name = report_data.get('version_name', 'N/A')
        md5_hash = report_data.get('md5', 'N/A')
        sha256_hash = report_data.get('sha256', 'N/A')

        network_summary = []
        network_data = report_data.get('dynamic_analysis', {}).get('network_analysis', {})
        if network_data.get('urls'):
            network_summary.append(f"Connected to {len(network_data['urls'])} unique URLs.")
        if network_data.get('domains'):
            network_summary.append(f"Accessed {len(network_data['domains'])} unique domains.")
        if network_data.get('traffic_summary'):
            total_traffic = network_data['traffic_summary'].get('Total Traffic', 'N/A')
            network_summary.append(f"Total traffic: {total_traffic}.")
        if report_data.get('traffic_features'):
             for feature in report_data['traffic_features']:
                 if feature.get('severity') in ['high', 'medium']:
                     network_summary.append(f"Suspicious network: {feature.get('title', 'N/A')}")

        network_traffic_summary = "; ".join(network_summary) if network_summary else "No specific network activity observed."

        api_calls = report_data.get('api_calls', [])
        api_calls_summary_list = []
        if api_calls:
            suspicious_apis = [
                call['api_call'] for call in api_calls
                if 'sensitive' in call and call['sensitive']
            ]
            if suspicious_apis:
                api_calls_summary_list.append(f"Observed {len(suspicious_apis)} sensitive API calls.")
                if len(suspicious_apis) > 3:
                    api_calls_summary_list.append(f"Examples: {', '.join(suspicious_apis[:3])}...")
                else:
                     api_calls_summary_list.append(f"Examples: {', '.join(suspicious_apis)}")

        api_calls_summary = "; ".join(api_calls_summary_list) if api_calls_summary_list else "No significant API calls observed."

        permissions_used = []
        if report_data.get('permissions_used'):
            permissions_used = [perm['permission'] for perm in report_data['permissions_used']]
        permissions_used_runtime = ", ".join(permissions_used) if permissions_used else "No runtime permissions observed."

        sensitive_data_leaks = []
        if report_data.get('sensitive_info'):
            for info_type, leaks in report_data['sensitive_info'].items():
                if leaks:
                    sensitive_data_leaks.append(f"{info_type.replace('_', ' ').title()}: {len(leaks)} instances.")
        sensitive_data_leaks_summary = "; ".join(sensitive_data_leaks) if sensitive_data_leaks else "No sensitive data leaks detected."

        report_hash = report_data.get('hash', '')
        dynamic_root_path = os.path.join(MOBSF_REPORT_BASE_DIR, report_hash, 'dynamic_analysis')

        screenshots_path = os.path.join(dynamic_root_path, 'screenshots') if os.path.exists(os.path.join(dynamic_root_path, 'screenshots')) else None
        logcat_output_path = os.path.join(dynamic_root_path, 'logcat.txt') if os.path.exists(os.path.join(dynamic_root_path, 'logcat.txt')) else None
        json_raw_results_path = json_file_path

        mobsf_report_url = f"{MOBSF_SERVER_URL}/?hash={report_hash}#dynamic_analysis" if report_hash and MOBSF_SERVER_URL else None

        return {
            'app_name': app_name,
            'package_name': package_name,
            'version_name': version_name,
            'md5_hash': md5_hash,
            'sha256_hash': sha256_hash,
            'mobsf_report_url': mobsf_report_url,
            'network_traffic_summary': network_traffic_summary,
            'api_calls_summary': api_calls_summary,
            'permissions_used_runtime': permissions_used_runtime,
            'sensitive_data_leaks': sensitive_data_leaks_summary,
            'screenshots_path': screenshots_path,
            'logcat_output_path': logcat_output_path,
            'json_raw_results_path': json_raw_results_path,
            'risk_score': risk_score,
        }

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {json_file_path}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while parsing {json_file_path}: {e}")
        return None

# --- Helper Functions ---

def run_adb_command(command_args, serial=None, capture_output=True, text=True):
    """
    Runs an ADB command and handles its output.
    Args:
        command_args (list): List of arguments for the adb command (e.g., ["install", "app.apk"]).
        serial (str, optional): The AVD serial number. If None, ADB will target the only connected device.
        capture_output (bool): Whether to capture stdout/stderr.
        text (bool): Decode stdout/stderr as text.
    Returns:
        subprocess.CompletedProcess: The result of the subprocess call.
    """
    full_command = ["adb"]
    if serial:
        full_command.extend(["-s", serial])
    full_command.extend(command_args)

    try:
        print(f"Executing: {' '.join(full_command)}")
        result = subprocess.run(full_command, capture_output=capture_output, text=text, check=False)
        if result.returncode != 0:
            print(f"ADB Command Failed: {' '.join(full_command)}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
        return result
    except FileNotFoundError:
        print("Error: 'adb' command not found. Ensure ADB is installed and in your PATH.")
        return None
    except Exception as e:
        print(f"An error occurred while running ADB command: {e}")
        return None

def calculate_file_hashes(file_path):
    """Calculates MD5 and SHA256 hashes of a given file."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found for hashing: {file_path}")
        return None, None
    except Exception as e:
        print(f"Error calculating hashes for {file_path}: {e}")
        return None, None

def get_avd_serial():
    """Lists connected AVDs and allows the user to select one."""
    result = run_adb_command(["devices"])
    if not result or result.returncode != 0:
        print("Could not list ADB devices. Is ADB server running and AVDs connected?")
        return None

    devices = []
    lines = result.stdout.splitlines()
    for line in lines:
        if "\tdevice" in line and "emulator" in line:
            serial = line.split("\t")[0].strip()
            devices.append(serial)

    if not devices:
        print("No AVDs found. Please ensure your emulators are running.")
        return None
    elif len(devices) == 1:
        print(f"Automatically selected AVD: {devices[0]}")
        return devices[0]
    else:
        print("Multiple AVDs found:")
        for i, serial in enumerate(devices):
            print(f"{i+1}. {serial}")
        while True:
            try:
                choice = int(input("Select an AVD by number: "))
                if 1 <= choice <= len(devices):
                    return devices[choice - 1]
                else:
                    print("Invalid choice. Please enter a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")

def get_apk_details_from_user():
    """Prompts user for APK details for logging."""
    package_name = input("Enter APK Package Name (e.g., com.example.app): ").strip()
    app_name = input("Enter App Name (e.g., My Awesome App): ").strip()
    version_name = input("Enter Version Name (e.g., 1.0.0): ").strip()
    version_code = input("Enter Version Code (e.g., 1): ").strip()
    try:
        version_code = int(version_code)
    except ValueError:
        print("Invalid version code, defaulting to 0.")
        version_code = 0
    source_store = input("Enter Source Store (Google Play/APKPure/Other): ").strip()
    return package_name, app_name, version_name, version_code, source_store

def get_apk_id_from_db(package_name):
    """Retrieves an APK's ID from the database based on package name."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT apk_id FROM apk_downloads WHERE package_name = ? ORDER BY download_time DESC LIMIT 1", (package_name,))
        result = cursor.fetchone()
        return result['apk_id'] if result else None
    except sqlite3.Error as e:
        print(f"Database error retrieving APK ID: {e}")
        return None
    finally:
        conn.close()

# --- Main Project Workflow ---

def main():
    """Main function to run the project workflow."""
    print("--- Mobile Forensic Investigative Project ---")

    # 1. Database Setup
    create_all_tables()

    # 2. User Identification
    username = input("Enter your username: ").strip()
    user_id = get_or_create_user(username)
    if not user_id:
        print("Failed to get or create user. Exiting.")
        return

    # 3. ADB Server Check
    print("\nStarting ADB server...")
    run_adb_command(["start-server"], capture_output=False)
    time.sleep(1) # Give ADB a moment to start

    # 4. AVD Selection
    selected_avd_serial = get_avd_serial()
    if not selected_avd_serial:
        print("No AVD selected. Please start an AVD and try again.")
        return

    avd_name_input = input(f"Enter a descriptive name for this AVD session (e.g., 'Google Play AVD', 'APKPure AVD'): ").strip()
    current_session_id = start_avd_session(user_id, avd_name_input)
    if not current_session_id:
        print("Failed to start AVD session in database. Exiting.")
        return

    print(f"\nConnected to AVD: {selected_avd_serial}")
    print(f"Session ID: {current_session_id}")

    current_apk_id = None # To keep track of the last APK analyzed/interacted with

    while True:
        print("\n--- AVD Session Menu ---")
        print("1. Install/Log APK")
        print("2. Launch Application")
        print("3. Grant Permission")
        print("4. Pull APK from AVD")
        print("5. Perform Static Analysis (JADX)")
        print("6. Perform Dynamic Analysis (MobSF)")
        print("7. View Current Session Logs (Basic)")
        print("8. End AVD Session and Exit")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            apk_path_on_host = input("Enter full path to APK file on your host machine: ").strip()
            if not os.path.exists(apk_path_on_host):
                print("Error: APK file not found on host.")
                continue

            # Install APK
            print(f"Installing {os.path.basename(apk_path_on_host)} on {selected_avd_serial}...")
            install_result = run_adb_command(["install", apk_path_on_host], serial=selected_avd_serial)
            if install_result and install_result.returncode == 0:
                print("APK installed successfully.")
                # Log APK details
                package_name, app_name, version_name, version_code, source_store = get_apk_details_from_user()
                md5, sha256 = calculate_file_hashes(apk_path_on_host)
                # For installed APKs, file_path_on_avd is usually /data/app/package_name-X/base.apk
                # This is a heuristic and might need refinement.
                file_path_on_avd = f"/data/app/{package_name}-*/base.apk" # Placeholder, actual path varies by Android version/install
                current_apk_id = log_apk_download(current_session_id, package_name, app_name, version_name, version_code, source_store, file_path_on_avd, md5, sha256)
                log_user_action(current_session_id, "APK_INSTALL", f"Installed {package_name} from {source_store}", current_apk_id)
            else:
                print("APK installation failed.")

        elif choice == '2':
            package_name = input("Enter package name of the app to launch (e.g., com.android.calculator2): ").strip()
            activity_name = input("Enter main activity (e.g., .Calculator) or leave empty for default: ").strip()
            command = ["shell", "am", "start", "-n", f"{package_name}/{activity_name if activity_name else ''}"]
            launch_result = run_adb_command(command, serial=selected_avd_serial)
            if launch_result and launch_result.returncode == 0:
                print(f"Attempted to launch {package_name}.")
                apk_id_for_action = get_apk_id_from_db(package_name)
                log_user_action(current_session_id, "APP_LAUNCH", f"Launched {package_name}", apk_id_for_action)
            else:
                print("Failed to launch application. Check package name/activity.")

        elif choice == '3':
            package_name = input("Enter package name of the app: ").strip()
            permission = input("Enter permission to grant (e.g., android.permission.CAMERA): ").strip()
            command = ["shell", "pm", "grant", package_name, permission]
            grant_result = run_adb_command(command, serial=selected_avd_serial)
            if grant_result and grant_result.returncode == 0:
                print(f"Attempted to grant {permission} to {package_name}.")
                apk_id_for_action = get_apk_id_from_db(package_name)
                log_user_action(current_session_id, "PERMISSION_GRANT", f"Granted {permission} to {package_name}", apk_id_for_action)
            else:
                print("Failed to grant permission.")

        elif choice == '4':
            apk_path_on_avd = input("Enter full path to APK on AVD (e.g., /data/app/com.example.app-1/base.apk): ").strip()
            local_save_path = os.path.join(APK_STORAGE_DIR, os.path.basename(apk_path_on_avd))
            os.makedirs(APK_STORAGE_DIR, exist_ok=True)

            print(f"Pulling {apk_path_on_avd} to {local_save_path}...")
            pull_result = run_adb_command(["pull", apk_path_on_avd, local_save_path], serial=selected_avd_serial)
            if pull_result and pull_result.returncode == 0:
                print("APK pulled successfully.")
                md5, sha256 = calculate_file_hashes(local_save_path)
                print(f"MD5: {md5}, SHA256: {sha256}")

                # Update or log APK details if this is a new APK or update
                package_name = input("Enter package name for the pulled APK (e.g., com.example.app): ").strip()
                app_name = input("Enter App Name for pulled APK: ").strip()
                version_name = input("Enter Version Name for pulled APK: ").strip()
                version_code = input("Enter Version Code for pulled APK: ").strip()
                try: version_code = int(version_code)
                except ValueError: version_code = 0
                source_store = "Pulled from AVD"

                # Check if this APK (by package name + hash) already exists
                conn = connect_db()
                cursor = conn.cursor()
                existing_apk_id = None
                try:
                    cursor.execute("SELECT apk_id FROM apk_downloads WHERE package_name = ? AND sha256_hash = ?", (package_name, sha256))
                    result = cursor.fetchone()
                    if result:
                        existing_apk_id = result['apk_id']
                finally:
                    conn.close()

                if existing_apk_id:
                    current_apk_id = existing_apk_id
                    print(f"Pulled APK already exists in DB (ID: {current_apk_id}).")
                else:
                    current_apk_id = log_apk_download(current_session_id, package_name, app_name, version_name, version_code, source_store, apk_path_on_avd, md5, sha256)

                log_user_action(current_session_id, "APK_PULL", f"Pulled {package_name} to {local_save_path}", current_apk_id)
            else:
                print("Failed to pull APK.")

        elif choice == '5':
            if not current_apk_id:
                print("Please install or pull an APK first to set the current APK ID.")
                continue
            
            apk_path_on_host = input("Enter full path to the APK file on your host for JADX analysis: ").strip()
            if not os.path.exists(apk_path_on_host):
                print("Error: APK file not found on host for JADX analysis.")
                continue

            output_dir = os.path.join(APK_STORAGE_DIR, "jadx_output", os.path.basename(apk_path_on_host).replace(".apk", ""))
            os.makedirs(output_dir, exist_ok=True)

            print(f"Running JADX on {apk_path_on_host} to {output_dir}...")
            try:
                jadx_command = [JADX_BINARY_PATH, "-d", output_dir, apk_path_on_host]
                print(f"Executing: {' '.join(jadx_command)}")
                jadx_result = subprocess.run(jadx_command, capture_output=True, text=True, check=False)

                if jadx_result.returncode == 0:
                    print("JADX analysis completed successfully.")
                    findings_summary = "JADX decompilation successful."
                    # You could add more sophisticated parsing here, e.g., looking for certain strings in output files
                    # For simplicity, we just log the output path.
                    log_static_analysis_result(current_apk_id, "JADX", findings_summary, output_dir)
                    log_user_action(current_session_id, "STATIC_ANALYSIS_JADX", f"JADX analysis for {os.path.basename(apk_path_on_host)} completed.", current_apk_id)
                else:
                    print("JADX analysis failed.")
                    print(f"JADX STDOUT: {jadx_result.stdout}")
                    print(f"JADX STDERR: {jadx_result.stderr}")
                    log_user_action(current_session_id, "STATIC_ANALYSIS_JADX_FAILED", f"JADX analysis for {os.path.basename(apk_path_on_host)} failed.", current_apk_id)

            except FileNotFoundError:
                print(f"Error: JADX executable not found at {JADX_BINARY_PATH}. Please check the path.")
            except Exception as e:
                print(f"An error occurred during JADX analysis: {e}")

        elif choice == '6':
            if not current_apk_id:
                print("Please install or pull an APK first to set the current APK ID.")
                continue

            print("\n--- MobSF Dynamic Analysis ---")
            print("NOTE: This script assumes MobSF dynamic analysis has been performed manually or via a separate script.")
            print("You need to provide the path to the generated MobSF JSON report.")

            mobsf_json_report_path = input("Enter full path to the MobSF dynamic analysis JSON report: ").strip()

            if not os.path.exists(mobsf_json_report_path):
                print("Error: MobSF JSON report not found at the specified path.")
                continue

            parsed_data = parse_mobsf_dynamic_json(mobsf_json_report_path)

            if parsed_data:
                log_dynamic_analysis_result(
                    apk_id=current_apk_id,
                    mobsf_report_url=parsed_data['mobsf_report_url'],
                    network_traffic_summary=parsed_data['network_traffic_summary'],
                    api_calls_summary=parsed_data['api_calls_summary'],
                    permissions_used_runtime=parsed_data['permissions_used_runtime'],
                    sensitive_data_leaks=parsed_data['sensitive_data_leaks'],
                    screenshots_path=parsed_data['screenshots_path'],
                    logcat_output_path=parsed_data['logcat_output_path'],
                    json_raw_results_path=parsed_data['json_raw_results_path'],
                    risk_score=parsed_data['risk_score']
                )
                log_user_action(current_session_id, "DYNAMIC_ANALYSIS_MOBSF", f"MobSF dynamic analysis logged for {parsed_data.get('package_name', 'N/A')}", current_apk_id)
            else:
                print("Failed to parse MobSF dynamic report. Data not logged.")
                log_user_action(current_session_id, "DYNAMIC_ANALYSIS_MOBSF_FAILED", f"Failed to parse MobSF report from {mobsf_json_report_path}", current_apk_id)

        elif choice == '7':
            conn = connect_db()
            cursor = conn.cursor()
            try:
                print(f"\n--- Logs for Session ID: {current_session_id} ---")
                cursor.execute("""
                    SELECT * FROM user_actions WHERE session_id = ? ORDER BY timestamp ASC
                """, (current_session_id,))
                actions = cursor.fetchall()
                if actions:
                    for action in actions:
                        print(f"[{action['timestamp']}] Type: {action['action_type']}, Details: {action['action_details']}")
                else:
                    print("No actions logged for this session yet.")
            except sqlite3.Error as e:
                print(f"Error retrieving session logs: {e}")
            finally:
                conn.close()

        elif choice == '8':
            print("Ending AVD session and exiting.")
            end_avd_session(current_session_id)
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    # Ensure APK storage directory exists
    os.makedirs(APK_STORAGE_DIR, exist_ok=True)
    main()