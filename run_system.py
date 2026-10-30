"""
CyberSentinel AI - System Launcher
Starts the FastAPI Backend (serving API, WebSockets & UI) on port 8000.
"""
import os
import sys
import subprocess
import webbrowser
import time

def main():
    root_dir = os.path.abspath(os.path.dirname(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    venv_python = os.path.join(root_dir, "venv", "Scripts", "python.exe")
    
    if not os.path.exists(venv_python):
        venv_python = sys.executable

    print("=" * 65)
    print("  CYBERSENTINEL AI - THREAT DETECTION & INCIDENT RESPONSE SOC  ")
    print("=" * 65)
    print(f"[*] Workspace Root: {root_dir}")
    print(f"[*] Python Runtime: {venv_python}")
    print("[*] Unified Full-Stack Platform starting on: http://localhost:8000")
    print("[*] API Documentation available on: http://localhost:8000/docs")
    print("=" * 65)

    env = os.environ.copy()
    env["PYTHONPATH"] = backend_dir

    try:
        # Start uvicorn
        proc = subprocess.Popen(
            [venv_python, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"],
            cwd=backend_dir,
            env=env
        )
        print("\n[+] CyberSentinel SOC Server is ONLINE!")
        print("[+] Access Dashboard: http://localhost:8000")
        print("\nPress Ctrl+C to terminate the platform.\n")
        proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping CyberSentinel AI Platform...")
        proc.terminate()
        proc.wait()
        print("[+] Shutdown complete.")

if __name__ == "__main__":
    main()
