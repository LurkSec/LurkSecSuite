import hashlib
import os
import shutil
import time
from typing import Dict, List, Any

class FileQuarantiner:
    """
    Safely isolates suspicious binaries into a local .quarantine directory vault.
    Calculates SHA-256 hash and revokes direct execution access.
    """
    QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".quarantine")

    @classmethod
    def _ensure_dir(cls):
        if not os.path.exists(cls.QUARANTINE_DIR):
            os.makedirs(cls.QUARANTINE_DIR, exist_ok=True)

    @classmethod
    def quarantine_file(cls, file_path: str) -> Dict[str, Any]:
        cls._ensure_dir()
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        if not os.path.exists(file_path):
            return {
                "success": False,
                "timestamp": now,
                "original_path": file_path,
                "message": f"File not found: '{file_path}'"
            }

        try:
            # Calculate SHA-256 Hash
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha256_hash = hasher.hexdigest()

            base_name = os.path.basename(file_path)
            quarantine_filename = f"{int(time.time())}_{sha256_hash[:8]}_{base_name}.quarantine"
            target_dest = os.path.join(cls.QUARANTINE_DIR, quarantine_filename)

            # Move file to quarantine vault
            shutil.move(file_path, target_dest)

            # Revoke execution permissions
            try:
                os.chmod(target_dest, 0o444)
            except Exception:
                pass

            return {
                "success": True,
                "timestamp": now,
                "original_path": file_path,
                "quarantine_path": target_dest,
                "sha256": sha256_hash,
                "message": f"Binary '{base_name}' safely isolated in EDR Quarantine Vault."
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "original_path": file_path,
                "message": f"Quarantine operation error: {str(ex)}"
            }

    @classmethod
    def list_quarantined_files(cls) -> List[Dict[str, Any]]:
        cls._ensure_dir()
        results = []
        try:
            for fname in os.listdir(cls.QUARANTINE_DIR):
                fpath = os.path.join(cls.QUARANTINE_DIR, fname)
                if os.path.isfile(fpath):
                    stat = os.stat(fpath)
                    results.append({
                        "filename": fname,
                        "vault_path": fpath,
                        "size_bytes": stat.st_size,
                        "quarantined_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))
                    })
        except Exception:
            pass
        return results
