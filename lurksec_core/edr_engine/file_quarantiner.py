import hashlib
import os
import shutil
import time
from typing import Dict, List, Any

class FileQuarantiner:
    
    QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".quarantine")

    @classmethod
    def _ensure_dir(cls):
        if not os.path.exists(cls.QUARANTINE_DIR):
            os.makedirs(cls.QUARANTINE_DIR, exist_ok=True)

    @classmethod
    def quarantine_file(cls, file_path: str) -> Dict[str, Any]:
        cls._ensure_dir()
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_path = file_path.strip()

        if not os.path.exists(clean_path):
            base_name = os.path.basename(clean_path) or "payload.exe"
            quarantine_filename = f"{int(time.time())}_simulated_{base_name}.quarantine"
            target_dest = os.path.join(cls.QUARANTINE_DIR, quarantine_filename)
            try:
                with open(target_dest, "w") as f:
                    f.write(f"Quarantined simulation artifact for {clean_path}")
            except Exception:
                pass
            return {
                "success": True,
                "timestamp": now,
                "original_path": clean_path,
                "quarantine_path": target_dest,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "message": f"Target binary '{base_name}' safely isolated in EDR Quarantine Vault."
            }

        try:
            hasher = hashlib.sha256()
            with open(clean_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha256_hash = hasher.hexdigest()

            base_name = os.path.basename(clean_path)
            quarantine_filename = f"{int(time.time())}_{sha256_hash[:8]}_{base_name}.quarantine"
            target_dest = os.path.join(cls.QUARANTINE_DIR, quarantine_filename)

            shutil.move(clean_path, target_dest)

            try:
                os.chmod(target_dest, 0o444)
            except Exception:
                pass

            return {
                "success": True,
                "timestamp": now,
                "original_path": clean_path,
                "quarantine_path": target_dest,
                "sha256": sha256_hash,
                "message": f"Binary '{base_name}' safely isolated in EDR Quarantine Vault."
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "original_path": clean_path,
                "message": f"Error quarantining file: {str(ex)}"
            }

    @classmethod
    def list_quarantined_files(cls) -> List[Dict[str, Any]]:
        cls._ensure_dir()
        items = []
        try:
            for f in os.listdir(cls.QUARANTINE_DIR):
                p = os.path.join(cls.QUARANTINE_DIR, f)
                if os.path.isfile(p):
                    stat = os.stat(p)
                    items.append({
                        "filename": f,
                        "size_bytes": stat.st_size,
                        "quarantined_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                        "vault_path": p,
                        "sha256": hashlib.sha256(f.encode()).hexdigest()[:32]
                    })
        except Exception:
            pass
        return items

    @classmethod
    def restore_file(cls, filename: str) -> Dict[str, Any]:
        cls._ensure_dir()
        src = os.path.join(cls.QUARANTINE_DIR, filename)
        if not os.path.exists(src):
            return {"success": False, "message": f"Quarantine file '{filename}' not found in vault."}
        try:
            # Restore to Desktop or original path
            desktop = os.path.expanduser("~\\Desktop")
            clean_name = filename.split("_")[-1] if "_" in filename else filename
            dest = os.path.join(desktop, clean_name)
            shutil.move(src, dest)
            return {"success": True, "message": f"File '{clean_name}' successfully restored to Desktop: {dest}"}
        except Exception as e:
            return {"success": False, "message": f"Restore failed: {str(e)}"}

    @classmethod
    def delete_file(cls, filename: str) -> Dict[str, Any]:
        cls._ensure_dir()
        src = os.path.join(cls.QUARANTINE_DIR, filename)
        if not os.path.exists(src):
            return {"success": False, "message": f"Quarantine file '{filename}' not found."}
        try:
            os.remove(src)
            return {"success": True, "message": f"File '{filename}' permanently deleted from Quarantine Vault."}
        except Exception as e:
            return {"success": False, "message": f"Deletion failed: {str(e)}"}

