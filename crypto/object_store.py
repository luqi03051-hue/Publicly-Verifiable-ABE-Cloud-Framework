# -*- coding: utf-8 -*-
import json
from pathlib import Path
from typing import Any, Dict, Optional


class FileObjectStore:
    

    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def _obj_dir(self, object_id: str) -> Path:
        return self.root_dir / object_id

    def put(self, object_id: str, record: Dict[str, Any]) -> None:
        obj_dir = self._obj_dir(object_id)
        obj_dir.mkdir(parents=True, exist_ok=True)

        version = int(record.get("version", 1))
        ver_path = obj_dir / f"v{version}.json"
        ver_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

        latest_path = obj_dir / "latest.json"
        latest_path.write_text(json.dumps({"latest_version": version}, ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, object_id: str, version: Optional[int] = None) -> Dict[str, Any]:
        obj_dir = self._obj_dir(object_id)
        if version is None:
            latest_path = obj_dir / "latest.json"
            if not latest_path.exists():
                raise FileNotFoundError(f"latest.json not found for object_id={object_id}")
            latest = json.loads(latest_path.read_text(encoding="utf-8"))
            version = int(latest["latest_version"])

        ver_path = obj_dir / f"v{int(version)}.json"
        if not ver_path.exists():
            raise FileNotFoundError(f"record not found: {ver_path}")
        return json.loads(ver_path.read_text(encoding="utf-8"))

