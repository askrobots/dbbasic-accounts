"""
Simple TSV database wrapper for passwd/shadow/group files
"""

import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
import fcntl


class Database:
    """Simple TSV database with headers"""

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Read headers if file exists
        if self.path.exists():
            with open(self.path, 'r') as f:
                reader = csv.DictReader(f, delimiter='\t')
                self.columns = reader.fieldnames or []
        else:
            self.columns = []

    def insert(self, row: Dict[str, Any]):
        """Insert a row"""
        with open(self.path, 'a') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                writer = csv.DictWriter(f, fieldnames=self.columns, delimiter='\t')
                writer.writerow(row)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def select(self, where: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Select rows with optional where clause"""
        if not self.path.exists():
            return []

        results = []
        with open(self.path, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                reader = csv.DictReader(f, delimiter='\t')
                for row in reader:
                    if where is None:
                        results.append(row)
                    else:
                        match = all(row.get(k) == v for k, v in where.items())
                        if match:
                            results.append(row)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        return results

    def update(self, where: Dict[str, Any], values: Dict[str, Any]):
        """Update rows matching where clause"""
        if not self.path.exists():
            return

        rows = []
        with open(self.path, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                reader = csv.DictReader(f, delimiter='\t')
                for row in reader:
                    match = all(row.get(k) == v for k, v in where.items())
                    if match:
                        row.update(values)
                    rows.append(row)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        # Write back
        with open(self.path, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                writer = csv.DictWriter(f, fieldnames=self.columns, delimiter='\t')
                writer.writeheader()
                writer.writerows(rows)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def delete(self, where: Dict[str, Any]):
        """Delete rows matching where clause"""
        if not self.path.exists():
            return

        rows = []
        with open(self.path, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                reader = csv.DictReader(f, delimiter='\t')
                for row in reader:
                    match = all(row.get(k) == v for k, v in where.items())
                    if not match:
                        rows.append(row)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        # Write back
        with open(self.path, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                writer = csv.DictWriter(f, fieldnames=self.columns, delimiter='\t')
                writer.writeheader()
                writer.writerows(rows)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
