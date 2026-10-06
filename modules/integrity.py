"""
modules/integrity.py - File integrity checking with SHA-256 hashing.
This module hashes files in a folder, saves baselines, and detects changes.
Designed to run in background threads to prevent UI freezing.
"""

import json
import hashlib
import os
import threading
from pathlib import Path
from typing import Dict, Tuple

BASELINE_FILE = "baseline.json"


def hash_file(filepath: Path) -> str:
    """
    Calculate SHA-256 hash of a file.
    
    Args:
        filepath: Path to the file
    
    Returns:
        Hex string of the SHA-256 hash
    
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file can't be read
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def hash_folder(folder_path: Path) -> Dict[str, str]:
    """
    Hash all files in a folder recursively.
    
    Args:
        folder_path: Path to the folder
    
    Returns:
        Dictionary mapping relative file paths to their SHA-256 hashes
    """
    hashes = {}
    for file_path in folder_path.rglob("*"):
        if file_path.is_file():
            try:
                rel_path = file_path.relative_to(folder_path)
                hashes[str(rel_path)] = hash_file(file_path)
            except (PermissionError, OSError):
                continue
    return hashes


def save_baseline(folder_path: Path) -> str:
    """
    Hash all files and save baseline to JSON file.
    Runs in a background thread to prevent UI freezing.
    
    Args:
        folder_path: Path to the folder to scan
    
    Returns:
        Path to the saved baseline file
    
    Raises:
        ValueError: If folder doesn't exist
    """
    if not folder_path.exists():
        raise ValueError(f"Folder does not exist: {folder_path}")
    
    def _save():
        hashes = hash_folder(folder_path)
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(hashes, f, indent=2)
    
    # Run in background thread
    thread = threading.Thread(target=_save, daemon=True)
    thread.start()
    thread.join()  # Wait for completion before returning
    
    return str(folder_path / BASELINE_FILE)


def load_baseline() -> Dict[str, str]:
    """
    Load baseline hashes from JSON file.
    
    Returns:
        Dictionary of file paths to hashes
    
    Raises:
        FileNotFoundError: If baseline.json doesn't exist
    """
    if not os.path.exists(BASELINE_FILE):
        raise FileNotFoundError("Baseline file not found. Create baseline first.")
    
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_files(current_hashes: Dict[str, str], baseline_hashes: Dict[str, str]) -> Dict[str, list]:
    """
    Compare current file hashes with baseline to detect changes.
    
    Args:
        current_hashes: Current file hashes (folder -> hash)
        baseline_hashes: Baseline file hashes (folder -> hash)
    
    Returns:
        Dictionary with 'modified', 'new', and 'deleted' file lists
    """
    modified = []
    new = []
    deleted = []
    
    current_paths = set(current_hashes.keys())
    baseline_paths = set(baseline_hashes.keys())
    
    # Find new and modified files
    for path in current_paths:
        if path not in baseline_paths:
            new.append(path)
        elif current_hashes[path] != baseline_hashes[path]:
            modified.append(path)
    
    # Find deleted files
    for path in baseline_paths:
        if path not in current_paths:
            deleted.append(path)
    
    return {
        "modified": modified,
        "new": new,
        "deleted": deleted
    }


def run_integrity_check(folder_path: str, baseline_path: str = BASELINE_FILE) -> Tuple[Dict[str, list], str]:
    """
    Run file integrity check with progress callback.
    Runs in a background thread to prevent UI freezing.
    
    Args:
        folder_path: Path to the folder to scan
        baseline_path: Path to baseline JSON file
    
    Returns:
        Tuple of (comparison results, status message)
    """
    try:
        folder = Path(folder_path)
        baseline = Path(baseline_path)
        
        if not folder.exists():
            return {
                "modified": [],
                "new": [],
                "deleted": []
            }, f"Error: Folder does not exist: {folder_path}"
        
        if not baseline.exists():
            return {
                "modified": [],
                "new": [],
                "deleted": []
            }, "Error: Baseline file not found. Create baseline first."
        
        current_hashes = hash_folder(folder)
        baseline_hashes = load_baseline()
        comparison = compare_files(current_hashes, baseline_hashes)
        
        return comparison, "Scan complete"
    
    except Exception as e:
        return {
            "modified": [],
            "new": [],
            "deleted": []
        }, f"Error: {str(e)}"


def get_baseline_path() -> str:
    """Get the path to the baseline JSON file."""
    return BASELINE_FILE
