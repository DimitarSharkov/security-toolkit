"""
modules/loganalyzer.py - Log file analysis for failed login attempts.
This module parses log files to detect suspicious login activity
by counting failed attempts per IP address.
"""

import re
from pathlib import Path
from typing import Dict, Tuple


def parse_log_file(log_path: Path) -> Dict[str, int]:
    """
    Parse a log file and count failed login attempts per IP.
    
    Args:
        log_path: Path to the log file
    
    Returns:
        Dictionary mapping IP addresses to failed attempt counts
    
    Raises:
        FileNotFoundError: If log file doesn't exist
        ValueError: If log file is empty or invalid
    """
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")
    
    failed_attempts: Dict[str, int] = {}
    
    # Common log patterns for failed login attempts
    # Matches patterns like "Failed password", "login failed", "authentication failure"
    failed_login_patterns = [
        r'Failed password',
        r'authentication failure',
        r'login failed',
        r'invalid user',
        r'bad password',
        r'access denied',
    ]
    
    # Pattern to extract IP address (IPv4)
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Check if line contains failed login indicators
                for pattern in failed_login_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Extract IP address from the line
                        ip_match = re.search(ip_pattern, line)
                        if ip_match:
                            ip = ip_match.group(1)
                            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                        else:
                            # If no IP found, use placeholder
                            failed_attempts['<unknown_ip>'] = failed_attempts.get('<unknown_ip>', 0) + 1
                        break  # Count each line once, even with multiple patterns
        
    except PermissionError:
        raise PermissionError(f"Cannot read log file: {log_path}")
    except Exception as e:
        raise ValueError(f"Error parsing log file: {str(e)}")
    
    return failed_attempts


def analyze_logs(log_path: Path) -> Tuple[Dict[str, int], str, str]:
    """
    Analyze log file and return parsed data with status.
    Runs in background thread to prevent UI freezing.
    
    Args:
        log_path: Path to the log file
    
    Returns:
        Tuple of (ip_attempts_dict, status_message, error_message)
    """
    try:
        ip_attempts = parse_log_file(log_path)
        total_attempts = sum(ip_attempts.values())
        
        # Calculate suspicious IPs (5+ attempts)
        suspicious_ips = {ip: count for ip, count in ip_attempts.items() if count >= 5}
        total_suspicious = len(suspicious_ips)
        
        return ip_attempts, f"Scanned {total_attempts} failed attempts", None
    
    except FileNotFoundError as e:
        return {}, "", str(e)
    except PermissionError as e:
        return {}, "", str(e)
    except Exception as e:
        return {}, "", f"Error: {str(e)}"


def get_suspicious_ips(ip_attempts: Dict[str, int], threshold: int = 5) -> Dict[str, int]:
    """
    Get list of suspicious IPs with failed attempts above threshold.
    
    Args:
        ip_attempts: Dictionary of IP to attempt count
        threshold: Minimum attempts to be considered suspicious (default 5)
    
    Returns:
        Dictionary of suspicious IPs and their attempt counts
    """
    return {ip: count for ip, count in ip_attempts.items() if count >= threshold}


def get_top_ips(ip_attempts: Dict[str, int], limit: int = 10) -> list:
    """
    Get top N IPs with most failed login attempts.
    
    Args:
        ip_attempts: Dictionary of IP to attempt count
        limit: Number of top IPs to return (default 10)
    
    Returns:
        List of tuples (ip, count) sorted by count descending
    """
    sorted_ips = sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)
    return sorted_ips[:limit]
