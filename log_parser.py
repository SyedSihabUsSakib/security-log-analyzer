import re
from datetime import datetime
import pandas as pd

def parse_auth_log(file_path):
    """
    Parse authentication log file and extract relevant information
    """
    logs = []
    
    # Regex pattern for auth logs
    pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(Authentication failure|Successful login)\s+for\s+(\w+)\s+from\s+([\d.]+)'
    
    with open(file_path, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                timestamp_str, status, username, ip_address = match.groups()
                
                logs.append({
                    'timestamp': datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S'),
                    'status': 'Failed' if 'failure' in status else 'Success',
                    'username': username,
                    'ip_address': ip_address,
                    'event_type': 'Authentication'
                })
    
    return pd.DataFrame(logs)

def parse_uploaded_file(uploaded_file):
    """
    Parse uploaded log file (handles both file path and uploaded file object)
    """
    logs = []
    content = uploaded_file.getvalue().decode('utf-8')
    
    pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(Authentication failure|Successful login)\s+for\s+(\w+)\s+from\s+([\d.]+)'
    
    for line in content.split('\n'):
        match = re.search(pattern, line)
        if match:
            timestamp_str, status, username, ip_address = match.groups()
            
            logs.append({
                'timestamp': datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S'),
                'status': 'Failed' if 'failure' in status else 'Success',
                'username': username,
                'ip_address': ip_address,
                'event_type': 'Authentication'
            })
    
    return pd.DataFrame(logs)