import os
import logging
from typing import Dict

def parse_ipp_file(ipp_path: str) -> Dict[str, str]:
    """
    Parse OpenVPN "ifconfig-pool-persist" (IPP) file.
    Format is typically: CommonName,IPAddress
    
    Args:
        ipp_path: Path to the ipp.txt file.
        
    Returns:
        Dict[str, str]: Dictionary mapping IP addresses to usernames.
                        Example: {'10.8.0.2': 'alice', '10.8.0.6': 'bob'}
    """
    ip_map = {}
    
    try:
        if not os.path.exists(ipp_path):
            logging.warning(f"IPP file not found: {ipp_path}")
            return ip_map
            
        logging.info(f"Reading IPP file: {ipp_path}")
        
        with open(ipp_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                parts = line.split(',')
                if len(parts) >= 2:
                    username = parts[0].strip()
                    ip = parts[1].strip()
                    ip_map[ip] = username
                    
        logging.info(f"Loaded {len(ip_map)} static IP assignments from IPP file")
        
    except Exception as e:
        logging.error(f"Error reading IPP file {ipp_path}: {e}")
        
    return ip_map
