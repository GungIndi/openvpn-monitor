#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# DNSMasq Log Parser for OpenVPN Monitor
# Parses dnsmasq query logs and groups by client IP

import logging
import re
import gzip
import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Optional
from pathlib import Path


class DNSMasqParser:
    """Parser for dnsmasq log files"""
    
    # Regex pattern to match dnsmasq query lines
    # Example: "2025-12-24T05:52:12.824895+00:00 ubuntu dnsmasq[281200]: query[A] play.google.com from 10.0.0.0"
    QUERY_PATTERN = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2}).*query\[(\w+)\]\s+(\S+)\s+from\s+([\d\.]+)'
    )
    
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.log_dir = os.path.dirname(log_file_path)
        self.log_basename = os.path.basename(log_file_path)
        
    def get_archive_files(self) -> List[str]:
        """
        Find all archived log files in the archives directory
        
        Returns:
            List of archive file paths, sorted by filename (newest first)
        """
        archive_dir = os.path.join(self.log_dir, 'archives')
        logging.info(f"Looking for archives in: {archive_dir}")
        
        if not os.path.exists(archive_dir):
            logging.warning(f"Archive directory does not exist: {archive_dir}")
            return []
        
        archives = []
        
        try:
            all_files = os.listdir(archive_dir)
            logging.info(f"Found {len(all_files)} files in archive directory")
            
            for filename in all_files:
                # Match pattern: vpn.log-* (any suffix)
                if filename.startswith(self.log_basename):
                    logging.debug(f"File matches basename '{self.log_basename}': {filename}")
                    filepath = os.path.join(archive_dir, filename)
                    archives.append(filepath)
                    logging.info(f"✓ Archive added: {filename}")
                else:
                    logging.debug(f"File doesn't match basename '{self.log_basename}': {filename}")
            
            # Sort by filename (reverse = newest first, assuming YYYY-MM-DD format)
            archives.sort(reverse=True)
            logging.info(f"Found {len(archives)} archive files to read")
            return archives
            
        except Exception as e:
            logging.error(f"Error reading archive directory: {e}")
            return []
    
    def read_lines_reverse(self, filepath: str) -> object:
        """
        Generator that yields lines from a file in reverse order.
        For plain text files, it reads from the end efficiently.
        For gzip files, it reads the whole file (due to compression nature).
        
        Args:
            filepath: Path to log file
            
        Yields:
            str: Each line from the file, starting from the last
        """
        chunk_size = 8192
        try:
            logging.debug(f"Reading log file (reverse): {filepath}")
            
            # Unzip the archives logs
            if filepath.endswith('.gz'):
                logging.debug("Reading as gzipped file")
                with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    logging.info(f"Read {len(lines)} lines from gzipped {os.path.basename(filepath)}")
                    for line in reversed(lines):
                        yield line
            else:
                # Plain text: Read from end efficiently
                logging.debug("Reading as plain text file (optimized reverse read)")
                with open(filepath, 'rb') as f:
                    f.seek(0, os.SEEK_END)
                    position = f.tell()
                    remainder = b''
                    
                    while position > 0:
                        delta = min(chunk_size, position)
                        position -= delta
                        f.seek(position, os.SEEK_SET)
                        chunk = f.read(delta) + remainder
                        
                        parts = chunk.split(b'\n')
                        
                        if position > 0:
                            remainder = parts[0]
                            parts = parts[1:]
                        else:
                            remainder = b''
                            
                        for part in reversed(parts):
                            if part:
                                try:
                                    yield part.decode('utf-8', errors='ignore')
                                except Exception:
                                    continue
                                    
        except FileNotFoundError:
            logging.error(f"Log file not found: {filepath}")
        except PermissionError:
            logging.error(f"Permission denied reading: {filepath}")
        except Exception as e:
            logging.error(f"Error reading log file {filepath}: {e}")
        
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single dnsmasq log line
        
        Args:
            line: Log line string
            
        Returns:
            Dict with query info or None if not a query line
        """
        match = self.QUERY_PATTERN.search(line)
        if not match:
            return None
            
        timestamp_str, query_type, domain, client_ip = match.groups()
        
        try:
            # Parse ISO 8601 timestamp with timezone
            # Example: 2025-12-24T05:52:12.824895+00:00
            timestamp_simple = timestamp_str.split('.')[0]  # Remove microseconds
            timestamp_utc = datetime.strptime(timestamp_simple, "%Y-%m-%dT%H:%M:%S")
            
            # Convert UTC to UTC+8
            timestamp_local = timestamp_utc + timedelta(hours=8)
            
            return {
                'timestamp': timestamp_local,
                'query_type': query_type,
                'domain': domain,
                'client_ip': client_ip
            }
        except ValueError as e:
            logging.warning(f"Failed to parse timestamp: {timestamp_str} - {e}")
            return None
    
    def parse_log(self, limit: int = 1000, hours: int = 24, include_archives: bool = True) -> List[Dict]:
        """
        Parse the dnsmasq log file and archives
        
        Args:
            limit: Maximum number of queries to return
            hours: Only include queries from the last N hours
            include_archives: Whether to read archived log files
            
        Returns:
            List of query dictionaries
        """
        queries = []
        cutoff_time = datetime.now() - timedelta(hours=hours)
        logging.info(f"DNS query cutoff time: {cutoff_time.strftime('%Y-%m-%d %H:%M:%S')} (last {hours} hours)")
        
        # Collect all log files to read
        log_files = []
        
        # Add current log file
        if os.path.exists(self.log_file_path):
            log_files.append(self.log_file_path)
            logging.info(f"Current log file exists: {self.log_file_path}")
        else:
            logging.warning(f"Current log file not found: {self.log_file_path}")
        
        # Add archive files if enabled
        if include_archives:
            logging.info(f"Archive reading enabled")
            archive_files = self.get_archive_files()
            log_files.extend(archive_files)
            logging.info(f"Total log files to read: {len(log_files)} (1 current + {len(archive_files)} archives)")
        else:
            logging.info("Archive reading disabled")
        
        # Read and parse all log files
        queries_per_file = {}
        for log_file in log_files:
            if len(queries) >= limit:
                logging.info(f"Reached query limit ({limit}), stopping")
                break
            
            file_queries_count = 0
            
            # Process lines in reverse to get most recent first
            # Now using the optimized generator that yields lines in reverse
            for line in self.read_lines_reverse(log_file):
                if len(queries) >= limit:
                    break
                    
                query = self.parse_log_line(line)
                if query:
                    if query['timestamp'] >= cutoff_time:
                        queries.append(query)
                        file_queries_count += 1
            
            queries_per_file[os.path.basename(log_file)] = file_queries_count
            if file_queries_count > 0:
                logging.info(f"  → {file_queries_count} queries from {os.path.basename(log_file)}")
        
        # Sort by timestamp (most recent first)
        queries.sort(key=lambda q: q['timestamp'], reverse=True)
        
        # Limit to requested number
        queries = queries[:limit]
        
        logging.info(f"Total parsed: {len(queries)} DNS queries from {len(log_files)} log files")
        return queries
    
    def group_by_ip(self, queries: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group DNS queries by client IP address
        
        Args:
            queries: List of query dictionaries
            
        Returns:
            Dict mapping client IP to list of queries
        """
        grouped = defaultdict(list)
        
        for query in queries:
            client_ip = query['client_ip']
            grouped[client_ip].append(query)
            
        # Sort queries within each IP by timestamp (most recent first)
        for ip in grouped:
            grouped[ip] = sorted(
                grouped[ip], 
                key=lambda q: q['timestamp'], 
                reverse=True
            )
            
        return dict(grouped)
    
    def get_query_stats(self, queries: List[Dict]) -> Dict:
        """
        Get statistics about DNS queries
        
        Args:
            queries: List of query dictionaries
            
        Returns:
            Dict with statistics
        """
        if not queries:
            return {
                'total_queries': 0,
                'unique_domains': 0,
                'unique_clients': 0,
                'query_types': {}
            }
            
        domains = set(q['domain'] for q in queries)
        clients = set(q['client_ip'] for q in queries)
        
        query_types = defaultdict(int)
        for q in queries:
            query_types[q['query_type']] += 1
            
        return {
            'total_queries': len(queries),
            'unique_domains': len(domains),
            'unique_clients': len(clients),
            'query_types': dict(query_types)
        }


# Convenience functions for easy import
def parse_dnsmasq_log(log_file_path: str, limit: int = 1000, hours: int = 24, include_archives: bool = True) -> List[Dict]:
    """
    Parse dnsmasq log file and archives, return queries
    
    Args:
        log_file_path: Path to dnsmasq log file
        limit: Maximum number of queries to return
        hours: Only include queries from last N hours
        include_archives: Whether to include archived log files
        
    Returns:
        List of query dictionaries
    """
    parser = DNSMasqParser(log_file_path)
    return parser.parse_log(limit=limit, hours=hours, include_archives=include_archives)


def group_queries_by_ip(queries: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Group queries by client IP
    
    Args:
        queries: List of query dictionaries
        
    Returns:
        Dict mapping client IP to list of queries
    """
    parser = DNSMasqParser('')  # No file needed for grouping
    return parser.group_by_ip(queries)


def get_query_stats(queries: List[Dict]) -> Dict:
    """
    Get statistics about queries
    
    Args:
        queries: List of query dictionaries
        
    Returns:
        Dict with statistics
    """
    parser = DNSMasqParser('')
    return parser.get_query_stats(queries)
