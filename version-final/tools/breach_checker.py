#!/usr/bin/env python3
"""
Breach Checker Module
Checks if an email address has been found in data breaches
"""

import csv
import os
from typing import Tuple, Optional

class BreachChecker:
    def __init__(self, csv_path: Optional[str] = None):
        """
        Initialize the BreachChecker with a CSV file path.
        
        Args:
            csv_path: Path to the CSV file containing breach data.
                     If None, defaults to breach_dataset (2).csv in the same directory.
        """
        if csv_path is None:
            # Default to breach_dataset (2).csv in the tools directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            csv_path = os.path.join(script_dir, 'breach_dataset (2).csv')
        
        self.csv_path = csv_path
        self.total_emails_in_db = 0
        self.breached_emails_count = 0
        
        # Load statistics from CSV
        self._load_statistics()
    
    def _load_statistics(self):
        """Load statistics about the breach database"""
        try:
            if not os.path.exists(self.csv_path):
                return
            
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.total_emails_in_db += 1
                    if row.get('breached', '0') == '1':
                        self.breached_emails_count += 1
        except Exception as e:
            print(f"Error loading statistics: {e}")
    
    def check_email(self, email: str) -> Tuple[bool, dict]:
        """
        Check if an email address exists in the breach database.
        
        Args:
            email: Email address to check (case-insensitive)
        
        Returns:
            Tuple of (found, details_dict)
            - found: True if email was found in the database
            - details_dict: Contains 'breached' (bool), 'email' (str), and 'message' (str)
        """
        email = email.strip().lower()
        
        if not email:
            return False, {
                'breached': False,
                'email': email,
                'message': 'No email provided'
            }
        
        try:
            if not os.path.exists(self.csv_path):
                return False, {
                    'breached': False,
                    'email': email,
                    'message': f'Breach database file not found: {self.csv_path}'
                }
            
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('email', '').strip().lower() == email:
                        is_breached = row.get('breached', '0') == '1'
                        return True, {
                            'breached': is_breached,
                            'email': row.get('email', email),
                            'message': f'Email found in database - {"BREACHED" if is_breached else "Not breached"}'
                        }
            
            # Email not found in database
            return False, {
                'breached': False,
                'email': email,
                'message': 'Email not found in breach database'
            }
            
        except Exception as e:
            return False, {
                'breached': False,
                'email': email,
                'message': f'Error checking email: {str(e)}'
            }
    
    def get_database_stats(self) -> dict:
        """
        Get statistics about the breach database.
        
        Returns:
            Dictionary with 'total_emails', 'breached_count', and 'safe_count'
        """
        return {
            'total_emails': self.total_emails_in_db,
            'breached_count': self.breached_emails_count,
            'safe_count': self.total_emails_in_db - self.breached_emails_count
        }

