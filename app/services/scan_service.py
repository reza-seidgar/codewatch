"""Scan service for code scanning operations"""
from app.core.security import generate_scan_id


class ScanService:
    """Service for scan-related operations"""

    @staticmethod
    def create_scan_id() -> str:
        """
        Generate a new scan ID.
        
        Returns:
            str: Unique scan ID
        """
        return generate_scan_id()

    @staticmethod
    def validate_scan_mode(scan_mode: str) -> bool:
        """
        Validate if scan mode is one of the allowed values.
        
        Args:
            scan_mode: Scan mode (quick, standard, deep)
            
        Returns:
            bool: True if valid, False otherwise
        """
        valid_modes = {"quick", "standard", "deep"}
        return scan_mode in valid_modes
