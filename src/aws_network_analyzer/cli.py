#!/usr/bin/env python3
"""
AWS Network Analyzer CLI Module

This module provides the command-line interface entry point for the
aws-network-analyzer package when installed via pip.

It wraps the full-featured main module to provide complete functionality.
"""

from aws_network_analyzer.main import main

if __name__ == "__main__":
    main()
