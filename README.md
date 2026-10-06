# Security Toolkit

A Windows 11 desktop app written in Python and Tkinter that combines three small defensive security tools in one window. It was built step by step with a local AI model (Qwen3.5 9B in LM Studio) and debugged by hand.

## Features

- **Passwords**: scores password strength as you type and generates secure random passwords using Python's `secrets` module.
- **File Integrity**: saves SHA-256 hashes of every file in a folder as a baseline, then reports modified, new and deleted files.
- **Log Analyzer**: reads an SSH-style auth log, counts failed logins per IP address, and flags IPs with 5 or more failures as suspicious.

## Requirements

- Windows 11
- Python 3.11 or newer (Tkinter is included with Python)
- No extra packages

## Run

In the project folder:

    py main.py

## Project structure

    main.py              entry point
    gui.py               interface for all three tabs
    modules/
        passwords.py     password scoring and generation
        integrity.py     file hashing and comparison
        loganalyzer.py   log parsing

## Notes

This project is for learning and for use on your own computer and files only. The example IP addresses used for testing belong to ranges reserved for documentation.
