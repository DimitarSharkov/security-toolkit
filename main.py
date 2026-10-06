"""
main.py - Entry point for the Security Toolkit application.
This file initializes the Tkinter root window and loads the GUI module.
"""

import sys
from gui import SecurityToolkitApp

def main():
    """Initialize and run the Security Toolkit application."""
    try:
        # Create the main application instance
        app = SecurityToolkitApp()
        
        # Center the window on the screen
        app.geometry("800x600")
        app.title("Security Toolkit")
        
        # Run the application mainloop
        app.mainloop()
        
    except Exception as e:
        # Catch errors during startup to prevent crash
        print(f"Error initializing application: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
