"""
Client Application Entry Point.

This script serves as the main entry point for running the client application.
It imports the necessary `make_request` function from the `protocol` module
and executes it when the script is run directly.
"""
from protocol import make_request

if __name__ == "__main__":
    """
    Main execution block for the client.
    
    Calls the make_request() function from the protocol module, which handles
    user interaction, communication with the server, and processing of responses.
    The return value of make_request() (True for nominal completion, False for
    critical setup errors) is not explicitly checked here for exit code, but
    could be in a more complex application.
    """
    print("Client application started.")
    make_request()
    print("Client application finished.")