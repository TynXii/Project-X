#!/bin/bash

# The name of the file to manage
FILE="encrypted_file.txt"

# Check if an argument was provided
if [ $# -eq 0 ]; then
    echo "No argument provided. Please use 'run' to run the program or 'delete' to remove the file."
    exit 1
fi

# Argument to run or delete the file
ACTION=$1

# Function to run the program (replace this with the actual command to run your program)
run_program() {
    echo "Running the program..."
    python client.py
}

# Function to delete the file
delete_file() {
    echo "Deleting file $FILE..."
    rm -f "$FILE"
}

# Perform the action based on the argument
case "$ACTION" in
    "run")
        run_program
        ;;
    "delete")
        delete_file
        ;;
    *)
        echo "Invalid argument. Use 'run' to execute the program or 'delete' to delete the file."
        exit 1
        ;;
esac
