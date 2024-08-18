#!/bin/bash

# Check if the correct number of arguments is provided
if [ $# -ne 4 ]; then
  echo "Usage: $0 <local_ip> <remote_ip> <remote_port> <number_of_clients>"
  exit 1
fi

# Assign input arguments to variables
local_ip=$1
remote_ip=$2
remote_port=$3
num_clients=$4

# Starting port number for local clients
start_port=8080

# Command to run clients
command="sudo ./tcp_raw"

# Array to store process IDs
pids=()

# Function to kill all background processes on Ctrl-C
cleanup() {
  echo "Killing all clients..."
  for pid in "${pids[@]}"; do
    kill -9 "$pid" 2>/dev/null
  done
  exit 1
}

# Trap Ctrl-C (SIGINT) and call the cleanup function
trap cleanup SIGINT

# Loop through the number of clients and start them on different ports
for ((i=0; i<num_clients; i++)); do
  port=$((start_port + i))
  echo "Starting client on port $port..."

  # Run the command and store the process ID
  $command $local_ip $port $remote_ip $remote_port &
  pids+=($!)
done

# Wait for all background processes to finish
for pid in "${pids[@]}"; do
  wait "$pid"
done

echo "All clients have finished."
