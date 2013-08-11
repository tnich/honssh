#!/bin/sh

echo -n "Starting honssh in background..."
twistd -y honssh.tac -l logs/honssh.log --pidfile honssh.pid
