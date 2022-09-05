#!/bin/bash

#
# interactively load a mail.log file and create a capture.sqlite
# database in the current directory

log="./mail.log"
pos="./pos.json"
sqlite="./capture.sqlite"
config="./config.json"
loglevel="debug"  #debug | info

if [ -e "./debug.log" ]; then
    log="./debug.log"
fi

case "$1" in
    *.log )
        log="$1"
        shift
        ;;
esac

if [ "$1" != "-c" ]; then
    # Start over. Don't continue where we left off
    echo "STARTING OVER"
    rm -f "$pos"
    rm -f "$sqlite"
else
    shift
fi

echo "USING LOG: $log"
echo "DB: $sqlite"
echo "LOGLEVEL: $loglevel"
python3 ../capture.py -d -loglevel $loglevel $@ -logfile "$log" -posfile "$pos" -sqlitefile "$sqlite" -config "$config"
