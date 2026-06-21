#!/bin/bash

#
# Convert the favicon.png to favicon.ico with multiple sizes

if ! command -v convert &> /dev/null
then
    echo "ImageMagick 'convert' command could not be found. Please install ImageMagick to proceed."
    exit 1
fi

convert ../ssltui/images/favicon.png -define icon:auto-resize=64,48,32,16 ../ssltui/images/favicon.ico
