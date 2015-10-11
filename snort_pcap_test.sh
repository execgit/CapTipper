#!/bin/bash

if [[ -z "$1" || -z "$2" ]] ; then
        echo "Usage: $0 <rulefile.rules> <pcap file>"
        exit 1
fi

rule="$1"
pcap="$2"

cat "$1" > /usr/local/snort/to-test.rules

/usr/sbin/snort -c /etc/snort/snort.conf -r "$pcap" -A console -K ascii -N -k none -X -v -q 2>&1

echo -n > /usr/local/snort/to-test.rules
