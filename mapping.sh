#!/usr/local/bin/bash
/usr/local/bin/curl -H "Content-Type: application/json"  -XPUT "192.168.2.115:9200/pcap2json_test?pretty" --data-binary "@mappings.json"

