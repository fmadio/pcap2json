#!/usr/local/bin/bash
curl -H "Content-Type: application/json"    -XPOST "http://192.168.2.115:9200/pcap2json_test7/_search" --data-binary "@last.json" | jq

