#!/usr/local/bin/bash
/usr/local/bin/curl -H "Content-Type: application/json"  -XPUT "192.168.2.176:9200/pcap2json_test7?pretty" --data-binary "@mapping.json" | jq 

