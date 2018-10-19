# pcap2json
High Speed PCAP to JSON conversion utility


Used for importing PCAP meta data into Elastic Search

```
fmadio@fmadio20v2-149:/mnt/store0/git/pcap2json$ ./pcap2json  --help
fmad engineering all rights reserved
http://www.fmad.io

pcap2json is a high speed PCAP meta data extraction utility

example converting a pcap to json:

cat /tmp/test.pcap | pcap2json > test.json

Command Line Arguments:
 --capture-name <name>  : capture name to use for ES Index data
 --json-packet          : write JSON packet data
 --json-flow            : write JSON flow data

fmadio@fmadio20v2-149:/mnt/store0/git/pcap2json$
```

# Generate ElasticSearch mapping

```
/usr/local/bin/curl -H "Content-Type: application/json"  -XPUT "192.168.2.115:9200/interop17?pretty" --data-binary "@mappings.json"
```
# Upload packet data directly into Elastic stack

```
$ cat /mnt/store1/tmp/interop17_hotstage_20170609_133953.717.953.280.pcap | ./pcap2json  --json-packet --capture-name interop17 | ./bulk_upload.lua
```

The bulk_upload.lua script saves the output of pcap2json every 1000 lines, then issues a ElasticSearch Bulk curl POST request for those 1000 lines. And repeats until there is no data left.


# Example output

```json
{"index":{"_index":"interop17","_type":"flow_record","_score":null}}
{"timestamp":1497015814284.541992,"TS":"13:43:34.284.542.042","FlowCnt":0,"Device":"fmadio20v2-149","hash":"d80b04ebb1a14bdc72ed17cde664cda755b39d8d","MACSrc":"7c:e2:ca:bd:97:d9","MACDst":"00:0e:52:80:00:16","MACProto":"IPv4","IPv4.Src":"150.100.29.14","IPv4.Dst":"130.128.19.30" ,"IPv4.Proto":"UDP","UDP.Port.Src":10662,"UDP.Port.Dst":5004,"TotalPkt":0,"TotalByte":0}
{"index":{"_index":"interop17","_type":"flow_record","_score":null}}
{"timestamp":1497015814284.543213,"TS":"13:43:34.284.543.223","FlowCnt":0,"Device":"fmadio20v2-149","hash":"d80b04ebb1a14bdc72ed17cde664cda755b39d8d","MACSrc":"7c:e2:ca:bd:97:d9","MACDst":"00:0e:52:80:00:16","MACProto":"IPv4","IPv4.Src":"150.100.29.14","IPv4.Dst":"130.128.19.30" ,"IPv4.Proto":"UDP","UDP.Port.Src":10662,"UDP.Port.Dst":5004,"TotalPkt":0,"TotalByte":0}
{"index":{"_index":"interop17","_type":"flow_record","_score":null}}
{"timestamp":1497015814284.544189,"TS":"13:43:34.284.544.362","FlowCnt":0,"Device":"fmadio20v2-149","hash":"d80b04ebb1a14bdc72ed17cde664cda755b39d8d","MACSrc":"7c:e2:ca:bd:97:d9","MACDst":"00:0e:52:80:00:16","MACProto":"IPv4","IPv4.Src":"150.100.29.14","IPv4.Dst":"130.128.19.30" ,"IPv4.Proto":"UDP","UDP.Port.Src":10662,"UDP.Port.Dst":5004,"TotalPkt":0,"TotalByte":0}
{"index":{"_index":"interop17","_type":"flow_record","_score":null}}
{"timestamp":1497015814284.549072,"TS":"13:43:34.284.548.992","FlowCnt":0,"Device":"fmadio20v2-149","hash":"d80b04ebb1a14bdc72ed17cde664cda755b39d8d","MACSrc":"7c:e2:ca:bd:97:d9","MACDst":"00:0e:52:80:00:16","MACProto":"IPv4","IPv4.Src":"150.100.29.14","IPv4.Dst":"130.128.19.30" ,"IPv4.Proto":"UDP","UDP.Port.Src":10662,"UDP.Port.Dst":5004,"TotalPkt":0,"TotalByte":0}
{"index":{"_index":"interop17","_type":"flow_record","_score":null}}
{"timestamp":1497015814284.549316,"TS":"13:43:34.284.549.405","FlowCnt":0,"Device":"fmadio20v2-149","hash":"b6183e3af206ac1c43eefb261f4ec03811ff1a45","MACSrc":"7c:e2:ca:bd:97:d9","MACDst":"00:0e:52:80:00:16","MACProto":"IPv4","IPv4.Src":"45.0.191.123","IPv4.Dst":"205.177.226.213" ,"IPv4.Proto":"UDP","UDP.Port.Src":10500,"UDP.Port.Dst":20986,"TotalPkt":0,"TotalByte":0}
```

