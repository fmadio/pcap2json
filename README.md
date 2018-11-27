# pcap2json
High Speed PCAP2JSON conversion utility  for importing PCAP network data into Elastic Search / ELK


![Alt text](http://fmad.io/analytics/logo_pcap2json.png "fmadio flow analyzer logo")

![Alt text](https://fmad.io/images/blog/20181126_netflow_snapshot2.png" "fmadio snapshot flow")

![Alt text](https://fmad.io/images/blog/images/blog/20181126_fmadio_netflow_snapshot2.png" "fmadio pcaket capture PCAP flow generator")

Full description is here
[https://fmad.io/blog-network-flow-monitoring.html](https://fmad.io/blog-network-flow-monitoring.html)


```
fmadio@fmadio20v2-149:/mnt/store0/git/pcap2json$ ./pcap2json  --help
fmad engineering all rights reserved
http://www.fmad.io

pcap2json is a high speed PCAP meta data extraction utility

example converting a pcap to json:

cat /tmp/test.pcap | pcap2json > test.json

Command Line Arguments:
 --capture-name <name>      : capture name to use for ES Index data
 --verbose                  : verbose output
 --config <confrig file>    : read from config file
 --json-packet              : write JSON packet data
 --json-flow                : write JSON flow data

Output Mode
 --output-stdout                : writes output to STDOUT
 --output-espush                : writes output directly to ES HTTP POST
 --output-lineflush <line cnt>  : number of lines before flushing output (default 100e3)
 --output-timeflush  <time ns>  : maximum amount of time since last flush (default 1e9(
 --output-cpu <gen1|gen2>       : cpu mapping list to run on

Flow specific options 
 --flow-samplerate <nanos>  : scientific notation flow sample rate. default 100e6 (100msec)

JSON Output Control 
 --disable-mac              : disable JSON MAC output
 --disable-vlan             : disable JSON VLAN output
 --disable-mpls             : disable JSON MPLS output
 --disable-ipv4             : disable JSON IPv4 output
 --disable-udp              : disable JSON UDP output
 --disable-tcp              : disable JSON TCP output

Elastic Stack options 
 --es-host <hostname:port> : Sets the ES Hostname
 --es-compress             : enables gzip compressed POST
fmadio@fmadio20v2-149:/mnt/store0/git/pcap2json_20181103_rc1$
```

# Generate ElasticSearch mapping

```
/usr/local/bin/curl -H "Content-Type: application/json"  -XPUT "192.168.2.115:9200/interop17?pretty" --data-binary "@mappings.json"
```
# Upload packet data directly into Elastic stack

```
$ cat /mnt/store1/tmp/interop17_hotstage_20170609_133953.717.953.280.pcap | ./pcap2json  --json-packet --capture-name interop17 --output-espush --es-compress --es-host 192.168.2.115 
```

This uses a high performance multithreaded direct C socket to to push the JSON data directly into ES. Multiple ES hosts can be specified to load balance the ingress queue. 

# Output JSON text data to STDOUT 

```
$ cat /mnt/store1/tmp/interop17_hotstage_20170609_133953.717.953.280.pcap | ./pcap2json  --json-packet --capture-name interop17 --output-stdout
```

Outputs the JSON data on stdout, which is usually piped to a file. This is helpful if debugging is required

# Output options 

Please see the config.\* files for other examples. This these are specified using the --config <file name> option 


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

# Performance numbers 

100GB Interop PCAP (5 min wall time)

(config.packet)       : 22min  : ~ 50,000 ES inserts / seccond<br>
Full packe Meta data, compressed JSON 1 ES instance

(config.flow.100msec) : 10min : ~  6,000 ES inserts / seccond<br>
100 msec sampled flow data, compressed JSON, 1 ES Instance

(config.flow.1sec)    : 8.5min : ~  4,238 ES inserts / seccond<br>
1sec sampled flow data, compressed JSON, 1 ES Instance



