# pcap2json
High Speed PCAP2JSON conversion utility  for importing PCAP network data into Elastic Search / ELK


![Alt text](http://firmware.fmad.io/images/logo_pcap2json.png "fmadio flow analyzer logo")

[https://fmad.io/](https://fmad.io)

![Alt text](https://old.fmad.io/images/blog/20181126_netflow_snapshot2.png "fmadio snapshot flow")

Example implementation 

![Alt text](https://old.fmad.io/images/blog/20181126_fmadio_netflow_snapshot2.png "fmadio pcaket capture PCAP flow generator")

Full description is here
[https://www.fmad.io/blog/network-flow-monitoring](https://www.fmad.io/blog/network-flow-monitoring)


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

Using FMADIO 20Gv2 Packet Capture system uses 12 CPUs

100K Flows @ 64B per packet ~5.1Mpps

![Alt text](http://old.fmad.io/pcap2json/20190301_pcap2json_perf64.JPG "pcap to json 64B packet rate")

100K Flows @ 1500B per packet 15.48Gbps 

![Alt text](http://old.fmad.io/pcap2json/20190301_pcap2json_perf1500.JPG "pcap to json 1500B packet rate")


1M Flows @ 64B per packet 36Mpps. Using a 96 CPU + 384GB RAM m5.metal machine (Blue is reference running on FMADIO 20G Gen2 system)

![Alt text](http://old.fmad.io/pcap2json/20190316_pcap2json_scaling_96cpu.JPG "pcap to json 1500B packet rate")

# Profile Snaphot 

Generating a profile snapshot as follows. 5 minute (300e9 nanosec) profile sample

sudo stream_cat -v --time-start 20:00:00 --time-stop 20:05:00 --ignore_fcs  mycapture_20200313_1712  | ./pcap2json  --json-flow --flow-samplerate 300e9 --output-null --output-histogram mycapture_20200313_2000.profile

