# pcap2json
High Speed PCAP to JSON conversion utility

```

fmad engineering all rights reserved
http://www.fmad.io

pcap2json is a high speed PCAP meta data extraction utility

example converting a pcap to json:

cat /tmp/test.pcap | pcap2json > test.json

Command Line Arguments:
 --mac               : include MAC information into the JSON output

```

# Example output

```json
{"Device":"fmadio20v2-149","EpochTS":1407517230654141000,"CaptureSize":   167,"WireSize":   167,"MAC.Src":"00:16:3e:ef:36:38","MAC.Dst":"00:10:18:72:00:3c","MAC.Proto":002048,"IP.Proto":  17,"IP.Src":"10.5.9.1","IP.Dst":"10.5.9.2","UDP.PortSrc":53,"UDP.PortDst":54655}
{"Device":"fmadio20v2-149","EpochTS":1407517230654147000,"CaptureSize":   135,"WireSize":   135,"MAC.Src":"00:16:3e:ef:36:38","MAC.Dst":"00:10:18:72:00:3c","MAC.Proto":002048,"IP.Proto":  17,"IP.Src":"10.5.9.1","IP.Dst":"10.5.9.2","UDP.PortSrc":53,"UDP.PortDst":54655}
{"Device":"fmadio20v2-149","EpochTS":1407517230655239000,"CaptureSize":   150,"WireSize":   150,"MAC.Src":"e0:3f:49:6a:af:a1","MAC.Dst":"00:10:18:72:00:3c","MAC.Proto":002048,"IP.Proto":   6,"IP.Src":"54.183.128.64","IP.Dst":"10.5.9.102","TCP.PortSrc":22222,"TCP.PortDst":51697,"TCP.SeqNo":2728668290,"TCP.AckNo":4050065242,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":0,"TCP.Window":1452}
{"Device":"fmadio20v2-149","EpochTS":1407517230657285000,"CaptureSize":   150,"WireSize":   150,"MAC.Src":"00:10:18:72:00:3c","MAC.Dst":"e0:3f:49:6a:af:a1","MAC.Proto":002048,"IP.Proto":   6,"IP.Src":"10.5.9.102","IP.Dst":"54.183.128.64","TCP.PortSrc":51697,"TCP.PortDst":22222,"TCP.SeqNo":4050065242,"TCP.AckNo":2728668374,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":0,"TCP.Window":1444}
{"Device":"fmadio20v2-149","EpochTS":1407517230679346000,"CaptureSize":    66,"WireSize":    66,"MAC.Src":"e0:3f:49:6a:af:a1","MAC.Dst":"00:10:18:72:00:3c","MAC.Proto":002048,"IP.Proto":   6,"IP.Src":"54.183.128.64","IP.Dst":"10.5.9.102","TCP.PortSrc":22222,"TCP.PortDst":51697,"TCP.SeqNo":2728668374,"TCP.AckNo":4050065326,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":0,"TCP.Window":1452}
{"Device":"fmadio20v2-149","EpochTS":1407517230683090000,"CaptureSize":    84,"WireSize":    84,"MAC.Src":"00:10:18:72:00:3c","MAC.Dst":"00:16:3e:ef:36:38","MAC.Proto":002048,"IP.Proto":  17,"IP.Src":"10.5.9.2","IP.Dst":"10.5.9.1","UDP.PortSrc":33168,"UDP.PortDst":53}
{"Device":"fmadio20v2-149","EpochTS":1407517230683095000,"CaptureSize":    84,"WireSize":    84,"MAC.Src":"00:10:18:72:00:3c","MAC.Dst":"00:16:3e:ef:36:38","MAC.Proto":002048,"IP.Proto":  17,"IP.Src":"10.5.9.2","IP.Dst":"10.5.9.1","UDP.PortSrc":33168,"UDP.PortDst":53}
{"Device":"fmadio20v2-149","EpochTS":1407517230683390000,"CaptureSize":   167,"WireSize":   167,"MAC.Src":"00:16:3e:ef:36:38","MAC.Dst":"00:10:18:72:00:3c","MAC.Proto":002048,"IP.Proto":  17,"IP.Src":"10.5.9.1","IP.Dst":"10.5.9.2","UDP.PortSrc":53,"UDP.PortDst":33168}
{"Device":"fmadio20v2-149","EpochTS":1407517230683392000,"CaptureSize":   135,"WireSize":   135,"MAC.Src":"00:16:3e:ef:36:38","MAC.Dst":"00:10:18:72:00:3c","MAC.Proto":002048,"IP.Proto":  17,"IP.Src":"10.5.9.1","IP.Dst":"10.5.9.2","UDP.PortSrc":53,"UDP.PortDst":33168}
```

