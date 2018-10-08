# pcap2json
High Speed PCAP to JSON conversion utility

fmad engineering all rights reserved
http://www.fmad.io

pcap2json is a high speed PCAP meta data extraction utility

example converting a pcap to json:

cat /tmp/test.pcap | pcap2json > test.json

Command Line Arguments:
 --mac               : include MAC information into the JSON output

# Example output

{"Device":"fmadio20v2-149","EpochTS":1479537432875808699,"CaptureSize":   139,"WireSize":   139,"MAC.Src":"00:24:dc:77:87:16","MAC.Dst":"00:17:cb:da:a1:4a","MAC.Proto":034887,"MPLSLabel":  67,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":3,"MPLS.TTL":62,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.78.84","IP.Dst":"137.6.79.68","TCP.PortSrc":8195,"TCP.PortDst":8196,"TCP.SeqNo":195728138,"TCP.AckNo":498718303,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":32}
{"Device":"fmadio20v2-149","EpochTS":1479537432875809385,"CaptureSize":  1382,"WireSize":  1382,"MAC.Src":"4c:96:14:f5:88:52","MAC.Dst":"00:19:e2:97:b8:00","MAC.Proto":034887,"MPLSLabel":  19,"MPLS.BOS":1,"MPLS.TC":5,"MPLS.L2":3,"MPLS.TTL":127,"MPLSDepth":1,"IP.Proto":  17,"IP.Src":"10.162.5.37","IP.Dst":"10.161.16.85","UDP.PortSrc":12500,"UDP.PortDst":12500}
{"Device":"fmadio20v2-149","EpochTS":1479537432875811806,"CaptureSize":   139,"WireSize":   139,"MAC.Src":"00:24:dc:77:87:16","MAC.Dst":"00:17:cb:da:a1:4a","MAC.Proto":034887,"MPLSLabel":  68,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":4,"MPLS.TTL":63,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.72.94","IP.Dst":"137.6.30.1","TCP.PortSrc":8195,"TCP.PortDst":56476,"TCP.SeqNo":4133052515,"TCP.AckNo":1427982222,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":32}
{"Device":"fmadio20v2-149","EpochTS":1479537432875815218,"CaptureSize":    98,"WireSize":    98,"MAC.Src":"00:24:dc:77:85:cc","MAC.Dst":"00:1d:b5:a0:49:4a","MAC.Proto":034887,"MPLSLabel":  68,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":4,"MPLS.TTL":63,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.72.77","IP.Dst":"137.6.132.105","TCP.PortSrc":8195,"TCP.PortDst":8196,"TCP.SeqNo":1106709979,"TCP.AckNo":3093715744,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":65}
{"Device":"fmadio20v2-149","EpochTS":1479537432875815449,"CaptureSize":   141,"WireSize":   141,"MAC.Src":"00:19:e2:97:b8:00","MAC.Dst":"4c:96:14:f5:88:52","MAC.Proto":034887,"MPLSLabel":  37,"MPLS.BOS":1,"MPLS.TC":0,"MPLS.L2":5,"MPLS.TTL":62,"MPLSDepth":1,"IP.Proto":   6,"IP.Src":"10.238.95.17","IP.Dst":"10.249.179.156","TCP.PortSrc":8292,"TCP.PortDst":49210,"TCP.SeqNo":3046011933,"TCP.AckNo":2174793295,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":32038}
{"Device":"fmadio20v2-149","EpochTS":1479537432875818310,"CaptureSize":   642,"WireSize":   642,"MAC.Src":"4c:96:14:f5:88:52","MAC.Dst":"00:19:e2:97:b8:00","MAC.Proto":034887,"MPLSLabel":  16,"MPLS.BOS":1,"MPLS.TC":4,"MPLS.L2":0,"MPLS.TTL":61,"MPLSDepth":1,"IP.Proto":  17,"IP.Src":"10.150.148.201","IP.Dst":"10.142.153.207","UDP.PortSrc":50834,"UDP.PortDst":50460}
{"Device":"fmadio20v2-149","EpochTS":1479537432875818392,"CaptureSize":   142,"WireSize":   142,"MAC.Src":"00:24:dc:77:85:cc","MAC.Dst":"00:1d:b5:a0:49:4a","MAC.Proto":034887,"MPLSLabel":  68,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":4,"MPLS.TTL":63,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"199.105.182.200","IP.Dst":"21.16.50.69","TCP.PortSrc":8195,"TCP.PortDst":45514,"TCP.SeqNo":3770508441,"TCP.AckNo":4101872579,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":65}
{"Device":"fmadio20v2-149","EpochTS":1479537432875822676,"CaptureSize":   139,"WireSize":   139,"MAC.Src":"00:24:dc:77:87:16","MAC.Dst":"00:17:cb:da:a1:4a","MAC.Proto":034887,"MPLSLabel":  68,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":4,"MPLS.TTL":63,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.72.110","IP.Dst":"137.14.92.152","TCP.PortSrc":8195,"TCP.PortDst":8197,"TCP.SeqNo":98641280,"TCP.AckNo":232925278,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":32}
{"Device":"fmadio20v2-149","EpochTS":1479537432875822796,"CaptureSize":   106,"WireSize":   106,"MAC.Src":"00:24:dc:77:85:cc","MAC.Dst":"00:1d:b5:a0:49:4a","MAC.Proto":034887,"MPLSLabel":  68,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":4,"MPLS.TTL":63,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.72.77","IP.Dst":"21.16.11.243","TCP.PortSrc":8195,"TCP.PortDst":33231,"TCP.SeqNo":978301924,"TCP.AckNo":1976086552,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":601}
{"Device":"fmadio20v2-149","EpochTS":1479537433394891977,"CaptureSize":   106,"WireSize":   106,"MAC.Src":"00:24:dc:77:85:cc","MAC.Dst":"00:1d:b5:a0:49:4a","MAC.Proto":034887,"MPLSLabel":  68,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":4,"MPLS.TTL":63,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.72.77","IP.Dst":"21.16.11.243","TCP.PortSrc":8195,"TCP.PortDst":33231,"TCP.SeqNo":978301924,"TCP.AckNo":1976086552,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":601}
{"Device":"fmadio20v2-149","EpochTS":1479537432875807000,"CaptureSize":   139,"WireSize":   139,"MAC.Src":"00:24:dc:77:87:16","MAC.Dst":"00:17:cb:da:a1:4a","MAC.Proto":034887,"MPLSLabel":  67,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":3,"MPLS.TTL":63,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.72.94","IP.Dst":"137.6.51.48","TCP.PortSrc":8195,"TCP.PortDst":8197,"TCP.SeqNo":2864033917,"TCP.AckNo":3077974715,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":64}
{"Device":"fmadio20v2-149","EpochTS":1479537432875808699,"CaptureSize":   139,"WireSize":   139,"MAC.Src":"00:24:dc:77:87:16","MAC.Dst":"00:17:cb:da:a1:4a","MAC.Proto":034887,"MPLSLabel":  67,"MPLS.BOS":1,"MPLS.TC":2,"MPLS.L2":3,"MPLS.TTL":62,"MPLSDepth":0,"IP.Proto":   6,"IP.Src":"69.184.78.84","IP.Dst":"137.6.79.68","TCP.PortSrc":8195,"TCP.PortDst":8196,"TCP.SeqNo":195728138,"TCP.AckNo":498718303,"TCP.FIN":0,"TCP.SYN":0,"TCP.RST":0,"TCP.PSH":0,"TCP.ACK":1,"TCP.Window":32}

