# pcap_flow
displays flow information from pcap and can extract individual or all tcp streams


***Options***

-o <filename>               | write filtered flows to the specified file name
                            | for bulk tcp extraction this is the prefix filename
--packet-max  <number>      | only process the first <number> packets
--extract <number>          | extract FlowID <number> into the output PCAP file
--extract-tcp <number>      | extract FlowID <number> as a TCP stream to the output file name
--extract-tcp-port <number> | extract all TCP flows with the specified port in src or dest 
--stdin                     | read pcap from stdin. e.g. zcat capture.pcap | pcap_flow --stdin

***Examples***


1) generate flow information from a compressed pcap file 

```
zcat capture.pcap.gz | pcap_flows --stdin
```

2) output a specific flow to a seperate pcap file 

pcap_flows --extract 1234 raw_capture.pcap -o capture_flow_1234.pcap

3) extract a tcp stream from a pcap

pcap_flows --extract-tcp 1234 raw_capture.pcap -o capture_flow_as_tcp1234.pcap
