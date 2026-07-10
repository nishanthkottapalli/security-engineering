# Limitations

- The correlation relies on consistently parsed `user` and `srcip` fields.
- NAT and bastions can aggregate unrelated users behind one source address.
- The fixed 120-second window is a lab default and requires production baselining.
- The safe fixture replay does not model packet loss, ingestion delay or cluster failover.
- The lab does not automatically block an address; response remains analyst-controlled.
