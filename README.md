Usage:
1. Execute 'create_energy' binary with the number of decomposition levels (e.g., ./create_energy 17 > energy.c);
2. Customize 'wavelets.p4cfg' in "ingress::tbl_flows":"rules" defining IP/TCP headers for flows;
3. Compile and load into Netronome NIC wavelets.p4 and wavelets.c files
4. Retrieve sum array getting 'sum' register from Netronome CLI.
