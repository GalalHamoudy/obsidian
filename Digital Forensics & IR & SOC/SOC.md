## Endpoint Detection and Response:
### EDR functions are:
- Monitors and collects data from targeted endpoints.
- Perform an analysis of the data to identify threats.
- Contain the incidents that happened and respond to threats and generate alerts.
### Components of an EDR:

#### Data collections agents:
Software components collect data from the endpoint like network activity information, filesystem information, processes running, etc.

#### Automated response rules:
Pre-configured rules that identify whether a certain activity is a threat or not and automatically take an action against it.

#### Forensics tools:
Tools that are used by security professionals to investigate incidents or even to perform a threat-hunting process.


One of the main differences between “.evtx” and “.evt” files is the memory efficiency as in old “.evt” logs, it requires about 300MB (maximum recommended event log size) to be mapped in memory, while in “.evtx” logs, it consists of a header and 64KB chunk and just mapping current 64KB chunk to memory.