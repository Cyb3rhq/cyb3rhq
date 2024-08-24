<!---
Copyright (C) 2015, Cyb3rhq Inc.
Created by Cyb3rhq, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Cyb3rhq module: Syscollector architecture
## Index
- [Cyb3rhq module: Syscollector architecture](#cyb3rhq-module-syscollector-architecture)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Sequence diagrams](#sequence-diagrams)


## Purpose
Everyone knows the importance of having detailed system information from our environment to take decisions based on specific use cases. Having detailed and valuable information about our environment helps us to react under unpredictable scenarios. The cyb3rhq agents are able to collect interesting and valuable system information regarding processes, hardware, packages, OS, network and ports.

The System Inventory feature interacts with different modules to split responsabilities and optimize internal dependencias:
- Data Provider: Module in charge of gathering system information based on OSes. This involves information about current running processes, packages/programs installed, ports being used, network adapters and OS general information.
- DBSync: This module has one single main responsibility: Database management. It manages all database related operations like insertion, update, selection and deletion. This allows Cyb3rhq to centralize and unify database management to make it more robust and to avoid possible data misleading.
- RSync: is in charge of database synchronization between Cyb3rhq agents DBs and Cyb3rhq  manager DBs (each agent DB). RSync implements a unified and generic communication algorithm used to maintain Cyb3rhq agents and Cyb3rhq manager datasets consistency.
- Syscollector: Module in charge of getting system information from Data Provider module and updating the local agent database (through dbsync module). Once this is done, the rsync module calculates the information to synchronize with the Cyb3rhq manager.


## Sequence diagrams
The different sequence diagrams ilustrate the flow of the different modules interacting on the syscollector general use.the configuration.
- 001-sequence-wm-syscollector: It explains the cyb3rhq module syscollector initialization, construction, use, destruction and stop from the cyb3rhq modules daemon perspective.
- 002-sequence-syscollector: It explains the syscollector internal interactions with modules like dbsync, rsync and normalizer. This diagram shows how is the flow for data synchronization, checksum calculation, scan starting, etc.
- 003-sequence-manager-side: It explains the modules interaction (analysisd, wdb) when a syscollector message arrives from the manager perspective. This diagram shows how is the flow from the modules initialization to the database storage.

