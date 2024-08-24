<!---
Copyright (C) 2015, Cyb3rhq Inc.
Created by Cyb3rhq, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Centralized Configuration
## Index
- [Centralized Configuration](#centralized-configuration)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Sequence diagram](#sequence-diagram)

## Purpose

One of the key features of Cyb3rhq as a EDR is the Centralized Configuration, allowing to deploy configurations, policies, rootcheck descriptions or any other file from Cyb3rhq Manager to any Cyb3rhq Agent based on their grouping configuration. This feature has multiples actors: Cyb3rhq Cluster (Master and Worker nodes), with `cyb3rhq-remoted` as the main responsible from the managment side, and Cyb3rhq Agent with `cyb3rhq-agentd` as resposible from the client side.


## Sequence diagram
Sequence diagram shows the basic flow of Centralized Configuration based on the configuration provided. There are mainly three stages:
1. Cyb3rhq Manager Master Node (`cyb3rhq-remoted`) creates every `remoted.shared_reload` (internal) seconds the files that need to be synchronized with the agents.
2. Cyb3rhq Cluster as a whole (via `cyb3rhq-clusterd`) continuously synchronize files between Cyb3rhq Manager Master Node and Cyb3rhq Manager Worker Nodes
3. Cyb3rhq Agent `cyb3rhq-agentd` (via ) sends every `notify_time` (ossec.conf) their status, being `merged.mg` hash part of it. Cyb3rhq Manager Worker Node (`cyb3rhq-remoted`) will check if agent's `merged.mg` is out-of-date, and in case this is true, the new `merged.mg` will be pushed to Cyb3rhq Agent.