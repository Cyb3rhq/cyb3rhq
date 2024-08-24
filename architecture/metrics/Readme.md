<!---
Copyright (C) 2015, Cyb3rhq Inc.
Created by Cyb3rhq, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Metrics

## Index

- [Metrics](#metrics)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Sequence diagram](#sequence-diagram)

## Purpose

Cyb3rhq includes some metrics to understand the behavior of its components, which allow to investigate errors and detect problems with some configurations. This feature has multiple actors: `cyb3rhq-remoted` for agent interaction messages, `cyb3rhq-analysisd` for processed events.

## Sequence diagram

The sequence diagram shows the basic flow of metric counters. These are the main flows:

1. Messages received by `cyb3rhq-remoted` from agents.
2. Messages that `cyb3rhq-remoted` sends to agents.
3. Events received by `cyb3rhq-analysisd`.
4. Events processed by `cyb3rhq-analysisd`.
