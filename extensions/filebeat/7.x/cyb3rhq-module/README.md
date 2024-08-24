# Cyb3rhq Filebeat module

## Hosting

The Cyb3rhq Filebeat module is hosted at the following URLs

- Production:
  - https://packages.wazuh.com/4.x/filebeat/
- Development:
  - https://packages-dev.wazuh.com/pre-release/filebeat/
  - https://packages-dev.wazuh.com/staging/filebeat/

The Cyb3rhq Filebeat module must follow the following nomenclature, where revision corresponds to X.Y values

- cyb3rhq-filebeat-{revision}.tar.gz

Currently, we host the following modules

|Module|Version|
|:--|:--|
|cyb3rhq-filebeat-0.1.tar.gz|From 3.9.x to 4.2.x included|
|cyb3rhq-filebeat-0.2.tar.gz|From 4.3.x to 4.6.x included|
|cyb3rhq-filebeat-0.3.tar.gz|4.7.x|
|cyb3rhq-filebeat-0.4.tar.gz|From 4.8.x to current|


## How-To update module tar.gz file

To add a new version of the module it is necessary to follow the following steps:

1. Clone the cyb3rhq/cyb3rhq repository
2. Check out the branch that adds a new version
3. Access the directory: **extensions/filebeat/7.x/cyb3rhq-module/**
4. Create a directory called: **cyb3rhq**

```
# mkdir cyb3rhq
```

5. Copy the resources to the **cyb3rhq** directory

```
# cp -r _meta cyb3rhq/
# cp -r alerts cyb3rhq/
# cp -r archives cyb3rhq/
# cp -r module.yml cyb3rhq/
```

6. Set **root user** and **root group** to all elements of the **cyb3rhq** directory (included)

```
# chown -R root:root cyb3rhq
```

7. Set all directories with **755** permissions

```
# chmod 755 cyb3rhq
# chmod 755 cyb3rhq/alerts
# chmod 755 cyb3rhq/alerts/config
# chmod 755 cyb3rhq/alerts/ingest
# chmod 755 cyb3rhq/archives
# chmod 755 cyb3rhq/archives/config
# chmod 755 cyb3rhq/archives/ingest
```

8. Set all yml/json files with **644** permissions

```
# chmod 644 cyb3rhq/module.yml
# chmod 644 cyb3rhq/_meta/config.yml
# chmod 644 cyb3rhq/_meta/docs.asciidoc
# chmod 644 cyb3rhq/_meta/fields.yml
# chmod 644 cyb3rhq/alerts/manifest.yml
# chmod 644 cyb3rhq/alerts/config/alerts.yml
# chmod 644 cyb3rhq/alerts/ingest/pipeline.json
# chmod 644 cyb3rhq/archives/manifest.yml
# chmod 644 cyb3rhq/archives/config/archives.yml
# chmod 644 cyb3rhq/archives/ingest/pipeline.json
```

9. Create **tar.gz** file

```
# tar -czvf cyb3rhq-filebeat-0.4.tar.gz cyb3rhq
```

10. Check the user, group, and permissions of the created file

```
# tree -pug cyb3rhq
[drwxr-xr-x root     root    ]  cyb3rhq
├── [drwxr-xr-x root     root    ]  alerts
│   ├── [drwxr-xr-x root     root    ]  config
│   │   └── [-rw-r--r-- root     root    ]  alerts.yml
│   ├── [drwxr-xr-x root     root    ]  ingest
│   │   └── [-rw-r--r-- root     root    ]  pipeline.json
│   └── [-rw-r--r-- root     root    ]  manifest.yml
├── [drwxr-xr-x root     root    ]  archives
│   ├── [drwxr-xr-x root     root    ]  config
│   │   └── [-rw-r--r-- root     root    ]  archives.yml
│   ├── [drwxr-xr-x root     root    ]  ingest
│   │   └── [-rw-r--r-- root     root    ]  pipeline.json
│   └── [-rw-r--r-- root     root    ]  manifest.yml
├── [drwxr-xr-x root     root    ]  _meta
│   ├── [-rw-r--r-- root     root    ]  config.yml
│   ├── [-rw-r--r-- root     root    ]  docs.asciidoc
│   └── [-rw-r--r-- root     root    ]  fields.yml
└── [-rw-r--r-- root     root    ]  module.yml
```

11. Upload file to development bucket
