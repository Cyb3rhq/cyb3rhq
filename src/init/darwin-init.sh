#!/bin/sh

# Darwin init script.
# by Lorenzo Costanzia di Costigliole <mummie@tin.it>
# Modified by Cyb3rhq, Inc. <info@wazuh.com>.
# Copyright (C) 2015, Cyb3rhq Inc.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

INSTALLATION_PATH=${1}
SERVICE=/Library/LaunchDaemons/com.cyb3rhq.agent.plist
STARTUP=/Library/StartupItems/CYB3RHQ/StartupParameters.plist
LAUNCHER_SCRIPT=/Library/StartupItems/CYB3RHQ/Cyb3rhq-launcher
STARTUP_SCRIPT=/Library/StartupItems/CYB3RHQ/CYB3RHQ

launchctl unload /Library/LaunchDaemons/com.cyb3rhq.agent.plist 2> /dev/null
mkdir -p /Library/StartupItems/CYB3RHQ
chown root:wheel /Library/StartupItems/CYB3RHQ
rm -f $STARTUP $STARTUP_SCRIPT $SERVICE
echo > $LAUNCHER_SCRIPT
chown root:wheel $LAUNCHER_SCRIPT
chmod u=rxw-,g=rx-,o=r-- $LAUNCHER_SCRIPT

echo '<?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
     <dict>
         <key>Label</key>
         <string>com.cyb3rhq.agent</string>
         <key>ProgramArguments</key>
         <array>
             <string>'$LAUNCHER_SCRIPT'</string>
         </array>
         <key>RunAtLoad</key>
         <true/>
     </dict>
 </plist>' > $SERVICE

chown root:wheel $SERVICE
chmod u=rw-,go=r-- $SERVICE

echo '
#!/bin/sh
. /etc/rc.common

StartService ()
{
        '${INSTALLATION_PATH}'/bin/cyb3rhq-control start
}
StopService ()
{
        '${INSTALLATION_PATH}'/bin/cyb3rhq-control stop
}
RestartService ()
{
        '${INSTALLATION_PATH}'/bin/cyb3rhq-control restart
}
RunService "$1"
' > $STARTUP_SCRIPT

chown root:wheel $STARTUP_SCRIPT
chmod u=rwx,go=r-x $STARTUP_SCRIPT

echo '
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://
www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Description</key>
       <string>CYB3RHQ Security agent</string>
       <key>Messages</key>
       <dict>
               <key>start</key>
               <string>Starting Cyb3rhq agent</string>
               <key>stop</key>
               <string>Stopping Cyb3rhq agent</string>
       </dict>
       <key>Provides</key>
       <array>
               <string>CYB3RHQ</string>
       </array>
       <key>Requires</key>
       <array>
               <string>IPFilter</string>
       </array>
</dict>
</plist>
' > $STARTUP

chown root:wheel $STARTUP
chmod u=rw-,go=r-- $STARTUP

echo '#!/bin/sh

capture_sigterm() {
    '${INSTALLATION_PATH}'/bin/cyb3rhq-control stop
    exit $?
}

if ! '${INSTALLATION_PATH}'/bin/cyb3rhq-control start; then
    '${INSTALLATION_PATH}'/bin/cyb3rhq-control stop
fi

while : ; do
    trap capture_sigterm SIGTERM
    sleep 3
done
' > $LAUNCHER_SCRIPT
