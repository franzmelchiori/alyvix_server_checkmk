# Checkmk local check for Alyvix Server

This Checkmk local check uses the RESTful web API of the Alyvix Server
to gather transaction measurements about a given ongoing Alyvix test
case.

usage:
* `agent_alyvix_server.py` `[-h]`
                           `[-a ALYVIX_SERVER_HTTPS_URL]`
                           `[-t TEST_CASE_ALIAS]`
  
1. install the module `agent_alyvix_server.py` in a folder
   `ALYVIX_SERVER_CHECKMK_PATH` of the Alyvix Server Windows machine
   
2. install the batch file `agent_alyvix_server.bat` in the folder
   `C:\ProgramData\checkmk\agent\local`; edit the batch file to set
   `ALYVIX_SERVER_CHECKMK_PATH`, `ALYVIX_SERVER_HTTPS_URL` and
   `TEST_CASE_ALIAS`: add a command line for each test case you would like to
   monitor
   
3. open the Checkmk service configuration web UI of the Alyvix Server
   host, scan for new services and add the new services
