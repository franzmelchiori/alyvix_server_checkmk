# Checkmk local check for Alyvix Server

This Checkmk local check uses the RESTful web API of the Alyvix Server
to gather transaction measurements about a given ongoing Alyvix test
case.

Usage:
* `python agent_alyvix_server.py`
* Optional arguments:
  * `[-h]`
  * `[-a ALYVIX_SERVER_HTTPS_URL]`
  * `[-t TEST_CASE_ALIAS]`
    
Deployment:
1. install this package `alyvix_server_checkmk` in a folder
   `PYTHON3_PATH\Lib\site-packages\` of the Alyvix Server (Windows
   machine)
2. install the batch file `agent_alyvix_server.bat` in the folder
   `C:\ProgramData\checkmk\agent\local`
3. open the Checkmk service configuration web UI of the Alyvix Server
   host, scan for new services and add the new services
