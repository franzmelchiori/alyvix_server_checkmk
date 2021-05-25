# Checkmk special agent for Alyvix Server

This Checkmk special agent uses the RESTful web API of the Alyvix Server
to gather transaction measurements about a given ongoing Alyvix test
case.

usage:
* `agent_alyvix_server.py` `[-h]`
                           `[-a ALYVIX_SERVER_HTTPS_URL]`
                           `[-t TEST_CASE_ALIAS]`
  
where to install the wrapper `agent_alyvix_server` of this special agent
in Checkmk:
* `/omd/sites/checkmkalyvix/local/bin`

where to install the module `agent_alyvix_server.py` of this special
agent in Checkmk:
* `/omd/sites/checkmkalyvix/lib/python3/cmk/special_agents`

notes:
* Checkmk special agents (a type of Checkmk datasource program) retrieve
  data via HTTP scripts
* Checkmk executes this CLI command: this produces the agent data on the
  standard output, which is then processed by Checkmk in exactly the
  same way as if it had come from a normal agent
* look for 'Individual program call' instead of agent access
* any exit code other than 0 will be treated as an error
* error messages are expected on the standard error channel (stderr)
