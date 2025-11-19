# Active-Response  
Scripts for Wazuh Active Response  
by Saad Zaib  

---

## Overview  
This repository contains a set of C-based active-response scripts that integrate with Wazuh’s active response mechanism. These scripts allow you to perform automated mitigation actions (such as blocking ports, disabling accounts, removing threats) upon detection of alerts by Wazuh.

---

## Included Scripts  
- `BlockPort.c` — Block a specific port via firewall or system command (to mitigate e.g., suspicious traffic).  
- `BlockPortAgentControl.c` — Similar to BlockPort, but perhaps directed at agents or remote control of agent ports (please review the code for details).  
- `disable_account_agent_control.c` — Disable a user account (local or via agent control) when triggered.  
- `remove-threat.c` — Remove a threat artefact or quarantine a file/process as part of response.

_(Note: Please review each script to confirm its exact behaviour, prerequisites, and compatibility with your environment.)_

---


---

## Installation & Usage  
1. Clone the repository:  
   ```bash
   git clone https://github.com/saad-zaib/Active-Response.git
   cd Active-Response
2 Clone the Wazuh Agent
  ```bash
  compile the agent with these new script would work fine then
