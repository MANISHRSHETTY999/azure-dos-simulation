# Azure-Based DoS Simulation and Detection

## Overview
This project demonstrates a Distributed Denial of Service (DoS) attack simulation using Azure Virtual Machines. It also includes packet capture and analysis to detect network anomalies.

## Project Structure
- azure-vm-setup: Commands for VM setup in Azure.
- attack-scripts: SYN flood attack script using hping3.
- pyshark-script: Python script for packet capture and analysis.
- documentation: Results and reports.
- requirements.txt: Python dependencies.

## Features
- Azure VM setup for attacker and target.
- SYN flood attack using `hping3`.
- Packet capture and analysis using Pyshark.
- Results sent to an Azure-hosted endpoint for classification.

## Prerequisites
- Azure account with access to VM creation.
- Python 3.8+ installed.
- Tools: hping3, pyshark.

## Setup
1. **Azure VM Creation**:
   - Create 3 VMs (1 attacker, 1 target, 1 observer) in the same virtual network.
   - Configure necessary NSG rules.

2. **Attack Simulation**:
   - Use `hping3` to generate a SYN flood attack.

3. **Packet Capture**:
   - Run the Pyshark script on the target to capture traffic.

4. **Endpoint Integration**:
   - Send captured packets to the Azure endpoint.

## Results
- Increased CPU utilization during the attack.
- SYN packets visible in netstat.
- Prediction results from the endpoint.

## License
This project is licensed under the MIT License.
