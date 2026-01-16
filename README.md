# READ ME

This document contains information on how to use this tool.

## Running the tool

The tool is designed to run on Linux machines only.
To run the tool, run `sudo python3 tool.py`. A GUI will pop up that you can configure the attack with.

## Tool usage

There are 3 attack modes in the tool, below is a brief explanation of each attack and how to set it up.

### ARP Poisoning

This attack will ARP poison both the ARP tables defined victim and server with the MAC address that is entered.
Fields to configure:
- `Victim IP` - Enter the IPv4 address of the victim.
- `Server IP` - Enter the IPv4 address of the server. This is prefilled with the gateway IPv4 address.
- `Spoof As MAC` - Here you enter the MAC you want to spoof as.

Pressing `Start Attack` will cause the tool to start sending forged ARP responses to the victim and the server,
where we claim to be the victim / server and that we are on the specified MAC address.

### DNS Spoofing

This attack will DNS spoof a victim when they try to access a specific domain.
Fields to configure:
- `Victim IP` - Enter the IPv4 address of the victim.
- `Domain to Spoof` - Enter the domain to spoof.

Pressing `Start Attack` will cause the tool to start ARP poisoning both the victim and the gateway, and listen for DNS queries and responses.
When a DNS response is found for `Domain to Spoof`, it will be transformed such that the victim gets redirected to the IP of the attackers device.

### MITM (With SSL stripping)

This attack will create a man in the middle position with SSL stripping.
Fields to configure:
- `Victim IP` - Enter the IPv4 address of the victim.
- `Server IP` - Enter the IPv4 address of the server.
- `Use SSL stripping` - Toggle to use SSL stripping.

Pressing `Start Attack` will cause the tool to start ARP poisoning both the victim and the server. When an HTTPS redirect is attempted,
it will be intercepted. The victim will stay on the non-secure HTTP version of the website, and the server will think the victim is on HTTPS.

