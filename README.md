# 2019-Spring-CSE6242-mlserver

## Initial Thinking

Server is deployed with models already trained. Training models is part of building the server software package. Each model is stored as a pickle in the server as a resource file. 

Server should take in a pcap file during startup or via a POST.

Given the pcap file it should extract the flows from the pcap file.

It should then perform classification on the generated flows. Each model available should be used to perform classification.

It should expose endpoints which allow for providing insights into IP pairs, port pairs, and IP + port pairs.

Example Request: GET https://mlserver.domain/v1/info?src\_ip=192.168.1.12&dest\_ip=192.168.1.10&src\_port=12345&dest\_port=23456

Example Return: JSON blob containing info about the values in the query

## API

### IP Pairs

__Request__: /v1/ip\_pair/{source\_ip}/{destination\_ip}

__Response__:

```
{
    "botnet_flow_liklihood": int
}
```

### Port Pairs

__Request__: /v1/port\_pair/{source\_port}/{destination\_port}

__Response__:

```
{
    "botnet_flow_liklihood": int
}
```

## Open Questions

Q: How to relate IP pairs, port pairs, IP + port pairs to individual flows?

A: It is likely that a given port pair will not be will not be used for background traffic and botnet traffic. It is possible that IP pairs will contain botnet traffic and background traffic. 

Given an IP pair or port pair we could provide likelihood that traffic between them is malicious.

BENIGN: No flow containing the IP pair is classified as botnet
POSSIBLY BOTNET: One or more flows containing the IP pair is classified as botnet 
BOTNET: All flows containing the IP pair are classified as botnet

We could even represent these as percentages which could lend itself to easy visualization.
