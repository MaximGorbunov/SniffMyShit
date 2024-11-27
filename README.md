# SniffMyShit

**SniffMyShit** is a packet interception tool designed to filter and display HTTP request and response data based on user-defined criteria. It provides a flexible way to monitor network traffic on a specific interface, analyze HTTP headers, bodies, and more.

## Protocols
* HTTP1 
* HTTP2 TBD

## Features
- Intercept HTTP packets.
- Apply various filters to extract relevant data.
- Display request and response details based on filters.
- Customizable interface selection for monitoring.

## Installation
To compile and use **SniffMyShit**, make sure you have a C++ compiler and required libraries for network packet interception (e.g., libpcap).

## Usage

Run the program with various options to filter packets and display the desired information.

./sniffmyshit [options]

## Options

| Option               | Description                                                   | Short Flag | Example Usage                                 |
|----------------------|---------------------------------------------------------------|------------|----------------------------------------------|
| `--interface`        | Specify the network interface to monitor (e.g., eth0, wlan0). | `-i`       | `./sniffmyshit --interface eth0`             |
| `--time`             | Display the timestamp of each packet.                         | `-t`       | `./sniffmyshit --time`                       |
| `--request-url`      | Filter requests by URL pattern.                               | `-u`       | `./sniffmyshit --request-url "/api/v1/*"`    |
| `--response-status`  | Filter responses by HTTP status code.                         | `-S`       | `./sniffmyshit --response-status 200`        |
| `--request-header`   | Filter requests by a specific HTTP header.                    | `-h`       | `./sniffmyshit --request-header "User-Agent"`|
| `--response-header`  | Filter responses by a specific HTTP header.                   | `-H`       | `./sniffmyshit --response-header "Content-Type"` |
| `--request-body`     | Search for specific content in the request body.              | `-b`       | `./sniffmyshit --request-body "username"`    |
| `--response-body`    | Search for specific content in the response body.             | `-B`       | `./sniffmyshit --response-body "success"`    |

## Examples

Example 1: Monitor traffic on eth0 for requests to a specific URL
```bash
./sniffmyshit --interface eth0 --request-url "/login"
```

Example 2: Display packets with HTTP 404 responses and specific headers
```bash
./sniffmyshit --response-status 404 --response-header "Content-Type"
```


Example 3: Search for the word “error” in the response body

```bash
./sniffmyshit --response-body "error"
```
Example 4: Monitor all traffic on the default interface with timestamps
```bash
./sniffmyshit --time
```