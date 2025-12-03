## Short Description of the scanner 

This is a simple mysql server scanner.
Given an IP address (IPv4/IPv6) and a destination port, the scanner will probe if the target is a mysql server or not.
The output is in JSON format.

## How to use

`go run main.go -ip 127.0.0.1 -port 3306`

`go run main.go -in ip_port_list`

You cna change the timeout (default=1sec):

`go run main.go -ip 127.0.0.1 -port 3306 -timeout 3`

`go run main.go -in ip_port_list -timeout=2`

Or, if you want, you can have the output in a file:

`go run main.go -ip 127.0.0.1 -port 3306 -out scan.jsonl`

`go run main.go -in ip_port_list -out scan.jsonl`


## Sample of IP_PORT list file
```text
127.0.0.1 3306
10.0.0.1 443
192.168.0.1 22
```

## Examples
**Run**
`go run main.go -ip 127.0.0.1 -port 3306`

**Output**

```JSON
{
  "ip": "127.0.0.1",
  "port": 3306,
  "is_mysql_server": "yes",
  "raw_buffer": "WwAAAAo4LjAuNDMtMHVidW50dTAuMjIuMDQuMQCWDAAALFlyL09cTwYA////AgD/3xUAAAAAAAAAAAAAamcaeidsNC4aBTRxAGNhY2hpbmdfc2hhMl9wYXNzd29yZAA=",
  "payload_len": 91,
  "protocol_ver": 10,
  "server_version": "8.0.43-0ubuntu0.22.04.1",
  "conn_id": 3222,
  "charset": "unknown",
  "charset_id": 255,
  "auth_data_p1": "LFlyL09cTwY=",
  "auth_data_p2": "amcaeidsNC4aBTRxAA==",
  "auth_plug_name": "caching_sha2_password\u0000",
  "status": 2,
  "capability_flags": [
    "CLIENT_RESERVED",
    "CLIENT_MULTI_RESULTS",
    "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",
    "CLIENT_DEPRECATE_EOF",
    "CLIENT_LONG_PASSWORD",
    "CLIENT_FOUND_ROWS",
    "CLIENT_NO_SCHEMA",
    "CLIENT_PROTOCOL_41",
    "CLIENT_SECURE_CONNECTION",
    "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
    "MARIADB_CLIENT_AUTH_PLUGIN_MISSING",
    "CLIENT_CONNECT_WITH_DB",
    "CLIENT_INTERACTIVE",
    "CLIENT_TRANSACTIONS",
    "CLIENT_CONNECT_ATTRS",
    "MARIADB_CLIENT_OPTIONAL_METADATA",
    "MARIADB_CLIENT_PROGRESS",
    "CLIENT_LONG_FLAG",
    "CLIENT_COMPRESS",
    "CLIENT_SSL",
    "CLIENT_MULTI_STATEMENTS",
    "CLIENT_PS_MULTI_RESULTS",
    "CLIENT_PLUGIN_AUTH",
    "CLIENT_SESSION_TRACK",
    "CLIENT_ODBC",
    "CLIENT_LOCAL_FILES",
    "CLIENT_IGNORE_SPACE",
    "CLIENT_IGNORE_SIGPIPE"
  ]
}
```
**Run**
`go run main.go -ip 10.0.0.1 -port 443`

**Output**

```JSON
{
  "ip": "10.0.0.1",
  "port": 443,
  "is_mysql_server": "no"
}
```
**Run**
`go run main.go -ip 10.0.0.1 -port 22`

**Output**

```JSON
{
  "ip": "10.0.0.1",
  "port": 22,
  "error": "i/o timeout"
}
```
