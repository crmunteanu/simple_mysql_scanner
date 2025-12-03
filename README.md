## Example of use

`go run main.go -ip 127.0.0.1 -port 3306`

`go run main.go -in ip_port_list`

If you want, you can have the output in a file:

`go run main.go -ip 127.0.0.1 -port 3306 -out scan.jsonl`

`go run main.go -in ip_port_list -out scan.jsonl`


## Sample of IP_PORT list file
```text
127.0.0.1 3306
10.0.0.1 443
192.168.0.1 22
```
