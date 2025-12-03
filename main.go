package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// stolen - might need an upgrade
var mysqlCharset = map[byte]string{
	1:   "big5_chinese_ci",
	3:   "dec8_swedish_ci",
	8:   "latin1_swedish_ci",
	9:   "latin2_general_ci",
	33:  "utf8_general_ci",
	45:  "utf8mb4_general_ci",
	46:  "utf8mb4_bin",
	47:  "latin1_general_ci",
	48:  "latin1_general_cs",
	49:  "cp1251_general_ci",
	52:  "cp1257_general_ci",
	63:  "binary",
	84:  "utf8_bin",
	96:  "cp1250_bin",
	255: "unknown",
}
var mysqlCapabilities = map[uint32]string{
	0x00000001: "CLIENT_LONG_PASSWORD",
	0x00000002: "CLIENT_FOUND_ROWS",
	0x00000004: "CLIENT_LONG_FLAG",
	0x00000008: "CLIENT_CONNECT_WITH_DB",
	0x00000010: "CLIENT_NO_SCHEMA",
	0x00000020: "CLIENT_COMPRESS",
	0x00000040: "CLIENT_ODBC",
	0x00000080: "CLIENT_LOCAL_FILES",
	0x00000100: "CLIENT_IGNORE_SPACE",
	0x00000200: "CLIENT_PROTOCOL_41",
	0x00000400: "CLIENT_INTERACTIVE",
	0x00000800: "CLIENT_SSL",
	0x00001000: "CLIENT_IGNORE_SIGPIPE",
	0x00002000: "CLIENT_TRANSACTIONS",
	0x00004000: "CLIENT_RESERVED",
	0x00008000: "CLIENT_SECURE_CONNECTION",
	0x00010000: "CLIENT_MULTI_STATEMENTS",
	0x00020000: "CLIENT_MULTI_RESULTS",
	0x00040000: "CLIENT_PS_MULTI_RESULTS",
	0x00080000: "CLIENT_PLUGIN_AUTH",
	0x00100000: "CLIENT_CONNECT_ATTRS",
	0x00200000: "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
	0x00400000: "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",
	0x00800000: "CLIENT_SESSION_TRACK",
	0x01000000: "CLIENT_DEPRECATE_EOF",

	// MariaDB extensions
	0x02000000: "MARIADB_CLIENT_OPTIONAL_METADATA",
	0x04000000: "MARIADB_CLIENT_AUTH_PLUGIN_MISSING",
	0x08000000: "MARIADB_CLIENT_PROGRESS",
}

func decodeCapabilities(cf uint32) []string {
	caps := []string{}
	for bit, name := range mysqlCapabilities {
		if cf&bit != 0 {
			caps = append(caps, name)
		}
	}
	return caps
}

type ScanResult struct {
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	Error           string   `json:"error,omitempty"`
	Is_mysql_server string   `json:"is_mysql_server,omitempty"`
	Raw_buffer      []byte   `json:"raw_buffer,omitempty"`
	Payload_len     int      `json:"payload_len,omitempty"`
	Protocol_ver    int      `json:"protocol_ver,omitempty"`
	Server_ver      string   `json:"server_version,omitempty"`
	Conn_id         int      `json:"conn_id,omitempty"`
	Charset         string   `json:"charset,omitempty"`
	Charset_nr      int      `json:"charset_id,omitempty"`
	Auth_data_1     []byte   `json:"auth_data_p1,omitempty"`
	Auth_data_2     []byte   `json:"auth_data_p2,omitempty"`
	Auth_plug_name  string   `json:"auth_plug_name,omitempty"`
	Status          int      `json:"status,omitempty"`
	CF              []string `json:"capability_flags,omitempty"`
}

// this should work for the current stable mysql - because I checked only that documentation.
// must be adapted for previous versions as well!
func it_is_mysql(data []byte, result *ScanResult) bool {
	if len(data) < 4+20 { // min size check
		return false
	}

	payload_len := int(data[0]) | int(data[1])<<8 | int(data[2])<<16

	if len(data) != payload_len+4 { // see if len fits
		return false
	}

	if data[3] != 0 { // mysql docs says it always starts at 0. We are at init handshake - must be 0
		return false
	}

	if data[4] != 10 && data[4] != 9 { // mysql protocol 9 must be a stretch - since was not used since the version in 1998 - BUT I have seen my share of old things on the Internet
		return false
	}
	protocol_ver := int(data[4])

	i := 5
	version := ""
	for i < len(data) && data[i] != 0 {
		if data[i] < 32 || data[i] > 126 { //check if printable ASCII (character code 32-127)
			return false
		}
		version += string(data[i])
		i++
	}
	if i >= len(data) || data[i] != 0 { //version has to end with a NULL
		return false
	}
	i++

	conn_id := binary.LittleEndian.Uint32(data[i : i+4]) //connection id ? something incremental
	i += 4

	apd_p1 := data[i : i+8] //auth plugin data part 1 - 8 bytes
	i += 8

	i++ //filter

	cf_low := data[i : i+2]
	i += 2

	charset := data[i]
	i++

	status := binary.LittleEndian.Uint16(data[i : i+2])
	i += 2

	cf_high := data[i : i+2]
	i += 2

	cf := uint32(binary.LittleEndian.Uint16(cf_low)) | uint32(binary.LittleEndian.Uint16(cf_high))<<16

	total_auth_plugin_data := int(data[i])
	i++

	i += 10 // rezerved zeroes

	to_read_plugin := total_auth_plugin_data - 8
	apd_p2 := data[i : i+to_read_plugin]

	i += to_read_plugin

	auth_plug_name := string(data[i:])
	if !strings.Contains(auth_plug_name, "mysql_native_password") &&
		!strings.Contains(auth_plug_name, "caching_sha2_password") &&
		!strings.Contains(auth_plug_name, "sha256_password") &&
		!strings.Contains(auth_plug_name, "mysql_clear_password") {
		return false
	}

	//fill the fields only if I know it is mysql, otherwise there is the raw buffer to check
	result.Payload_len = payload_len
	result.Protocol_ver = protocol_ver
	result.Server_ver = version
	result.Conn_id = int(conn_id)
	result.Charset = mysqlCharset[charset]
	result.Charset_nr = int(charset)
	result.Status = int(status)
	result.Auth_data_1 = apd_p1
	result.Auth_data_2 = apd_p2
	result.Auth_plug_name = auth_plug_name
	result.CF = decodeCapabilities(cf)

	return true
}

func tcpConnect(address string, port int, timeout time.Duration) ScanResult {
	ipList, err := net.LookupHost(address)
	result := ScanResult{
		IP:   address,
		Port: port,
	}
	if err != nil {
		result.Error = fmt.Sprintf("%s", err)
		return result
	}
	if len(ipList) == 0 {
		result.Error = fmt.Sprintf("Unable to resolve %s", err)
		return result
	}
	connAddr := net.JoinHostPort(ipList[0], fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", connAddr, timeout)
	if err != nil {
		sErr := err.Error()
		if strings.HasSuffix(sErr, "connection refused") {
			fmt.Printf("\"error\":\"connection refused\",\n")
			result.Error = "connection refused"
			return result
		}
		if strings.HasSuffix(sErr, "i/o timeout") {
			result.Error = "i/o timeout"
			return result
		}
		result.Error = fmt.Sprintf("%s", err)
		return result
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		result.Is_mysql_server = "no"
		return result
	}
	data := buf[:n]

	result.Raw_buffer = data
	is_mysql := it_is_mysql(data, &result)
	if is_mysql {
		result.Is_mysql_server = "yes"
	} else {
		result.Is_mysql_server = "no"
	}

	return result
}

func writeResult(out io.Writer, result ScanResult) {
	jsonBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprintln(out, string(jsonBytes))
}

func processInputFile(path string, out io.Writer, timeout time.Duration) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			fmt.Fprintf(os.Stderr, "Skipping invalid line %d: %q\n", lineNo, line)
			continue
		}

		ip := fields[0]
		p, err := strconv.Atoi(fields[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid port on line %d: %q\n", lineNo, fields[1])
			continue
		}

		result := tcpConnect(ip, p, timeout)
		writeResult(out, result)
	}

	return scanner.Err()
}

func main() {
	ip := flag.String("ip", "", "IP address to scan")
	port := flag.Int("port", 3306, "Port to scan")
	inFile := flag.String("in", "", "Input file with list of 'ip port'")
	outFile := flag.String("out", "", "Output file (JSON lines). If empty, prints to stdout")
	timeout := flag.Int("timeout", 3, "Timeout in seconds")

	flag.Parse()

	// write to files if out is set
	var out io.Writer = os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	// if I got input file, ignore the ip/port flags
	if *inFile != "" {
		if err := processInputFile(*inFile, out, time.Duration(*timeout)*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing input file: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *ip == "" {
		fmt.Fprintln(os.Stderr, "Either -ip and -port or -in must be provided")
		os.Exit(1)
	}

	result := tcpConnect(*ip, *port, time.Duration(*timeout)*time.Second)
	writeResult(out, result)
}
