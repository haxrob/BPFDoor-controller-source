# BPFDoor-controller-source
Source code to recent BPFDoor's controller variant
- Original: `2eacc8d91b9829b9606a7945fc5311fb5876cfb42ffccc1b91f61841237b04c1`
- Fixed: `bpfdoor_controller.c`
- Original to fixed helper: `format_fix.py`

## Compile:
```
$ apt install libssl-dev
$ gcc -Wno-implicit-function-declaration bpfdoor_controller.c -lssl -lcrypto -o controller`
```

## To recover/fix from original yourself:
```
$ python3 ./format_fix.py 
```

## Usage
`usage()` details have been stripped from the source. Supported options:

| Option | Argument | Description |
|--------|----------|-------------|
| -h | host | Destination host  |
| -H | ip | Secondary/hidden IP address (embedded in magic packet) |
| -d | port | Destination port on the infected host (any open port) |
| -b | port | Listen on specified TCP port  |
| -l | ip | Remote host (reverse shell) |
| -s | port | Remote port (reverse shell) |
| -t | value | Timeout value |
| -D | dir | URL directory path for HTTPS mode (max 20 chars) |
| -g | host | HTTPS mode - send magic packet via SSL POST request |
| -f | value | Set custom magic sequence (hex value) |
| -w | - | TCP mode |
| -i | - | ICMP mode |
| -u | - | UDP mode |
| -n | - | No password (check if backdoor is alive) |
| -o | - | Set magic sequence to 0x5571 |
| -m | - | Use local IP as remote host (overwrites -l) |
| -v | - | Enable debug |
| -c | - | Unused |

