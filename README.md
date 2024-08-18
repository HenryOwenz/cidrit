# CIDR Information Tool

The CIDR Information Tool is a command-line utility designed for network engineers to analyze and manipulate CIDR blocks. It provides various functionalities, including calculating the number of IPs in a CIDR block, splitting CIDR blocks into smaller subnets, generating subnets, checking for overlapping CIDR blocks, summarizing subnets, converting IP ranges to CIDR blocks, and generating documentation of the CIDR operations.

## Features

- **CIDR Block Analysis**: Calculate the number of IPs in a given CIDR block.
- **Subnet Splitting**: Split a CIDR block into smaller subnets based on a new prefix.
- **Subnet Generation**: Generate a specified number of subnets from a CIDR block.
- **Overlap Checking**: Check if a CIDR block overlaps with other specified CIDR blocks.
- **Subnet Summarization**: Summarize a list of CIDR blocks into the smallest possible set of CIDR blocks.
- **IP Range to CIDR Conversion**: Convert a range of IP addresses to the corresponding CIDR blocks.
- **Documentation Generation**: Generate a markdown document containing the results of CIDR operations.

## Installation

To use this tool, clone the repository and ensure that Python is installed on your system.

git clone https://github.com/henryowenz/cidrit.git
cd cidrit

## Usage

The tool can be invoked with various command-line options to perform different operations. Below are the available options:

- `cidr_block`: The CIDR block to analyze (e.g., `192.168.1.0/24`).
- `-n`, `--num_ips`: Display the number of IPs in the subnet.
- `-s`, `--split_net`: Split the CIDR block into smaller subnets with the given prefix length.
- `-g`, `--generate_net`: Generate a list of subnets based on the number of subnets you want.
- `--check-overlap`: Check if the CIDR block overlaps with other specified CIDR blocks.
- `--summarize`: Summarize a list of subnets into the smallest possible set of CIDR blocks.
- `--range-to-cidr`: Convert an IP range to the corresponding CIDR blocks.
- `-gd`, `--generate-doc`: Generate documentation of the CIDR blocks and operations in a specified file.
- `--no-color`: Disable color output.
- `--debug`: Enable debug output.

### Example Commands

# Calculate the number of IPs in a CIDR block
python cidrinfo.py 192.168.1.0/24 -n

# Split a CIDR block into smaller subnets
python cidrinfo.py 192.168.1.0/24 -s 26

# Generate a specified number of subnets from a CIDR block
python cidrinfo.py 192.168.1.0/24 -g 4

# Check for overlaps with other CIDR blocks
python cidrinfo.py 192.168.1.0/24 --check-overlap 10.0.0.0/8 172.16.0.0/12

# Summarize a list of subnets into the smallest possible set of CIDR blocks
python cidrinfo.py --summarize 192.168.1.0/24 192.168.2.0/24

# Convert an IP range to CIDR blocks
python cidrinfo.py --range-to-cidr 192.168.1.1 192.168.1.255

# Generate documentation of CIDR blocks and operations
python cidrinfo.py 192.168.1.0/24 -n -gd output.md

## License

This project is licensed under the MIT License.

