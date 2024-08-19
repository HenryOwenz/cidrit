import sys
import ipaddress
import argparse
import subprocess
import re
import logging
from typing import List, Tuple

LESS_THRESHOLD = 20

# Initialize the logger at the module level
logger = logging.getLogger(__name__)

# Logger configuration class
class LoggerConfig:
    @staticmethod
    def configure_logging(debug: bool = False) -> None:
        """Configure logging for the application."""
        logger.setLevel(logging.DEBUG if debug else logging.INFO)

        # Create a console handler for errors (stderr)
        ch_error = logging.StreamHandler(sys.stderr)
        ch_error.setLevel(logging.ERROR)
        ch_error.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

        # Create a console handler for debug/info (stdout)
        ch_info = logging.StreamHandler(sys.stdout)
        ch_info.setLevel(logging.DEBUG if debug else logging.INFO)
        ch_info.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

        # Clear existing handlers to avoid duplication
        if logger.hasHandlers():
            logger.handlers.clear()

        # Add the handlers to the logger
        logger.addHandler(ch_error)
        logger.addHandler(ch_info)

        # Ensure that the error handler only handles ERROR level messages
        ch_info.addFilter(lambda record: record.levelno < logging.ERROR)


class ErrorHandler:
    @staticmethod
    def handle_exception(exc: Exception, msg: str = "") -> None:
        """Handle an exception by logging it and printing an optional custom message."""
        if msg:
            logger.error(f"{msg}: {exc}")
        else:
            logger.error(f"An error occurred: {exc}")
        sys.exit(1)  # Exit the program after logging the error

    @staticmethod
    def handle_value_error(exc: ValueError, msg: str = "") -> None:
        """Handle ValueErrors specifically."""
        if msg:
            logger.error(f"Value Error - {msg}: {exc}")
        else:
            logger.error(f"Value Error: {exc}")
        sys.exit(1)

    @staticmethod
    def handle_io_error(exc: IOError, msg: str = "") -> None:
        """Handle IOErrors specifically."""
        if msg:
            logger.error(f"IO Error - {msg}: {exc}")
        else:
            logger.error(f"IO Error: {exc}")
        sys.exit(1)

    @staticmethod
    def handle_ip_address_error(exc: ipaddress.AddressValueError, msg: str = "") -> None:
        """Handle IP address-related errors specifically."""
        if msg:
            logger.error(f"IP Address Error - {msg}: {exc}")
        else:
            logger.error(f"IP Address Error: {exc}")
        sys.exit(1)


class CidrInfo:
    def __init__(self, cidr_block: str = None, no_color: bool = False):
        try:
            self.network = ipaddress.IPv4Network(cidr_block, strict=False) if cidr_block else None
        except ipaddress.AddressValueError as e:
            ErrorHandler.handle_ip_address_error(e, "Invalid CIDR block")
        self.no_color = no_color
        self.color_index = 0
        self.colors = ["\033[94m", "\033[93m", "\033[92m", "\033[95m"]
        self.total_output = ""
    
    def get_number_of_ips(self) -> str:
        try:
            return f"The number of IPs in the subnet is: {self.network.num_addresses}"
        except AttributeError as e:
            ErrorHandler.handle_exception(e, "Failed to calculate the number of IPs")

    def split_net(self, new_prefix: int) -> str:
        try:
            if new_prefix <= self.network.prefixlen:
                raise ValueError(f"New prefix {new_prefix} must be greater than the original prefix {self.network.prefixlen}.")
            
            subnets = list(self.network.subnets(new_prefix=new_prefix))
            result = [("Subnets after Splitting", ""), ("Number of Subnets", str(len(subnets))), ("Subnet CIDR", "Number of IPs")]
            result += [(str(subnet), str(subnet.num_addresses)) for subnet in subnets]
            
            output = self._format_output(result)
            self.total_output += output
            return output
        except ValueError as e:
            ErrorHandler.handle_value_error(e, "Error during subnet splitting")
        except Exception as e:
            ErrorHandler.handle_exception(e, "Unexpected error during subnet splitting")
    
    def generate_net(self, num_subnets: int) -> str:
        try:
            new_prefix = self.network.prefixlen + (num_subnets - 1).bit_length()
            if new_prefix > 32:
                raise ValueError("Not enough IP space to generate that many subnets.")
            
            subnets = list(self.network.subnets(new_prefix=new_prefix))
            result = [("Generated Subnets", ""), ("Number of Subnets", str(len(subnets[:num_subnets]))), ("Subnet CIDR", "Number of IPs")]
            result += [(str(subnet), str(subnet.num_addresses)) for subnet in subnets[:num_subnets]]
            
            output = self._format_output(result)
            self.total_output += output
            return output
        except ValueError as e:
            ErrorHandler.handle_value_error(e, "Error during subnet generation")
        except Exception as e:
            ErrorHandler.handle_exception(e, "Unexpected error during subnet generation")
    
    def check_overlap(self, other_cidr_blocks: List[str]) -> str:
        try:
            overlapping = [cidr for cidr in other_cidr_blocks if self.network.overlaps(ipaddress.IPv4Network(cidr, strict=False))]
            
            if overlapping:
                result = [("Overlapping CIDR Blocks", ""), ("Number of Overlaps", str(len(overlapping)))] + [(cidr, "") for cidr in overlapping]
            else:
                result = [("Overlapping CIDR Blocks", ""), ("No overlaps found", "")]
            
            output = self._format_output(result)
            self.total_output += output
            return output
        except ipaddress.AddressValueError as e:
            ErrorHandler.handle_ip_address_error(e, "Error during overlap check")
        except Exception as e:
            ErrorHandler.handle_exception(e, "Unexpected error during overlap check")

    def summarize_subnets(self, subnets: List[str]) -> str:
        try:
            # Convert input subnets to IPv4Network objects and sort them
            network_objects = sorted([ipaddress.IPv4Network(cidr) for cidr in subnets])
            logger.debug(f"Sorted network objects: {network_objects}")
            
            # Summarize contiguous subnets
            summarized = list(ipaddress.collapse_addresses(network_objects))
            logger.debug(f"Summarized CIDR blocks: {summarized}")
            
            # Prepare the result for output
            result = [("Summarized CIDR Blocks", ""), ("Number of Summarized Blocks", str(len(summarized))), ("Subnet CIDR", "Number of IPs")]
            result += [(str(cidr), str(cidr.num_addresses)) for cidr in summarized]
            
            # Format the output
            output = self._format_output(result)
            self.total_output += output
            return output
        except ipaddress.AddressValueError as e:
            ErrorHandler.handle_ip_address_error(e, "Error during subnet summarization")
        except Exception as e:
            ErrorHandler.handle_exception(e, "Unexpected error during subnet summarization")

    def range_to_cidr(self, start_ip: str, end_ip: str) -> str:
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            networks = list(ipaddress.summarize_address_range(start, end))
            result = [("CIDR Blocks for IP Range", ""), ("Number of CIDR Blocks", str(len(networks)))] + [(str(cidr), "") for cidr in networks]
            
            output = self._format_output(result)
            self.total_output += output
            return output
        except ipaddress.AddressValueError as e:
            ErrorHandler.handle_ip_address_error(e, "Invalid IP range for CIDR conversion")
        except Exception as e:
            ErrorHandler.handle_exception(e, "Unexpected error during range to CIDR conversion")
    
    def generate_doc(self, output_file: str) -> None:
        try:
            no_color_output = self._remove_color(self.total_output)
            with open(output_file, 'w') as f:
                f.write("# CIDR Block Documentation\n\n")
                f.write("## CIDR Block Information\n\n")
                f.write(no_color_output)
            logger.info(f"Documentation generated: {output_file}")
        except IOError as e:
            ErrorHandler.handle_io_error(e, f"Failed to write documentation to {output_file}")
        except Exception as e:
            ErrorHandler.handle_exception(e, "Unexpected error during documentation generation")

    def _format_output(self, rows: List[Tuple[str, str]]) -> str:
        try:
            if not rows:
                return ""

            col_widths = [max(len(item) for item in col) for col in zip(*rows)]
            header_color = self.colors[self.color_index] if not self.no_color else ""
            border_color = "\033[90m" if not self.no_color else ""
            reset_color = "\033[0m" if not self.no_color else ""
            self.color_index = (self.color_index + 1) % len(self.colors)
            
            border = border_color + "+" + "+".join("-" * (width + 2) for width in col_widths) + "+" + reset_color

            result = [border]
            for i, row in enumerate(rows):
                line = "| " + " | ".join(item.ljust(width) for item, width in zip(row, col_widths)) + " |"
                if i < 2:
                    line = header_color + line + reset_color
                result.append(line)
                result.append(border)
            
            return "\n".join(result) + "\n"
        except Exception as e:
            ErrorHandler.handle_exception(e, "Error during output formatting")

    def output_with_less(self) -> None:
        """Handles output, determining whether to use less based on content size and prints entire output afterward."""
        try:
            lines = self.total_output.count('\n')
            if lines > LESS_THRESHOLD:
                no_color_output = self._remove_color(self.total_output)
                subprocess.run(['less'], input=no_color_output.encode('utf-8'))
            
            # Print the entire output to the terminal after the less command is used
            print(self.total_output)
        except Exception as e:
            ErrorHandler.handle_exception(e, "Error during output handling")

    def _remove_color(self, text: str) -> str:
        try:
            return re.sub(r'\x1b\[\d+m', '', text)
        except Exception as e:
            ErrorHandler.handle_exception(e, "Error during color removal")

class CidrInfoTool:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="CIDR Information Tool for Network Engineers")
        self._setup_arguments()

    def _setup_arguments(self) -> None:
        self.parser.add_argument("cidr_block", nargs='?', help="The CIDR block to analyze (e.g., 192.168.1.0/24)")
        self.parser.add_argument("-n", "--num_ips", action="store_true", help="Display the number of IPs in the subnet")
        self.parser.add_argument("-s", "--split_net", type=int, help="Split the CIDR block into smaller subnets with the given prefix length")
        self.parser.add_argument("-g", "--generate_net", type=int, help="Generate a list of subnets based on the number of subnets you want")
        self.parser.add_argument("--check-overlap", nargs='+', help="Check if the CIDR block overlaps with other specified CIDR blocks")
        self.parser.add_argument("--summarize", nargs='+', help="Summarize a list of subnets into the smallest possible set of CIDR blocks")
        self.parser.add_argument("--range-to-cidr", nargs=2, metavar=('START_IP', 'END_IP'), help="Convert an IP range to the corresponding CIDR block(s)")
        self.parser.add_argument("-gd", "--generate-doc", metavar='OUTPUT_FILE', help="Generate documentation of the CIDR blocks and operations in a specified file")
        self.parser.add_argument("--no-color", action="store_true", help="Disable color output")
        self.parser.add_argument("--debug", action="store_true", help="Enable debug output")

    def run(self) -> None:
        """Parse arguments and execute corresponding CIDR information functions."""
        try:
            args = self.parser.parse_args()

            # Configure logging based on the debug flag
            LoggerConfig.configure_logging(debug=args.debug)

            # Check if no arguments are provided and print error + help if so
            if len(sys.argv) == 1:
                logger.error("No input provided. Please specify a CIDR block or other options.")
                self.parser.print_help()
                sys.exit(1)

            if not args.cidr_block and not any([args.summarize, args.range_to_cidr, args.generate_doc]):
                logger.error("CIDR block is required unless --summarize, --range-to-cidr, or --generate-doc is specified.")
                sys.exit(1)

            cidr_info = CidrInfo(args.cidr_block, no_color=args.no_color) if args.cidr_block else CidrInfo()

            # Default to displaying the number of IPs if no other action is specified
            if args.cidr_block and not any([args.num_ips, args.split_net, args.generate_net, args.check_overlap, args.summarize, args.range_to_cidr, args.generate_doc]):
                args.num_ips = True

            if args.num_ips and args.cidr_block:
                logger.debug("Displaying number of IPs.")
                cidr_info.total_output += cidr_info._format_output([("CIDR Block Information", ""), ("CIDR Block", "Number of IPs"), (args.cidr_block, str(cidr_info.network.num_addresses))])

            if args.split_net and args.cidr_block:
                logger.debug(f"Splitting network with new prefix {args.split_net}.")
                cidr_info.split_net(args.split_net)

            if args.generate_net and args.cidr_block:
                logger.debug(f"Generating network with {args.generate_net} subnets.")
                cidr_info.generate_net(args.generate_net)

            if args.check_overlap and args.cidr_block:
                logger.debug(f"Checking overlap with provided CIDR blocks: {args.check_overlap}.")
                cidr_info.check_overlap(args.check_overlap)

            if args.summarize:
                logger.debug("Summarizing provided subnets.")
                cidr_info.total_output += cidr_info.summarize_subnets(args.summarize)

            if args.range_to_cidr:
                logger.debug(f"Converting range {args.range_to_cidr[0]} - {args.range_to_cidr[1]} to CIDR blocks.")
                cidr_info.total_output += cidr_info.range_to_cidr(args.range_to_cidr[0], args.range_to_cidr[1])

            if args.generate_doc:
                logger.debug(f"Generating documentation in file {args.generate_doc}.")
                cidr_info.generate_doc(args.generate_doc)

            # Output with less if necessary and print the entire output afterward
            cidr_info.output_with_less()

        except Exception as e:
            ErrorHandler.handle_exception(e, "An error occurred during CIDR info processing")

if __name__ == "__main__":
    tool = CidrInfoTool()
    tool.run()

