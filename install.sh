#!/bin/bash
# NetHawk Installation Script

echo "Installing NetHawk Security Toolkit..."

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Installing system-wide..."
    pip install .
else
    echo "Installing for current user..."
    pip install . --user
fi

echo ""
echo "Installation complete!"
echo ""
echo "Usage:"
echo "  nethawk --help                    # Show help"
echo "  sudo nethawk --sniff eth0         # Packet sniffing"
echo "  nethawk --trace google.com        # Traceroute"
echo "  sudo nethawk --fullscan target    # Full scan"
echo ""
