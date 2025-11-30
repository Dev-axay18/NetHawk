# NetHawk Screenshots

Place your screenshots here with the following names:

1. **banner.png** - NetHawk banner and main interface
2. **packet-capture.png** - Packet sniffing in action
3. **flow-analysis.png** - Flow analysis output
4. **anomaly-detection.png** - Anomaly detection alerts
5. **traceroute.png** - Advanced traceroute results
6. **threat-detection.png** - Threat intelligence alerts
7. **reports.png** - JSON report example

## Screenshot Guidelines

- Use high-quality terminal screenshots
- Recommended terminal: Terminator, Tilix, or iTerm2
- Color scheme: Dark background with colored output
- Resolution: At least 1920x1080
- Format: PNG with transparency (if possible)

## How to Take Screenshots

```bash
# Run commands and capture output
sudo nethawk --sniff wlan0 --flows --detect --timeout 10
sudo nethawk --trace google.com
sudo nethawk --fullscan 8.8.8.8

# Use screenshot tools
# Linux: gnome-screenshot, flameshot, scrot
# macOS: Command+Shift+4
```
