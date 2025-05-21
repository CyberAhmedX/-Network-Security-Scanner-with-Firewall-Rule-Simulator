from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import nmap
import subprocess
import platform

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

# In-memory storage for firewall rules
firewall_rules = []

@app.route('/')
def index():
    return render_template('index.html')

# Handle scan request
@socketio.on('start_scan')
def handle_scan(data):
    target_ip = data['target_ip']
    scan_type = data['scan_type']
    
    nm = nmap.PortScanner()

    # Run different types of scans based on the scan_type
    if scan_type == 'tcp':
        nm.scan(hosts=target_ip, arguments='-sS')  # TCP SYN Scan
    elif scan_type == 'udp':
        nm.scan(hosts=target_ip, arguments='-sU')  # UDP Scan
    elif scan_type == 'version':
        nm.scan(hosts=target_ip, arguments='-sV')  # Service Version Detection
    else:
        nm.scan(hosts=target_ip, arguments='-sT')  # Full TCP Connect Scan

    # Process scan results
    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                scan_results.append({
                    'ip': host,
                    'port': port,
                    'service': nm[host][proto][port]['name'],
                    'status': nm[host][proto][port]['state']
                })
    
    # Apply firewall rules and simulate traffic flow
    simulate_traffic(scan_results)

    # Emit scan results to frontend
    if scan_results:
        for result in scan_results:
            emit('scan_update', result)
    else:
        emit('scan_update', {
            'ip': target_ip,
            'port': 'N/A',
            'service': 'N/A',
            'status': 'No open ports found'
        })
    
    # Emit scan complete event to hide animation
    emit('scan_complete')
    


def add_real_firewall_rule(ip, port, action):
    """Add real firewall rule to the system"""
    try:
        if platform.system() == 'Windows':
            rule_name = f"Block_{ip}_{port}"
            if action == 'deny':
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="{rule_name}" '
                    f'dir=in action=block protocol=TCP remoteip={ip} localport={port}',
                    shell=True
                )
            else:  # allow
                subprocess.run(
                    f'netsh advfirewall firewall delete rule name="{rule_name}"',
                    shell=True
                )
        elif platform.system() == 'Linux':
            if action == 'deny':
                subprocess.run(
                    f'sudo iptables -A INPUT -p tcp --dport {port} -s {ip} -j DROP',
                    shell=True
                )
            else:  # allow
                subprocess.run(
                    f'sudo iptables -D INPUT -p tcp --dport {port} -s {ip} -j DROP',
                    shell=True
                )
        return True
    except Exception as e:
        print(f"Error managing firewall rule: {e}")
        return False
 # Handle firewall rule creation
@socketio.on('add_firewall_rule')
def handle_firewall_rule(data):
    rule_ip = data['ip']
    rule_port = int(data['port'])
    rule_action = data['action']
    
    # Add the firewall rule to the list
    firewall_rules.append({
        'ip': rule_ip,
        'port': rule_port,
        'action': rule_action
    })
    
    # Add real firewall rule to the system
    success = add_real_firewall_rule(rule_ip, rule_port, rule_action)
    
    if not success:
        emit('firewall_error', {'message': 'Failed to apply real firewall rule'})
        return
    
    # Emit the rule to the frontend for visualization
    emit('firewall_rule_added', {
        'ip': rule_ip,
        'port': rule_port,
        'action': rule_action
    })
@socketio.on('remove_firewall_rule')
def handle_remove_firewall_rule(data):
    rule_number = data['rule_number'] - 1  # Convert to 0-based index
    
    if 0 <= rule_number < len(firewall_rules):
        rule = firewall_rules[rule_number]
        
        # Remove the real firewall rule
        add_real_firewall_rule(rule['ip'], rule['port'], 'allow')
        
        # Remove from our list
        firewall_rules.pop(rule_number)
        
        emit('firewall_rule_removed', {'rule_number': data['rule_number']})
    else:
        emit('firewall_error', {'message': 'Invalid rule number'})

# Simulate traffic flow based on firewall rules
def simulate_traffic(scan_results):
    for result in scan_results:
        allowed = False
        for rule in firewall_rules:
            # Check if the rule applies to the scan result
            if rule['ip'] == result['ip'] and rule['port'] == result['port']:
                # Apply action based on rule
                if rule['action'] == 'deny':
                    result['status'] = 'Blocked'
                else:
                    result['status'] = 'Allowed'
                allowed = True
                break
        # If no matching rule, consider the traffic allowed by default
        if not allowed:
            result['status'] = 'Allowed'

# Start the server
if __name__ == '__main__':
    socketio.run(app, debug=True)
