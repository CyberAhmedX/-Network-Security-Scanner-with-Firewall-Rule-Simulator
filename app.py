from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import nmap

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
    
    # Emit the rule to the frontend for visualization
    emit('firewall_rule_added', {
        'ip': rule_ip,
        'port': rule_port,
        'action': rule_action
    })

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


if __name__ == '__main__':
    socketio.run(app, debug=True)
