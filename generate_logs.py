import random
from datetime import datetime, timedelta

# Generate sample auth logs
ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '192.168.1.105', 
       '203.0.113.42', '198.51.100.17', '192.168.1.100']
users = ['admin', 'root', 'user1', 'guest', 'administrator', 'test']
statuses = ['Failed', 'Success', 'Failed', 'Success', 'Failed'] 

with open('auth.log', 'w') as f:
    base_time = datetime.now() - timedelta(hours=24)
    for i in range(500):
        timestamp = base_time + timedelta(minutes=i*3)
        # This line fixes the date format by removing milliseconds
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        ip = random.choice(ips)
        user = random.choice(users)
        status = random.choice(statuses)
        
        if status == 'Failed':
            log_line = f"{timestamp_str} Authentication failure for {user} from {ip}\n"
        else:
            log_line = f"{timestamp_str} Successful login for {user} from {ip}\n"
        
        f.write(log_line)

print("✅ Sample 'auth.log' file created successfully!")