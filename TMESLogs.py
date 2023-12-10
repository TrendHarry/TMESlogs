import requests
import base64
import csv
import time
import json
import threading

def start_query_thread(base_url, format_function, log_type_name, headers, delay, max_iterations):
    query_thread = threading.Thread(target=query_logs, args=(base_url, format_function, log_type_name, headers, delay, max_iterations))
    query_thread.start()
    return query_thread

def fetch_logs(url, headers):
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            print("Received 204 No Content, retrying...")
            time.sleep(5)  
        else:
            print(f"Error fetching data: {response.status_code}, {response.text}")
            return None

def format_policy_event_log(log):
    if not isinstance(log, dict):
        print("Warning: Log is not a dictionary. Skipping this log.")
        return None

    details = log.get('details', '{}')
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError:
            details = {}

    spam_report = details.get('spamReport', {})
    return {
        'genTime': log.get('genTime', 'N/A'),
        'timestamp': log.get('timestamp', 'N/A'),
        'sender': log.get('sender', 'N/A'),
        'direction': log.get('direction', 'N/A'),
        'messageID': log.get('messageID', 'N/A'),
        'subject': log.get('subject', 'N/A'),
        'size': log.get('size', 'N/A'),
        'eventType': log.get('eventType', 'N/A'),
        'eventSubtype': log.get('eventSubtype', 'N/A'),
        'domainName': log.get('domainName', 'N/A'),
        'recipients': ', '.join(log.get('recipients', ['N/A'])),
        'policyAction': log.get('policyAction', 'N/A'),
        'policyName': log.get('policyName', 'N/A'),
        'enginePatternVersion': spam_report.get('enginePatternVersion', 'N/A'),
        'spamResultHeader': spam_report.get('spamResultHeader', 'N/A'),
        'SpamRidHeader': spam_report.get('spamRidHeader', 'N/A'),
        'snapHeader': spam_report.get('snapHeader', 'N/A'),
        'spamXGenCloudHeader': spam_report.get('spamXGenCloudHeader', 'N/A'),
        'headerFrom': log.get('headerFrom', 'N/A'),
        'headerTo': ', '.join(log.get('headerTo', ['N/A']))
    }

def format_accepted_traffic_log(log):
    return {
        'genTime': log.get('genTime', 'N/A'),
        'timestamp': log.get('timestamp', 'N/A'),
        'sender': log.get('sender', 'N/A'),
        'messageID': log.get('messageID', 'N/A'),
        'direction': log.get('direction', 'N/A'),
        'subject': log.get('subject', 'N/A'),
        'size': log.get('size', 'N/A'),
        'mailID': log.get('mailID', 'N/A'),
        'recipient': log.get('recipient', 'N/A'),
        'action': log.get('action', 'N/A'),
        'tlsInfo': log.get('tlsInfo', 'N/A'),
        'headerFrom': log.get('headerFrom', 'N/A'),
        'headerTo': ', '.join(log.get('headerTo', ['N/A'])),
        'senderIP': log.get('senderIP', 'N/A'),
        'embeddedUrls': ', '.join(log.get('embeddedUrls', ['N/A']))
    }

def format_blocked_traffic_log(log):
    return {
        'genTime': log.get('genTime', 'N/A'),
        'timestamp': log.get('timestamp', 'N/A'),
        'sender': log.get('sender', 'N/A'),
        'deliveryTime': log.get('deliveryTime', 'N/A'),
        'direction': log.get('direction', 'N/A'),
        'mailID': log.get('mailID', 'N/A'),
        'recipient': log.get('recipient', 'N/A'),
        'reason': log.get('reason', 'N/A'),
        'tlsInfo': log.get('tlsInfo', 'N/A'),
        'senderIP': log.get('senderIP', 'N/A'),
        'details': log.get('details', 'N/A'),
    }


def write_to_csv(logs, filename):
    if not logs:
        print("No data to write to CSV.")
        return
    with open(filename, 'w', newline='', encoding='utf-8') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=logs[0].keys())
        dict_writer.writeheader()
        dict_writer.writerows(logs)

def query_logs(base_url, format_function, log_type_name, headers, delay, max_iterations):
    iteration_count = 0
    next_token = None
    previous_token = None
    all_logs = []

    while iteration_count < max_iterations:
        url = base_url + (f"&token={next_token}" if next_token else "")
        data = fetch_logs(url, headers)

        if not data:
            break

        if next_token != previous_token:
            logs = [format_function(log) for log in data.get("logs", []) if log is not None]
            all_logs.extend(log for log in logs if log is not None)
            previous_token = next_token
            iteration_count += 1

        next_token = data.get("nextToken")

        if next_token:
            print(f"Next token for {log_type_name}: {next_token}")

        time.sleep(delay)

    write_to_csv(all_logs, f'tmes_logs_{log_type_name}.csv')
    print(f"{log_type_name} CSV file generated with {iteration_count} iterations.")

def main():
    regions = {
        1: 'North America, Latin America, Asia Pacific',
        2: 'Europe, Africa',
        3: 'Australia, New Zealand',
        4: 'Japan, Singapore, India, Middle East'
    }
    region_url_map = {
        1: 'api.tmes.trendmicro.com',
        2: 'api.tmes.trendmicro.eu',
        3: 'api.tmes-anz.trendmicro.com',
        4: 'api.tmems-jp.trendmicro.com'
    }

    for key, value in regions.items():
        print(f"{key}. {value}")

    region_choice = int(input("Select your region number: "))
    region_url = region_url_map.get(region_choice, 'api.tmes.trendmicro.com')
    username = input("Enter your username: ")
    api_key = input("Enter your API key: ")

    
    user_api_key_pair = f"{username}:{api_key}"
    encoded_credentials = base64.b64encode(user_api_key_pair.encode('utf-8')).decode('utf-8')
    headers = {'Authorization': f'Basic {encoded_credentials}'}

    print("Select the delay between each query:")
    print("1. 30s\n2. 1min\n3. 2mins")
    delay_choice = int(input("Your choice: "))
    delay_map = {1: 30, 2: 60, 3: 120}
    delay = delay_map.get(delay_choice, 60)

    print("Select the number of iterations:")
    print("1. 10\n2. 100\n3. 1000\n4. 2000\n5. Completed Query")
    iteration_choice = int(input("Your choice: "))
    iteration_map = {1: 10, 2: 100, 3: 1000, 4: 2000, 5: float('inf')}
    max_iterations = iteration_map.get(iteration_choice, float('inf'))

    print("Select the type of logs to query:")
    print("1. Policy Event Logs\n2. Accepted Traffic Logs\n3. Blocked Traffic Logs\n4. All Logs")
    log_choice = int(input("Your choice: "))

    policy_event_url = f"https://{region_url}/api/v1/log/policyeventlog?limit=500"
    accepted_traffic_url = f"https://{region_url}/api/v1/log/mailtrackinglog?type=accepted_traffic&limit=500"
    blocked_traffic_url = f"https://{region_url}/api/v1/log/mailtrackinglog?type=blocked_traffic&limit=500"

    threads = []
    if log_choice in [1, 4]:
        threads.append(start_query_thread(policy_event_url, format_policy_event_log, "Policy Events", headers, delay, max_iterations))
    if log_choice in [2, 4]:
        threads.append(start_query_thread(accepted_traffic_url, format_accepted_traffic_log, "Accepted Traffic", headers, delay, max_iterations))
    if log_choice in [3, 4]:
        threads.append(start_query_thread(blocked_traffic_url, format_blocked_traffic_log, "Blocked Traffic", headers, delay, max_iterations))

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
