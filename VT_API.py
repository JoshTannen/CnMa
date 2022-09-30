#import file where api key is stored at
import config
import requests
import json

def api_call_virustotal(ip_address):
    
    ip_address = ip_address
    api_key = config.virustotal_api_key
    api_url = "https://www.virustotal.com/api/v3/search?query=" + ip_address
    headers = {
        "Accept": "application/json",
        "x-apikey": config.virustotal_api_key
    }
    response = requests.get(api_url, headers=headers)
    return response

def read_response(response):
    '''
    returns a dictionary with flagged ratio, engines flagged and quantity for each reponse
    '''
    j_data = json.loads(response.text)
    info = j_data['data']
    stats = info[0]['attributes']['last_analysis_stats']

    harmless = stats.get('harmless', 0)
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    timeout = stats.get("timeout", 0)

    stats_output = (malicious + suspicious) / (malicious + suspicious + harmless + undetected + timeout)

    info = j_data['data']
    data = info[0]['attributes']['last_analysis_results']

    new_list = []
    for i in data:
        if data[i]['category'] == 'malicious':
            new_list.append(data[i]['engine_name'])
    
    out = {'stats_output': stats_output,
           'engines_flagged': new_list,
           'harmless': harmless,
           'malicious': malicious,
           'suspicious': suspicious,
           'undetected': undetected,
           'timeout':timeout
          }
    
    return out