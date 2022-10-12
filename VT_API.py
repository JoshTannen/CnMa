#import file where api key is stored at
import config
import requests
import json

def api_call_virustotal(query):
    
    api_key = config.virustotal_api_key
    api_url = "https://www.virustotal.com/api/v3/search?query=" + query
    headers = {
        "Accept": "application/json",
        "x-apikey": config.virustotal_api_key
    }
    response = requests.get(api_url, headers=headers)
    
    return response


def read_response(response, query):
    '''
    returns a dictionary with flagged ratio, engines flagged and quantity for each reponse
    '''
    #pull information
    j_data = json.loads(response.text)
    info = j_data['data']
    
    #stats infomation from info
    try:
        stats = info[0]['attributes']['last_analysis_stats']
        
    except IndexError:
        #exit when 
        print(f"No valid results for {query}")
        return {'query_input': query
               }

    harmless = stats.get('harmless', 0)
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    timeout = stats.get('timeout', 0)
    stats_output = (malicious + suspicious) / (malicious + suspicious + harmless + undetected + timeout)
    
    
    #getting engine names from info
    data = info[0]['attributes']['last_analysis_results']

    mal_list = []
    for i in data:
        if data[i]['category'] == 'malicious':
            mal_list.append(data[i]['engine_name'])
    
    out = {'query_input': query,
           'stats_output': stats_output,
           'engines_flagged': mal_list,
           'harmless': harmless,
           'malicious': malicious,
           'suspicious': suspicious,
           'undetected': undetected,
           'timeout':timeout
          }
    
    return out


def virustotal_request(query):
    response = api_call_virustotal(query)
    out = read_response(response, query)
    
    return out