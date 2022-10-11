'''
For OpenSearch honeyfarm
API call to parse query to extract records of interest 
'''

import pandas as pd
import json
import requests
import config
import os

#columns of interest
COLS = ['peerIP',
        'peerPort',
        'hostIP',
        'hostPort',
        'commands',
        'hashes',
        'urls',
        'loggedin',
        'startTime',
        'endTime',
        'sort_num',
        'peerCountry',
        'hostCountry'
       ]

def osearch_load(size, queryls, search_after):
    # load basic json request
    json_file = open(os.getcwd()+"\\OS_json.txt")
    json_request = json.load(json_file)
    
    #update required query and params

    #size of each pull
    json_request['params']['body']['size'] = size
    
    #set continue search
    json_request['params']['body']['search_after'] = search_after
    
    # set command match
    json_request['params']['body']['query']['bool']['filter'] = queryls

    return json_request


def osearch_get(config, json_request):

    # log in to get session cookie
    headers = {
        'osd-xsrf': 'true',
        'content-type': 'application/json'
    }
    
    data = config.Opensearch_API_key
    response = requests.post('https://os.gcaaide.org/_dashboards/auth/login', headers=headers, json=data)
    cookie_key = response.headers['set-cookie'].split()[0]
    
    headers = {
        'osd-xsrf': 'true',
        'content-type': 'application/json',
        'cookie': cookie_key
    }
    # take the session cookie and do search based on parameters required.
    response = requests.post('https://os.gcaaide.org/_dashboards/internal/search/opensearch', headers=headers,
                             json=json_request)
    print(response)
    response_json = response.content.decode('utf-8').replace('\0', '')
    
    return response_json


def opensearch_output(response_json):
    
    struct = json.loads(response_json)
    #print('struct', struct)
    #print(f"Total hits: {struct['rawResponse']['hits']['total']}")

    df = pd.json_normalize(struct)

    test = df['rawResponse.hits.hits'][0]
    #print('test', test)
    df1 = pd.json_normalize(test)
    #print(df1)
    
    if len(df1)==0:
        print("There is no valid data")
        output = pd.DataFrame(None, columns = COLS)
        return output

    try:
        #normal output
        print("Output success")
        output = df1[['_source.peerIP',
                      '_source.peerPort',                  
                      '_source.hostIP',
                      '_source.hostPort',
                      '_source.commands',
                      '_source.hashes',
                      '_source.urls',
                      '_source.loggedin',
                      '_source.startTime',
                      '_source.endTime',
                      'sort',
                      '_source.geoip.country_code2',
                      '_source.hostGeoip.country_code2'
                     ]]
    
    except:
        #host country not available before ~August 20th 2022
        print("Data is before August 20th 2022, no hostCountry data")
        output = df1[['_source.peerIP',
                      '_source.peerPort',                  
                      '_source.hostIP',
                      '_source.hostPort',
                      '_source.commands',
                      '_source.hashes',
                      '_source.urls',
                      '_source.loggedin',
                      '_source.startTime',
                      '_source.endTime',
                      'sort',
                      '_source.geoip.country_code2'
                     ]]
        output.loc[:,'hostCountry'] = None  
    
    output.columns = COLS

    return output


def opensearch_request(size, queryls, search_after):

    json_request = osearch_load(size, queryls, search_after)
    response_json = osearch_get(config, json_request)
    output = opensearch_output(response_json)
    
    return output
    
    