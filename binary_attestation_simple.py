# For testing the api

import requests

# Base URL of the API or web service
url = 'http://127.0.0.1:5000/signature'

# Dictionary of query parameters to send with the GET request
params = {
    'package': 'ls',
    'version': '3',
    'system': 'fedora'
}

try:
    # Send the GET request with query parameters
    response = requests.get(url, params=params)
    
    # Check if the request was successful
    if response.status_code == 200:
        # Print the content of the response
        print("Response Content:")
        print(response.text)
    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")
except requests.RequestException as e:
    print(f"An error occurred: {e}")
    