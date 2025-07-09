import requests

def get_access_token(token_url, client_id, client_secret):
    try:
        response = requests.post(token_url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": "TSL-Dataspace-CoreManager"
        })

        if response.status_code == 200:
            token = response.json().get("access_token")
            print(f"Access Token received")
            return token
        else:
            print(f"Failed to retrieve token: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None