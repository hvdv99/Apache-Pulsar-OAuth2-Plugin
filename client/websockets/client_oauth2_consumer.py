import asyncio
import base64
import json
import websockets
import token_provider

async def connectConsumer(broker_url, header, namespace, topic, subscription_name):
   
    print(f"Connecting consumer to broker")

    consumer_uri = f"ws://{broker_url}/ws/v2/consumer/persistent/public/{namespace}/{topic}/{subscription_name}"
    
    async with websockets.connect(consumer_uri, additional_headers=header) as websocket:
        print("Connected to Pulsar websocket")
        while websocket.state == websockets.protocol.State.OPEN:
            try:
                result = await websocket.recv()
                print("Received msg: {}".format(result))

                msg = json.loads(result)
                if not msg:
                    break

                if 'type' in msg and msg['type']=='AUTH_CHALLENGE':
                    tokenN = token_provider.get_access_token(token_url, client_id, client_secret)
                    jsondump = json.dumps({'type' : 'AUTH_RESPONSE', 'authResponse' : {'clientVersion' : 'v21', 'protocolVersion' : 21, 'response' : {'authMethodName':'token', 'authData': tokenN}}})

                    print('Send message:', jsondump)
                    await websocket.send(jsondump)
                else:
                    print( "Received msg: {}".format(base64.b64decode(msg['payload'])))
                    
                    # Send ack
                    await websocket.send(json.dumps({'messageId' : msg['messageId']}))

            except:
                print("Some error")

if __name__ == "__main__":
    client_id = "kwuRHRvIbEQbgwLX9phvSnHEVfjeILxQ"
    client_secret = "KdC..."
    token_url = "https://topsector-logistiek.eu.auth0.com/oauth/token"

    token = token_provider.get_access_token(token_url, client_id, client_secret)
    
    broker_url = "localhost:8080"
    namespace = "NL.KVK.76660680"
    topic = "oauth2"
    subscription_name = "consumer_oauth2"

    header = {"Authorization": f"Bearer {token}"}
    
    asyncio.run(connectConsumer(broker_url, header, namespace, topic, subscription_name))