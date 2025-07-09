import websockets
import token_provider
import asyncio
import base64
import json

async def connectProducer(broker_url, header, namespace, topic):

    print(f"Connecting producer to broker")

    producer_uri = f"ws://{broker_url}/ws/v2/producer/persistent/public/{namespace}/{topic}"

    async with websockets.connect(producer_uri, additional_headers=header) as websocket:
        print("connected to Pulsar websocket")
        while websocket.state == websockets.protocol.State.OPEN:
            send_task = asyncio.create_task(send(websocket))
            await send_task
            
            receive_task = asyncio.create_task(receive(websocket))
            await receive_task

        
async def send(websocket):
    print("sending message")
    payloadString = "This is a personal message for someone" 

    payloadString = payloadString.encode('utf-8')
    payloadString = base64.b64encode(payloadString)
    payloadString = payloadString.decode('UTF-8')

    pulsarMessageFormat = json.dumps({
        'payload' : payloadString
    })

    print('Send message:', pulsarMessageFormat)

    await websocket.send(pulsarMessageFormat)

    #Wait 5 seconds before sending the message again
    await asyncio.sleep(5)

async def receive(websocket):
    try:
        message = await asyncio.wait_for(websocket.recv(), timeout=0.1)
        print("Message received:", message)

        msg = json.loads(message)      
        if 'type' in msg and msg['type']=='AUTH_CHALLENGE':
            tokenN = token_provider.update_token.get_access_token(token_url, client_id, client_secret)
            jsondump = json.dumps({'type' : 'AUTH_RESPONSE', 'authResponse' : {'clientVersion' : 'v21', 'protocolVersion' : 21, 'response' : {'authMethodName':'token', 'authData': tokenN}}})
            print('Send messgae:', jsondump)
            await websocket.send(jsondump)
        elif 'result' in msg and msg['result'] == 'ok':
                print('.', end='')
        else:
            print('Failed to publish message:', message)
        
    except asyncio.TimeoutError:
        print("No Data")
    await asyncio.sleep(0.1)

if __name__ == "__main__":

    client_id = "kwuRHRvIbEQbgwLX9phvSnHEVfjeILxQ"
    client_secret = "KdC..."
    token_url = "https://topsector-logistiek.eu.auth0.com/oauth/token"

    token = token_provider.get_access_token(token_url, client_id, client_secret)

    broker_url = "localhost:8080"
    namespace = "NL.KVK.76660680"
    topic = "oauth2"
    
    header = {"Authorization": f"Bearer {token}"}

    asyncio.run(connectProducer(broker_url, header, namespace, topic))