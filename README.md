# Introduction 
This repository contains an Authorisation plugin for Apache Pulsar to support the oAuth2 method for authorisation. An external provider for the access token can be used. In this case the external provider is Poort8, but another provider could be configured as well.

# Getting Started
### 1.	Build the Docker image 

Build the Docker image within the same directory as the Dockerfile: 
```
$ docker build -t cgi/pulsar:4.0.3 .
```
The Dockerfile contains information to build the image on a laptop that is protected by Zscaler. Therefore it is necessary to include the ZscalerRootCertificate within the same directory as the Dockerfile.

### 2a.	Prepare the config file for Authentication

In the standalone.conf file set the following information. In this case the information for the Topsector Logisitiek Noodlebar is provided, but another provider could also be used.

```
# Enable authentication
authenticationEnabled=true
authenticationProviders=org.apache.pulsar.broker.authentication.AuthenticationProviderToken
tokenPublicKey=file:///pulsar/keys/public-key.der

# Authentication settings of the broker itself. Used when the broker connects to other brokers,
# either in same or other clusters
brokerClientAuthenticationPlugin=org.apache.pulsar.client.impl.auth.oauth2.AuthenticationOAuth2
brokerClientAuthenticationParameters={"privateKey":"file:///pulsar/keys/credentials_file.json","audience":"TSL-Dataspace-CoreManager","issuerUrl":"https://poort8.eu.auth0.com"}
```
Place the tokenPublicKey in the volumes/keys folder. The Public Key can be extracted from the access token provided by the provider, for instance, by inspecting the access token's data using jwt.io.. Ensure it is supplied in .der format.

The brokerClientAuthenticationParameters should be configured as follows: 
- Include a credentials_file.json in the volumes/keys folder that include the following variables:

```
{ 
    "client_id": "",
    "client_secret": ""
}
```
- The audience and the issueUrl can be retrieved from the received access token. 

### 2b.	Prepare the config file for Authorization

When Authorization is needed, the standalone.conf file must also contain the following information: 

```
# Enforce authorization
authorizationEnabled=true

# Authorization provider fully qualified class-name
authorizationProvider=org.bdinetwork.pulsaroauth2.authorization.Oauth2AuthorizationProvider

# Oauth configuration parameters
oAuthBrokerClientId=o3kUDUJVShcrOaLxT4WT76nOLQwu5aPc
oAuthUseCase="hwct"
OAuthAuthenticationUrl="https://tsl-dataspace-coremanager.azurewebsites.net/api/authorization/enforce"

```
The Oauth configuration parameters depend on the authorisation provider that is used and the information that is validated in the plugin. In this case the ClientId is validated when the BrokerAdmin is validated.

### 3.	Run the Apache Pulsar Broker with the OAuth2 authorisation plugin

```
docker run --name "ApachePulsar" -it -p 6650:6650 -p 8080:8080 -v "$(pwd)/volumes/conf:/pulsar/conf" -v "$(pwd)/volumes/keys:/pulsar/keys" cgi/pulsar:4.0.3 /pulsar/bin/pulsar standalone
```

### 4.	Create the namespace
Every organisation has their own namespace. Create a namespace with the organistation id as registered in the association register. (such as 'NL.KVK.76660680')

1. Get the token of the broker admin
2. Create new namespace:
   - action: PUT 
   - url: {url}/admin/v2/namespaces/public/{namespace} 
   - Headers: Authorisation: Bearer {token}


# Test

For testing purposes there are two organizations made on https://tsl-dataspace-coremanager.azurewebsites.net/: 

- CGI 
- CGI consumer

Both organizations have one application with their own clientId and clientSecret. The first organization is used for the broker communication. The second one is used for the consumer and the producer. The CGI consumer application has the following policies: 

- topic: oauth2, action: subscribe, usecase: hwct
- topic: oauth2, action: publish, usecase: hwct

Run client_oauth2_producer.py program to send messages. Run client_oauth_consumer.py in a different terminal to receive the messages. When changing the topic that the consumer wants to subscribe on you can demonstrate that the consumer can only subscribe to the oauth2 topic.

# Using another token provider

When using a different token provider make sure to change the following parts of the application: 

- standalone.conf
   - brokerClientAuthenticationParameters
   - tokenPublicKey
   - all Oauth configuration parameters

- Oauth2AuthorizationProvider: 
   - Method isBrokerAdmin: the getClaim parameter for client_id could have a different name. It is also possible to check for the BrokerAdmin with different parameters.
   - Method checkAccess: the way to check which authentication applies to a certain client depends on the provider used. In this case a Get Request should be made, but it is also possible that the authentication information is already present in the token