package org.bdinetwork.pulsaroauth2;

import org.apache.pulsar.broker.ServiceConfiguration;

public class OAuthConfiguration {

	static final String CONF_OAUTH_BROKER_CLIENT_ID = "oAuthBrokerClientId";
	static final String CONF_OAUTH_ORGANIZATION_ID_CONSUMER = "oAuthOrganizationId_consumer";
	static final String CONF_OAUTH_USECASE = "oAuthUseCase";
	static final String CONF_OAUTH_AUTHENTICATION_URL = "OAuthAuthenticationUrl";
	static final String CONF_TOKEN_PUBLIC_KEY = "tokenPublicKey";
	private ServiceConfiguration conf;


	public OAuthConfiguration(ServiceConfiguration configuration) {
		this.conf = configuration;
	}

	public String getClientId() {
		return (String) conf.getProperty(CONF_OAUTH_BROKER_CLIENT_ID);
	}

	public String getConsumerOrganizationId() {
		return (String) conf.getProperty(CONF_OAUTH_ORGANIZATION_ID_CONSUMER);
	}

	public String getUseCase() {
		String useCase = (String) conf.getProperty(CONF_OAUTH_USECASE);
		return useCase.substring(1, useCase.length() - 1);
	}

	public String getAuthenticationUrl() {
		String url = ((String) conf.getProperty(CONF_OAUTH_AUTHENTICATION_URL));
		//remove quotes
		return url.substring(1, url.length() - 1);
	}

	public String getTokenPublicKeyPath() {
		return (String) conf.getProperty(CONF_TOKEN_PUBLIC_KEY);
	}
}