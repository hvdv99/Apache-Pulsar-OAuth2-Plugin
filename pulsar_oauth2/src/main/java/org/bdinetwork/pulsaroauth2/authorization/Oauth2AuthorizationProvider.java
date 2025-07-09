package org.bdinetwork.pulsaroauth2.authorization;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationDataSubscription;
import org.apache.pulsar.broker.authentication.utils.AuthTokenUtils;
import org.apache.pulsar.broker.authorization.AuthorizationProvider;
import org.apache.pulsar.broker.resources.PulsarResources;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.apache.pulsar.common.policies.data.PolicyName;
import org.apache.pulsar.common.policies.data.PolicyOperation;
import org.apache.pulsar.common.policies.data.TenantOperation;
import org.apache.pulsar.common.policies.data.TopicOperation;
import org.bdinetwork.pulsaroauth2.OAuthConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static java.util.Objects.requireNonNull;

public class Oauth2AuthorizationProvider implements AuthorizationProvider {
	static final String HTTP_HEADER_NAME = "Authorization";
	static final String HTTP_HEADER_VALUE_PREFIX = "Bearer ";
	private static final Logger log = LoggerFactory.getLogger(Oauth2AuthorizationProvider.class);
	protected PulsarResources pulsarResources;
	private JWTVerifier parser;
	private OAuthConfiguration oauthConfig;
	private String client_id;
	private String oAuthUseCase;
	private String oAuthUrl;
	private String tokenPublicKeyPath;

	private static boolean checkAuthorization(final String baseUrl, final String action, final String resource,
			final String subject, final String useCase, final String namespace) {
		boolean isAllowed = false;

		try {
			String url = String.format("%s?subject=%s&resource=%s&action=%s&usecase=%s&issuer=%s&serviceProvider=&type=&attribute=&context=",
					baseUrl, URLEncoder.encode(subject, StandardCharsets.UTF_8),
					URLEncoder.encode(resource, StandardCharsets.UTF_8),
					URLEncoder.encode(action, StandardCharsets.UTF_8),
					URLEncoder.encode(useCase, StandardCharsets.UTF_8),
					URLEncoder.encode(namespace, StandardCharsets.UTF_8));

			HttpClient client = HttpClient.newHttpClient();
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(url))
					.GET()
					.build();

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				String responseBody = response.body();
				ObjectMapper mapper = new ObjectMapper();
				Map responseMap = mapper.readValue(responseBody, Map.class);
				if (responseMap.containsKey("allowed")) {
					isAllowed = Boolean.parseBoolean(responseMap.get("allowed").toString());
				}
			} else {
				System.out.println("GET request failed with response code: " + response.statusCode());
			}
		} catch (IOException | InterruptedException e) {
			throw new RuntimeException(e);
		}

		return isAllowed;
	}

	public Oauth2AuthorizationProvider() {

	}

	public Oauth2AuthorizationProvider(ServiceConfiguration conf, PulsarResources resources)
			throws IOException {
		initialize(conf, resources);
	}

	@Override
	public void initialize(ServiceConfiguration conf, PulsarResources pulsarResources) throws IOException {
		requireNonNull(conf, "ServiceConfiguration can't be null");
		requireNonNull(pulsarResources, "PulsarResources can't be null");

		this.oauthConfig = new OAuthConfiguration(conf);
		this.client_id = oauthConfig.getClientId();
		this.oAuthUseCase = oauthConfig.getUseCase();
		this.oAuthUrl = oauthConfig.getAuthenticationUrl();
		this.tokenPublicKeyPath = oauthConfig.getTokenPublicKeyPath();

		final byte[] validationKey = AuthTokenUtils.readKeyFromUrl(tokenPublicKeyPath);
		PublicKey publicKey = AuthTokenUtils.decodePublicKey(validationKey, SignatureAlgorithm.RS256);
		Algorithm algorithm = Algorithm.RSA256((RSAKey) publicKey);

		parser = JWT.require(algorithm)
				.build();
	}

	@Override
	public void close() throws IOException {
		// No-op
	}

	@Override
	public CompletableFuture<Boolean> canProduceAsync(TopicName topicName, String role,
	                                                  AuthenticationDataSource authenticationData) {
		return checkAccess(authenticationData, "publish",
				topicName.getLocalName(), topicName.getNamespacePortion());
	}

	@Override
	public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role,
	                                                  AuthenticationDataSource authenticationData, String subscription) {
		return checkAccess(authenticationData, "subscribe",
				topicName.getLocalName(), topicName.getNamespacePortion());
	}

	@Override
	public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role,
	                                                 AuthenticationDataSource authenticationData) {
		CompletableFuture<Boolean> canConsume = canConsumeAsync(topicName, role, authenticationData, role);
		CompletableFuture<Boolean> canProduce = canProduceAsync(topicName, role, authenticationData);
		return canConsume.thenCombine(canProduce, (a, b) -> a || b);
	}

	@Override
	public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role,
	                                                        AuthenticationDataSource authenticationData) {
		return isBrokerAdmin(authenticationData);
	}

	@Override
	public CompletableFuture<Boolean> allowSourceOpsAsync(NamespaceName namespaceName, String role,
	                                                      AuthenticationDataSource authenticationData) {
		return isBrokerAdmin(authenticationData);
	}

	@Override
	public CompletableFuture<Boolean> allowSinkOpsAsync(NamespaceName namespaceName, String role,
	                                                    AuthenticationDataSource authenticationData) {
		return isBrokerAdmin(authenticationData);
	}

	@Override
	public CompletableFuture<Void> grantPermissionAsync(NamespaceName namespace, Set<AuthAction> actions, String role,
	                                                    String authDataJson) {
		if (log.isDebugEnabled()) {
			log.debug("Policies are read-only. Broker cannot do read-write operations");
		}
		throw new IllegalStateException("policies are in readonly mode");
	}

	@Override
	public CompletableFuture<Void> grantSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName,
	                                                                Set<String> roles, String authDataJson) {
		if (log.isDebugEnabled()) {
			log.debug("Policies are read-only. Broker cannot do read-write operations");
		}
		throw new IllegalStateException("policies are in readonly mode");
	}

	@Override
	public CompletableFuture<Void> revokeSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName,
	                                                                 String role, String authDataJson) {
		if (log.isDebugEnabled()) {
			log.debug("Policies are read-only. Broker cannot do read-write operations");
		}
		throw new IllegalStateException("policies are in readonly mode");
	}

	@Override
	public CompletableFuture<Void> grantPermissionAsync(TopicName topicName, Set<AuthAction> actions, String role,
	                                                    String authDataJson) {
		if (log.isDebugEnabled()) {
			log.debug("Policies are read-only. Broker cannot do read-write operations");
		}
		throw new IllegalStateException("policies are in readonly mode");
	}

	@Override
	public CompletableFuture<Boolean> allowNamespaceOperationAsync(NamespaceName namespaceName, String role,
	                                                               NamespaceOperation operation, AuthenticationDataSource authData) {
		return isBrokerAdmin(authData);
	}

	@Override
	public CompletableFuture<Boolean> allowNamespacePolicyOperationAsync(NamespaceName namespaceName, PolicyName policy,
	                                                                     PolicyOperation operation, String role, AuthenticationDataSource authData) {
		return isBrokerAdmin(authData);
	}

	@Override
	public CompletableFuture<Boolean> allowTenantOperationAsync(String tenantName, String role,
	                                                            TenantOperation operation, AuthenticationDataSource authData) {
		return isBrokerAdmin(authData);
	}

	@Override
	public CompletableFuture<Boolean> allowTopicOperationAsync(TopicName topic, String role, TopicOperation operation,
	                                                           AuthenticationDataSource authData) {
		try {
			CompletableFuture<Boolean> isBrokerAdmin = isBrokerAdmin(authData);

			switch (operation) {
				case CONSUME:
				case SUBSCRIBE:
					CompletableFuture<Boolean> canConsume = canConsumeAsync(topic, role, authData, "");
					return isBrokerAdmin.thenCombine(canConsume, (a, b) -> a || b);
				case PRODUCE:
					CompletableFuture<Boolean> canProduce = canProduceAsync(topic, role, authData);
					return isBrokerAdmin.thenCombine(canProduce, (a, b) -> a || b);
				default:
					return isBrokerAdmin;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return CompletableFuture.supplyAsync(() -> false);
	}

	@Override
	public CompletableFuture<Boolean> allowTopicPolicyOperationAsync(TopicName topic, String role, PolicyName policy,
	                                                                 PolicyOperation operation, AuthenticationDataSource authData) {
		return isBrokerAdmin(authData);
	}

	private String getToken(AuthenticationDataSource authenticationData) {
		String token = null;

		if (authenticationData.hasDataFromCommand()) {
			// Authenticate Pulsar binary connection
			token = authenticationData.getCommandData();
		} else if (authenticationData.hasDataFromHttp()) {
			// The format here should be compliant to RFC-6750
			// (https://tools.ietf.org/html/rfc6750#section-2.1). Eg: Authorization: Bearer
			// xxxxxxxxxxxxx
			String httpHeaderValue = authenticationData.getHttpHeader(HTTP_HEADER_NAME);
			if (httpHeaderValue != null && httpHeaderValue.startsWith(HTTP_HEADER_VALUE_PREFIX)) {
				// Remove prefix
				token = httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length());
			}
		} else if (authenticationData instanceof AuthenticationDataSubscription) {
			AuthenticationDataSubscription authDataSubscription = (AuthenticationDataSubscription) authenticationData;
			String httpHeaderValue = authDataSubscription.getAuthData().getHttpHeader(HTTP_HEADER_NAME);
			if (httpHeaderValue != null && httpHeaderValue.startsWith(HTTP_HEADER_VALUE_PREFIX)) {
				// Remove prefix
				token = httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length());
			}
		}

		return token;
	}

	private DecodedJWT parseToken(String jwtToken) {
		return parser.verify(jwtToken);
	}

	private CompletableFuture<Boolean> isBrokerAdmin(AuthenticationDataSource authenticationData) {
		try {
			String jwtToken = getToken(authenticationData);
			DecodedJWT claim = parseToken(jwtToken);

			String client_id = claim.getClaim("client_id").asString();
			if (client_id.equals(this.client_id)) {
				return CompletableFuture.supplyAsync(() -> true);
			}

			return CompletableFuture.supplyAsync(() -> false);

		} catch (Exception e) {
			log.info("Exception in  " + e.getMessage());
		}

		return CompletableFuture.supplyAsync(() -> false);
	}

	private CompletableFuture<Boolean> checkAccess(AuthenticationDataSource authenticationData, String action,
			String topicName, String namespace) {

		try {

			String jwtToken = getToken(authenticationData);
			DecodedJWT claim = parseToken(jwtToken);
			String organizationId = claim.getClaim("organizationId").asString();

			String useCase = this.oAuthUseCase;
			String url = this.oAuthUrl;

			boolean accessGranted = checkAuthorization(url, action, topicName, organizationId, useCase, namespace);

			if (accessGranted) {
				log.info("Client is authorised to access the topic");
			} else {
				log.info("Topic owner {} denied access to {} for topic {} to perform action {}", namespace,
						organizationId, topicName, action);
			}

			return CompletableFuture.supplyAsync(() -> accessGranted);

		} catch (Exception e) {
			log.info("Exception in  " + e.getMessage());
		}
		return CompletableFuture.supplyAsync(() -> false);
	}
}