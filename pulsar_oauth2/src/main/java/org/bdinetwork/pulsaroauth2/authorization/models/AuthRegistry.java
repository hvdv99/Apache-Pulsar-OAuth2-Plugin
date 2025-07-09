package org.bdinetwork.pulsaroauth2.authorization.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.annotation.Nullable;

public class AuthRegistry {
	@JsonProperty("authorizationRegistryName")
	public @Nullable String AuthorizationRegistryName;
	@JsonProperty("authorizationRegistryID")
	public @Nullable String AuthorizationRegistryID;
	@JsonProperty("authorizationRegistryUrl")
	public @Nullable String AuthorizationRegistryUrl;
	@JsonProperty("dataspaceID")
	public @Nullable String DataspaceID;
	@JsonProperty("dataspaceName")
	public @Nullable String DataspaceName;

	public AuthRegistry() {

	}

	public AuthRegistry(String authorizationRegistryID, String authorizationRegistryUrl) {
		this.AuthorizationRegistryID = authorizationRegistryID;
		this.AuthorizationRegistryUrl = authorizationRegistryUrl;
	}

	@Nullable
	public String getAuthorizationRegistryName() {
		return AuthorizationRegistryName;
	}

	@Nullable
	public String getAuthorizationRegistryID() {
		return AuthorizationRegistryID;
	}

	@Nullable
	public String getAuthorizationRegistryUrl() {
		return AuthorizationRegistryUrl;
	}

	@Nullable
	public String getDataspaceID() {
		return DataspaceID;
	}

	public String getDataspaceName() {
		return DataspaceName;
	}

	public void setAuthorizationRegistryName(@Nullable String authorizationRegistryName) {
		AuthorizationRegistryName = authorizationRegistryName;
	}

	public void setAuthorizationRegistryID(@Nullable String authorizationRegistryID) {
		AuthorizationRegistryID = authorizationRegistryID;
	}

	public void setAuthorizationRegistryUrl(@Nullable String authorizationRegistryUrl) {
		AuthorizationRegistryUrl = authorizationRegistryUrl;
	}

	public void setDataspaceID(@Nullable String dataspaceID) {
		DataspaceID = dataspaceID;
	}

	@Nullable
	public void setDataspaceName(@Nullable String dataspaceName) {
		DataspaceName = dataspaceName;
	}
}
