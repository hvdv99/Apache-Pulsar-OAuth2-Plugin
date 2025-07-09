package org.bdinetwork.pulsaroauth2.authorization.models;


import com.fasterxml.jackson.annotation.JsonProperty;

import javax.annotation.Nullable;
import java.util.ArrayList;

public class Delegation {
	public static class PolicySet {
		@JsonProperty("maxDelegationDepth")
		public @Nullable int MaxDelegationDepth;
		@JsonProperty("target")
		public @Nullable TargetObject Target;
		@JsonProperty("policies")
		public @Nullable ArrayList<Policy> Policies;

		@Nullable
		public int getMaxDelegationDepth() {
			return MaxDelegationDepth;
		}

		@Nullable
		public TargetObject getTarget() {
			return Target;
		}

		@Nullable
		public ArrayList<Policy> getPolicies() {
			return Policies;
		}

		public void setMaxDelegationDepth(@Nullable int maxDelegationDepth) {
			MaxDelegationDepth = maxDelegationDepth;
		}

		public void setTarget(@Nullable TargetObject target) {
			Target = target;
		}

		public void setPolicies(@Nullable ArrayList<Policy> policies) {
			Policies = policies;
		}
	}

	public static class Policy {
		@JsonProperty("target")
		public @Nullable TargetObject Target;
		@JsonProperty("rules")
		public @Nullable ArrayList<Rule> Rules;

		@Nullable
		public TargetObject getTarget() {
			return Target;
		}

		@Nullable
		public ArrayList<Rule> getRules() {
			return Rules;
		}

		public void setTarget(@Nullable TargetObject target) {
			Target = target;
		}

		public void setRules(@Nullable ArrayList<Rule> rules) {
			Rules = rules;
		}
	}

	public static class Rule {
		@JsonProperty("effect")
		public @Nullable String Effect;

		@Nullable
		public String getEffect() {
			return Effect;
		}

		public void setEffect(@Nullable String effect) {
			Effect = effect;
		}
	}

	public static class Resource {
		@JsonProperty("type")
		public @Nullable String Type;
		@JsonProperty("identifiers")
		public @Nullable ArrayList<String> Identifiers;
		@JsonProperty("attributes")
		public @Nullable ArrayList<String> Attributes;

		@Nullable
		public String getType() {
			return Type;
		}

		@Nullable
		public ArrayList<String> getIdentifiers() {
			return Identifiers;
		}

		@Nullable
		public ArrayList<String> getAttributes() {
			return Attributes;
		}

		public void setType(@Nullable String type) {
			Type = type;
		}

		public void setIdentifiers(@Nullable ArrayList<String> identifiers) {
			Identifiers = identifiers;
		}

		public void setAttributes(@Nullable ArrayList<String> attributes) {
			Attributes = attributes;
		}
	}

	public static class Environment {
		@JsonProperty("licenses")
		public @Nullable ArrayList<String> Licenses;
		@JsonProperty("serviceProviders")
		public @Nullable ArrayList<String> ServiceProviders;

		@Nullable
		public ArrayList<String> getLicenses() {
			return Licenses;
		}

		@Nullable
		public ArrayList<String> getServiceProviders() {
			return ServiceProviders;
		}

		public void setLicenses(@Nullable ArrayList<String> licenses) {
			Licenses = licenses;
		}

		public void setServiceProviders(@Nullable ArrayList<String> serviceProviders) {
			ServiceProviders = serviceProviders;
		}
	}

	public static class TargetObject {
		@JsonProperty("accessSubject")
		public @Nullable String AccessSubject;
		@JsonProperty("environment")
		public @Nullable Environment Environment;
		@JsonProperty("resource")
		public @Nullable Resource Resource;
		@JsonProperty("actions")
		public @Nullable ArrayList<String> Actions;

		@Nullable
		public String getAccessSubject() {
			return AccessSubject;
		}

		@Nullable
		public Environment getEnvironment() {
			return Environment;
		}

		@Nullable
		public Resource getResource() {
			return Resource;
		}

		@Nullable
		public ArrayList<String> getActions() {
			return Actions;
		}

		public void setAccessSubject(@Nullable String accessSubject) {
			AccessSubject = accessSubject;
		}

		public void setEnvironment(@Nullable Environment environment) {
			Environment = environment;
		}

		public void setResource(@Nullable Resource resource) {
			Resource = resource;
		}

		public void setActions(@Nullable ArrayList<String> actions) {
			Actions = actions;
		}
	}

}