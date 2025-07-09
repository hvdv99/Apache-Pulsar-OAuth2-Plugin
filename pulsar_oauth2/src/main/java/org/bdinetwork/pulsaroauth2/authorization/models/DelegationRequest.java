package org.bdinetwork.pulsaroauth2.authorization.models;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;

@JsonRootName(value = "delegationRequest")
public class DelegationRequest {
	@JsonProperty("policyIssuer")
	public @Nullable String PolicyIssuer;
	@JsonProperty("target")
	public @Nullable Delegation.TargetObject Target;
	@JsonProperty("policySets")
	public @Nullable ArrayList<Delegation.PolicySet> PolicySets;

	public DelegationRequest() {

	}

	public DelegationRequest(String subject, String resourceType, String resourceIdentifier, String resourceAttribute, String action, String policyIssuer, String serviceProviderId) {

		Delegation.TargetObject target = new Delegation.TargetObject();
		target.setAccessSubject(subject);

		Delegation.Resource resource = new Delegation.Resource();
		resource.setType(resourceType);
		resource.setIdentifiers(new ArrayList<>(Arrays.asList(resourceIdentifier)));
		resource.setAttributes(new ArrayList<>(Arrays.asList(resourceAttribute)));

		Delegation.Environment environment = new Delegation.Environment();
		environment.setServiceProviders(new ArrayList<>(Arrays.asList(serviceProviderId)));

		Delegation.TargetObject policyTarget = new Delegation.TargetObject();
		policyTarget.setResource(resource);
		policyTarget.setActions(new ArrayList<>(Arrays.asList(action)));
		policyTarget.setEnvironment(environment);

		Delegation.Rule rule = new Delegation.Rule();
		rule.setEffect("Permit");

		Delegation.Policy policy_1 = new Delegation.Policy();
		policy_1.setTarget(policyTarget);
		policy_1.setRules(new ArrayList<>(Arrays.asList(rule)));

		Delegation.PolicySet policySet = new Delegation.PolicySet();
		policySet.setPolicies(new ArrayList<>(Arrays.asList(policy_1)));

		this.setPolicyIssuer(policyIssuer);
		this.setTarget(target);
		this.setPolicySets(new ArrayList<>(Arrays.asList(policySet)));

	}

	@Nullable
	public String getPolicyIssuer() {
		return PolicyIssuer;
	}

	@Nullable
	public Delegation.TargetObject getTarget() {
		return Target;
	}

	@Nullable
	public ArrayList<Delegation.PolicySet> getPolicySets() {
		return PolicySets;
	}

	public void setPolicyIssuer(@Nullable String policyIssuer) {
		PolicyIssuer = policyIssuer;
	}

	public void setTarget(@Nullable Delegation.TargetObject target) {
		Target = target;
	}

	public void setPolicySets(@Nullable ArrayList<Delegation.PolicySet> policySets) {
		PolicySets = policySets;
	}
}