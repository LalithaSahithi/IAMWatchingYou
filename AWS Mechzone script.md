#!/bin/bash
# ============================================================
# MechZone AWS Incident Investigation
# Compromised Identity: cloud-ops-intern
# ============================================================

echo ""
echo "============================================================"
echo " Q1: ARN of the compromised identity"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.userIdentity.userName == "cloud-ops-intern") |
  .userIdentity.arn
' | sort -u

echo ""
echo "============================================================"
echo " Q2: AWS service used to deploy malicious resources"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.userIdentity.userName == "cloud-ops-intern") |
  .eventSource
' | sort | uniq -c | sort -rn

echo ""
echo "============================================================"
echo " Q3: How many malicious compute resources were deployed"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.eventName == "RunInstances") |
  .responseElements.instancesSet.items[]?.instanceId
' | sort -u | wc -l

echo ""
echo "============================================================"
echo " Q4: Instance type of the deployed resources"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.eventName == "RunInstances") |
  .requestParameters.instanceType
' | sort -u

echo ""
echo "============================================================"
echo " Q5: IP CIDR range allowed for inbound access"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.eventName == "AuthorizeSecurityGroupIngress") |
  .requestParameters.ipPermissions.items[]?.ipRanges.items[]?.cidrIp
' | sort -u

echo ""
echo "============================================================"
echo " Q6: Port allowed for inbound access"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.eventName == "AuthorizeSecurityGroupIngress") |
  .requestParameters.ipPermissions.items[]? |
  [(.fromPort // "any" | tostring), (.toPort // "any" | tostring)] |
  @tsv
' | sort -u

echo ""
echo "============================================================"
echo " Q7: Protocol allowed for inbound access"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.eventName == "AuthorizeSecurityGroupIngress") |
  .requestParameters.ipPermissions.items[]?.ipProtocol
' | sort -u

echo ""
echo "============================================================"
echo " Q8: Malicious IAM username created"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(.eventName == "CreateUser") |
  .requestParameters.userName
' | sort -u

echo ""
echo "============================================================"
echo " Q9: IP address the attack originated from"
echo "============================================================"
cat *.json | jq -r '
  .Records[] |
  select(
    .eventName == "CreateUser" or
    .eventName == "RunInstances" or
    .eventName == "AuthorizeSecurityGroupIngress"
  ) |
  .sourceIPAddress
' | sort | uniq -c | sort -rn

echo ""
echo "============================================================"
echo " DONE - Paste output above for full investigation summary"
echo "============================================================"
