package elbsvc

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elbv2"
)

const (
	ELBActiveMaxWait  = 120 * time.Second
	ELBDeletedMaxWait = 120 * time.Second
	ELBSchemeInternet = "internet-facing"
	ELBSchemeInternal = "internal"
)

// NewLoadBalancer specifies a new ELBv2 application load balancer
type NewLoadBalancer struct {
	// A unique name for the load balancer.
	// Maximum of 32 characters, must contain only alphanumeric characters or
	// hyphens and cannot begin or end with a hyphen.
	Name string
	// The type of load balancer (internal|internet-facing).
	Scheme string
	// The ID of the security group to assign to the load balancer
	SecurityGroup string
	// The IDs of the subnets to attach to the load balancer. Must specify
	// only one subnet per Availability Zone. Must specify subnets from at
	// least two Availability Zones.
	Subnets []string
	// Tags to assign to the load balancer.
	Tags map[string]string
	// Enable storing of access logs in Amazon S3.
	AccessLogsS3Enabled bool
	// The name of the S3 bucket for the access logs. The bucket must exist in
	// the same region as the load balancer and have a bucket policy that grants
	// Elastic Load Balancing permission to write to the bucket.
	AccessLogsS3Bucket string
	// The optional prefix for the location in the S3 bucket.
	AccessLogsS3Prefix string
	// The idle timeout of the load balancer in seconds.
	IdleTimoutSeconds int
}

// LoadBalancerInfo represents an existing ELBv2 application load balancer
type LoadBalancerInfo struct {
	// The name of the load balancer.
	Name string
	// The Amazon Resource Name (ARN) of the load balancer.
	LoadBalancerArn string
	// The type of load balancer: (internal|internet-facing).
	Scheme string
	// The public DNS name of the load balancer.
	DNSName string
	// The ID of the security groups assigned to the load balancer.
	SecurityGroups []string
	// The ID of the VPC the load balancer was created in.
	VpcID string
	// The Availability Zones for the load balancer.
	// [ZoneName]SubnetID
	AvailabilityZones map[string]string
	// The tags of the load balancer.
	Tags map[string]string
	// The state of the load balancer: provisioning|active|failed.
	State string
	// The listeners of the load balancer
	Listeners []*Listener
}

// Listener represents an ELBv2 listener
type Listener struct {
	// The Amazon Resource Name (ARN) of the listener.
	ListenerArn string
	// Port on which the load balancer is listening.
	Port int64
	// Front-end protocol to use: HTTP|HTTPS.
	Protocol string
	// The Amazon Resource Name (ARN) of the SSL certificate.
	// Required if the protocol is HTTPS.
	CertificateArn string
	// The backends to which the load balancer forwards requests.
	Backends []*Backend
}

// Backend represents an ELBv2 target group
type Backend struct {
	// Whether this is the default target group.
	IsDefault bool
	// The priority of this backend.
	Priority int64
	// The Name of the target group.
	TargetGroupName string
	// The ARN of the target group.
	TargetGroupArn string
	// The ARN of the rule that associates the target group with the listener.
	RuleArn string
	// Tags assigned to the target group.
	Tags map[string]string
	// Backend protocol to use: HTTP, HTTPS.
	BackendProtocol string
	// The port on which the backend is listening.
	BackendPort int64
	// The IDs of the EC2 instances registered to this backend.
	Instances []string
	// The path pattern to match for requests to be forwarded to this backend.
	PathPattern string
	// Whether Sticky Sessions are enabled for this target group.
	StickySessions bool
}

/*
 * Load Balancer
 */

// GetLoadBalancerByName returns the LoadBalancerInfo describing the specified
// load balancer. Returns nil if the load balancer was not found.
func (svc *ELBService) GetLoadBalancerByName(name string) (*LoadBalancerInfo, error) {
	logrus.Debugf("GetLoadBalancerByName => name: %s", name)

	resp, err := svc.GetLoadBalancers(name)
	if err != nil {
		if IsAWSErr(err, AWSErrLoadBalancerNotFound) {
			return nil, nil
		}
		return nil, err
	}

	if len(resp) > 0 {
		return resp[0], nil
	}

	return nil, nil
}

// GetLoadBalancers returns the LoadBalancerInfo structs describing the specified
// load balancers. If invoked without the argument, all load balancers are returned.
func (svc *ELBService) GetLoadBalancers(names ...string) ([]*LoadBalancerInfo, error) {
	logrus.Debugf("GetLoadBalancers => names: %v", names)

	var loadBalancers []*LoadBalancerInfo

	params := &elbv2.DescribeLoadBalancersInput{}
	if len(names) > 0 {
		awsNames := make([]*string, len(names))
		for i, n := range names {
			awsNames[i] = aws.String(n)
		}
		params.Names = awsNames
	}

	resp, err := svc.elbv2c.DescribeLoadBalancers(params)
	if err != nil {
		return nil, err
	}
	awsLoadBalancers := resp.LoadBalancers

	if len(awsLoadBalancers) == 0 {
		return loadBalancers, nil
	}

	awsArns := make([]*string, len(awsLoadBalancers))
	for i, awsLb := range awsLoadBalancers {
		awsArns[i] = awsLb.LoadBalancerArn
	}

	tagDescriptions, err := svc.describeResourceTags(awsArns)
	if err != nil {
		return nil, fmt.Errorf("Failed to get load balancer tags: %v", err)
	}

	arnToTags := make(map[string][]*elbv2.Tag)
	for _, td := range tagDescriptions {
		arnToTags[*td.ResourceArn] = td.Tags
	}

	for _, awsLb := range awsLoadBalancers {
		securityGroups := make([]string, len(awsLb.SecurityGroups))
		for i, id := range awsLb.SecurityGroups {
			securityGroups[i] = *id
		}

		azSubnet := make(map[string]string)
		for _, az := range awsLb.AvailabilityZones {
			azSubnet[*az.ZoneName] = *az.SubnetId
		}

		tags := make(map[string]string)
		if elbTags, ok := arnToTags[*awsLb.LoadBalancerArn]; ok {
			tags = mapTags(elbTags)
		}

		listeners, err := svc.GetLoadBalancerListeners(*awsLb.LoadBalancerArn)
		if err != nil {
			return nil, fmt.Errorf("Failed to get listeners for %s: %v", *awsLb.LoadBalancerName, err)
		}

		loadBalancer := &LoadBalancerInfo{
			Name:              *awsLb.LoadBalancerName,
			LoadBalancerArn:   *awsLb.LoadBalancerArn,
			Scheme:            *awsLb.Scheme,
			DNSName:           *awsLb.DNSName,
			SecurityGroups:    securityGroups,
			VpcID:             *awsLb.VpcId,
			AvailabilityZones: azSubnet,
			Tags:              tags,
			State:             *awsLb.State.Code,
			Listeners:         listeners,
		}

		loadBalancers = append(loadBalancers, loadBalancer)
	}

	logrus.Debugf("GetLoadBalancers => returning %d load balancers", len(loadBalancers))
	return loadBalancers, nil
}

// GetLoadBalancerListeners returns the Listener struct for the specified load balancer ARN.
func (svc *ELBService) GetLoadBalancerListeners(loadBalancerArn string) ([]*Listener, error) {
	logrus.Debugf("GetLoadBalancerListeners => loadBalancerArn: %s", loadBalancerArn)

	var listeners []*Listener
	params := &elbv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(loadBalancerArn),
		PageSize:        aws.Int64(400),
	}
	resp, err := svc.elbv2c.DescribeListeners(params)
	if err != nil {
		return listeners, fmt.Errorf("DescribeListeners SDK error: %v", err)
	}

	if len(resp.Listeners) == 0 {
		return listeners, nil
	}
	for _, awsListener := range resp.Listeners {
		var certificateArn string
		if len(awsListener.Certificates) > 0 {
			certificateArn = *awsListener.Certificates[0].CertificateArn
		}

		listener := &Listener{
			ListenerArn:    *awsListener.ListenerArn,
			Port:           *awsListener.Port,
			Protocol:       *awsListener.Protocol,
			CertificateArn: certificateArn,
		}

		var backends []*Backend
		var targetGroupsArns []*string

		rules, err := svc.describeListenerRules(*awsListener.ListenerArn)
		if err != nil {
			return listeners, err
		}

		for _, r := range rules {
			var pathRule string
			for _, c := range r.Conditions {
				if *c.Field == "path-pattern" {
					pathRule = *c.Values[0]
					break // TODO: support multiple path patterns?
				}
			}
			var tgArn string
			for _, a := range r.Actions {
				if *a.Type == elbv2.ActionTypeEnumForward {
					tgArn = *a.TargetGroupArn
					break
				}
			}
			if tgArn == "" {
				continue
			}

			var priority int64
			if *r.IsDefault {
				priority = int64(0)
			} else {
				priority, err = strconv.ParseInt(*r.Priority, 10, 64)
				if err != nil {
					return listeners, fmt.Errorf("While parsing rule priority to integer: %v", err)
				}
			}

			b := &Backend{
				TargetGroupArn: tgArn,
				RuleArn:        *r.RuleArn,
				IsDefault:      *r.IsDefault,
				PathPattern:    pathRule,
				Priority:       priority,
			}
			backends = append(backends, b)
			targetGroupsArns = append(targetGroupsArns, &tgArn)
		}

		// get the target group details
		targetGroups, err := svc.describeTargetGroups(targetGroupsArns)
		if err != nil {
			return listeners, err
		}

		arnToTargetGroup := make(map[string]*elbv2.TargetGroup)
		for _, tg := range targetGroups {
			arnToTargetGroup[*tg.TargetGroupArn] = tg
		}

		// get the targets registered to each of the target groups
		arnToTargets := make(map[string][]*elbv2.TargetDescription)
		for arn, _ := range arnToTargetGroup {
			targets, err := svc.describeRegisteredTargets(arn)
			if err != nil {
				return listeners, err
			}
			arnToTargets[arn] = targets
		}

		// get the tags for the target groups
		tagDescriptions, err := svc.describeResourceTags(targetGroupsArns)
		if err != nil {
			return nil, fmt.Errorf("While getting target group tags: %v", err)
		}

		arnToTags := make(map[string][]*elbv2.Tag, len(tagDescriptions))
		for _, td := range tagDescriptions {
			arnToTags[*td.ResourceArn] = td.Tags
		}

		// add the target group details to the backend structs
		for _, be := range backends {
			if tg, ok := arnToTargetGroup[be.TargetGroupArn]; ok {
				be.BackendProtocol = *tg.Protocol
				be.BackendPort = *tg.Port
				be.TargetGroupName = *tg.TargetGroupName
			}

			if elbTags, ok := arnToTags[be.TargetGroupArn]; ok {
				be.Tags = mapTags(elbTags)
			}

			if targets, ok := arnToTargets[be.TargetGroupArn]; ok {
				var ids []string
				for _, t := range targets {
					ids = append(ids, *t.Id)
				}
				be.Instances = ids
			}

			sticky, err := svc.GetTargetGroupStickiness(be.TargetGroupArn)
			if err != nil {
				return nil, err
			}
			be.StickySessions = sticky
		}

		listener.Backends = backends
		listeners = append(listeners, listener)
	}

	return listeners, nil
}

// CreateLoadBalancer creates an ELBv2 load balancer and returns it's information.
func (svc *ELBService) CreateLoadBalancer(newLb *NewLoadBalancer) (*LoadBalancerInfo, error) {
	logrus.Debugf("CreateLoadBalancer => newLb: %v", newLb)

	subnets := make([]*string, len(newLb.Subnets))
	for i, sn := range newLb.Subnets {
		subnets[i] = aws.String(sn)
	}

	elbTags := elbTags(newLb.Tags)
	var awsSecurityGroups []*string
	if len(newLb.SecurityGroup) > 0 {
		awsSecurityGroups = append(awsSecurityGroups, aws.String(newLb.SecurityGroup))
	}

	params := &elbv2.CreateLoadBalancerInput{
		Name:           aws.String(newLb.Name),
		Subnets:        subnets,
		Scheme:         aws.String(newLb.Scheme),
		SecurityGroups: awsSecurityGroups,
		Tags:           elbTags,
	}
	resp, err := svc.elbv2c.CreateLoadBalancer(params)
	if err != nil {
		return nil, fmt.Errorf("CreateLoadBalancer SDK error: %v", err)
	}

	// This should never happen but well...
	if len(resp.LoadBalancers) == 0 {
		return nil, fmt.Errorf("Unexpected API response while creating load balancer")
	}

	awsLb := resp.LoadBalancers[0]
	// Wait for load balancer to become active
	//logrus.Infof("Waiting for load balancer '%s' to become active...", newLb.Name)
	//if err := svc.waitLoadBalancerActive(*awsLb.LoadBalancerArn); err != nil {
	//	return nil, err
	//}

	securityGroups := make([]string, len(awsLb.SecurityGroups))
	for i, id := range awsLb.SecurityGroups {
		securityGroups[i] = *id
	}

	azSubnet := make(map[string]string)
	for _, az := range awsLb.AvailabilityZones {
		azSubnet[*az.ZoneName] = *az.SubnetId
	}

	lbInfo := &LoadBalancerInfo{
		Name:              *awsLb.LoadBalancerName,
		LoadBalancerArn:   *awsLb.LoadBalancerArn,
		Scheme:            *awsLb.Scheme,
		DNSName:           *awsLb.DNSName,
		SecurityGroups:    securityGroups,
		VpcID:             *awsLb.VpcId,
		AvailabilityZones: azSubnet,
		State:             *awsLb.State.Code,
	}

	params2 := &elbv2.ModifyLoadBalancerAttributesInput{
		LoadBalancerArn: aws.String(lbInfo.LoadBalancerArn),
	}

	if newLb.AccessLogsS3Enabled && newLb.AccessLogsS3Bucket != "" {
		logrus.Debugf("Enabling access logs for ELB %s using S3 bucket %s",
			newLb.Name, newLb.AccessLogsS3Bucket)
		attributes := []*elbv2.LoadBalancerAttribute{
			{
				Key:   aws.String("access_logs.s3.enabled"),
				Value: aws.String("true"),
			},
			{
				Key:   aws.String("access_logs.s3.bucket"),
				Value: aws.String(newLb.AccessLogsS3Bucket),
			},
			{
				Key:   aws.String("access_logs.s3.prefix"),
				Value: aws.String(newLb.AccessLogsS3Prefix),
			},
		}
		params2.Attributes = append(params2.Attributes, attributes...)
	}

	if newLb.IdleTimoutSeconds > 0 {
		logrus.Debugf("Setting idle timeout for ELB %s to %d seconds",
			newLb.Name, newLb.IdleTimoutSeconds)
		idleTimeout := strconv.FormatInt(int64(newLb.IdleTimoutSeconds), 10)
		params2.Attributes = append(params2.Attributes, &elbv2.LoadBalancerAttribute{
			Key:   aws.String("idle_timeout.timeout_seconds"),
			Value: aws.String(idleTimeout),
		})
	}

	if len(params2.Attributes) > 0 {
		_, err = svc.elbv2c.ModifyLoadBalancerAttributes(params2)
		if err != nil {
			return nil, fmt.Errorf("ModifyLoadBalancerAttributes SDK error: %v", err)
		}
	}

	return lbInfo, nil
}

// DeleteLoadBalancer deletes the load balancer for the specified ARN.
func (svc *ELBService) DeleteLoadBalancer(loadBalancerArn string) error {
	params := &elbv2.DeleteLoadBalancerInput{
		LoadBalancerArn: aws.String(loadBalancerArn),
	}
	_, err := svc.elbv2c.DeleteLoadBalancer(params)
	if err != nil {
		return fmt.Errorf("DeleteLoadBalancer SDK error: %v", err)
	}

	return nil
}

// SetLoadBalancerSubnets enables the specified subnets for the specified load balancer.
func (svc *ELBService) SetLoadBalancerSubnets(loadBalancerArn string, subnetIds []string) error {
	logrus.Debugf("SetLoadBalancerSubnets => loadBalancerArn: %s, subnetsIds: %v",
		loadBalancerArn, subnetIds)

	awsSubnets := make([]*string, len(subnetIds))
	for i, id := range subnetIds {
		awsSubnets[i] = aws.String(id)
	}
	params := &elbv2.SetSubnetsInput{
		LoadBalancerArn: aws.String(loadBalancerArn),
		Subnets:         awsSubnets,
	}
	_, err := svc.elbv2c.SetSubnets(params)
	if err != nil {
		return fmt.Errorf("SetSubnets SDK error: %v", err)
	}

	return nil
}

// SetLoadBalancerSecurityGroups associates the specified security groups with the specified load balancer.
func (svc *ELBService) SetLoadBalancerSecurityGroups(loadBalancerArn string, securityGroupIds []string) error {
	logrus.Debugf("SetLoadBalancerSecurityGroups => loadBalancerArn: %s, securityGroupIds: %v",
		loadBalancerArn, securityGroupIds)

	awsIds := make([]*string, len(securityGroupIds))
	for i, id := range securityGroupIds {
		awsIds[i] = aws.String(id)
	}
	params := &elbv2.SetSecurityGroupsInput{
		LoadBalancerArn: aws.String(loadBalancerArn),
		SecurityGroups:  awsIds,
	}
	_, err := svc.elbv2c.SetSecurityGroups(params)
	if err != nil {
		return fmt.Errorf("SetSecurityGroupsSDK error: %v", err)
	}

	return nil
}

/*
 * Listeners
 */

// CreateListener creates a new listener for the specified load balancer using
// the specified parameters. It returns the ARN of the created listener.
func (svc *ELBService) CreateListener(loadBalancerArn, defaultTargetGroupArn, protocol string,
	port int64, certificateArn string) (string, error) {
	logrus.Debugf("createListener => loadBalancerArn: %s, tgArn: %s, port: %d, protocol: %s, cert: %s",
		loadBalancerArn, defaultTargetGroupArn, port, protocol, certificateArn)

	var certificates []*elbv2.Certificate
	if len(certificateArn) > 0 {
		certificates = append(certificates, &elbv2.Certificate{
			CertificateArn: aws.String(certificateArn),
		})
	}
	params := &elbv2.CreateListenerInput{
		DefaultActions: []*elbv2.Action{
			{
				TargetGroupArn: aws.String(defaultTargetGroupArn),
				Type:           aws.String(elbv2.ActionTypeEnumForward),
			},
		},
		LoadBalancerArn: aws.String(loadBalancerArn),
		Port:            aws.Int64(port),
		Protocol:        aws.String(protocol),
		Certificates:    certificates,
	}

	resp, err := svc.elbv2c.CreateListener(params)
	if err != nil {
		return "", fmt.Errorf("CreateListener SDK error: %v", err)
	}

	if len(resp.Listeners) == 0 {
		return "", fmt.Errorf("Unexpected API response while creating listener")
	}

	return *resp.Listeners[0].ListenerArn, nil
}

// DeleteListener removes the specified listener from the ELB.
func (svc *ELBService) DeleteListener(listenerArn string) error {
	logrus.Debugf("deleteListener => listenerArn: %s", listenerArn)

	params := &elbv2.DeleteListenerInput{
		ListenerArn: aws.String(listenerArn),
	}
	_, err := svc.elbv2c.DeleteListener(params)
	if err != nil {
		return fmt.Errorf("DeleteListener SDK error: %v", err)
	}

	return nil
}

// CreateListenerPathRule creates a path-based forward rule for the specified listener.
func (svc *ELBService) CreateListenerPathRule(listenerArn, targetGroupArn, pathPattern string,
	priority int64) error {
	logrus.Debugf("createListenerPathRule => listener: %s targetGroup: %s pathPattern: %s priority: %d",
		listenerArn, targetGroupArn, pathPattern, priority)

	params := &elbv2.CreateRuleInput{
		Actions: []*elbv2.Action{
			{
				TargetGroupArn: aws.String(targetGroupArn),
				Type:           aws.String(elbv2.ActionTypeEnumForward),
			},
		},
		Conditions: []*elbv2.RuleCondition{
			{
				Field: aws.String("path-pattern"),
				Values: []*string{
					aws.String(pathPattern),
				},
			},
		},
		ListenerArn: aws.String(listenerArn),
		Priority:    aws.Int64(priority),
	}
	_, err := svc.elbv2c.CreateRule(params)
	if err != nil {
		return fmt.Errorf("CreateRule SDK error: %v", err)
	}

	return nil
}

// DeleteListenerRule deletes the specified listener rule.
func (svc *ELBService) DeleteListenerRule(ruleArn string) error {
	logrus.Debugf("DeleteListenerRule => ruleArn: %s", ruleArn)

	params := &elbv2.DeleteRuleInput{
		RuleArn: aws.String(ruleArn),
	}
	_, err := svc.elbv2c.DeleteRule(params)
	if err != nil && !IsAWSErr(err, AWSErrRuleNotFound) {
		return fmt.Errorf("DeleteRule SDK error: %v", err)
	}

	return nil
}

// ModifyListenerRulePathPattern modifies the path pattern for the specified rule Arn.
func (svc *ELBService) ModifyListenerRulePathPattern(ruleArn, pathPattern string) error {
	logrus.Debugf("ModifyListenerRulePathPattern => ruleArn: %s pattern: %s",
		ruleArn, pathPattern)

	params := &elbv2.ModifyRuleInput{
		RuleArn: aws.String(ruleArn),
		Conditions: []*elbv2.RuleCondition{
			{
				Field: aws.String("path-pattern"),
				Values: []*string{
					aws.String(pathPattern),
				},
			},
		},
	}

	_, err := svc.elbv2c.ModifyRule(params)
	if err != nil {
		return fmt.Errorf("ModifyRule SDK error: %v", err)
	}

	return nil
}

// returns the elbv2.Rule struct for the specified listener.
func (svc *ELBService) describeListenerRules(listenerArn string) ([]*elbv2.Rule, error) {
	params := &elbv2.DescribeRulesInput{
		ListenerArn: aws.String(listenerArn),
	}
	resp, err := svc.elbv2c.DescribeRules(params)
	if err != nil {
		return nil, fmt.Errorf("DescribeRules SDK error: %v", err)
	}

	return resp.Rules, nil
}

// SetRulePriority changes the specified rule to the specified priority.
func (svc *ELBService) SetRulePriority(ruleArn string, priority int64) error {
	logrus.Debugf("SetRulePriority => ruleArn: %s, priority %d",
		ruleArn, priority)

	params := &elbv2.SetRulePrioritiesInput{
		RulePriorities: []*elbv2.RulePriorityPair{
			{
				Priority: aws.Int64(priority),
				RuleArn:  aws.String(ruleArn),
			},
		},
	}
	_, err := svc.elbv2c.SetRulePriorities(params)
	if err != nil {
		return fmt.Errorf("SetRulePriorities SDK error: %v", err)
	}

	return nil
}

// ReorderRules reorders listener rules according to the specified map
// that contains pairs of the rule's ARN and it's new priority.
func (svc *ELBService) ReorderRules(rulePriorityPairs map[string]int64) error {
	logrus.Debugf("ReorderRules => rulePriorities: %v", rulePriorityPairs)

	var awsRulePriorityPairs []*elbv2.RulePriorityPair
	for rule, priority := range rulePriorityPairs {
		awsRulePriorityPairs = append(awsRulePriorityPairs, &elbv2.RulePriorityPair{
			Priority: aws.Int64(priority),
			RuleArn:  aws.String(rule),
		})
	}

	params := &elbv2.SetRulePrioritiesInput{
		RulePriorities: awsRulePriorityPairs,
	}
	_, err := svc.elbv2c.SetRulePriorities(params)
	if err != nil {
		return fmt.Errorf("SetRulePriorities SDK error: %v", err)
	}

	return nil
}

// SetListenerDefaultTargetGroup sets the specified target group
// as the default target for the specified listener.
func (svc *ELBService) SetListenerDefaultTargetGroup(listenerArn, targetGroupArn string) error {
	logrus.Debugf("SetListenerDefaultTargetGroup => listener: %s, target group: %s",
		listenerArn, targetGroupArn)

	params := &elbv2.ModifyListenerInput{
		ListenerArn: aws.String(listenerArn),
		DefaultActions: []*elbv2.Action{
			{
				TargetGroupArn: aws.String(targetGroupArn),
				Type:           aws.String(elbv2.ActionTypeEnumForward),
			},
		},
	}
	_, err := svc.elbv2c.ModifyListener(params)
	if err != nil {
		return fmt.Errorf("ModifyListener SDK error: %v", err)
	}

	return nil
}

// SetListenerCertificate sets the specified certificate in the specified listener.
func (svc *ELBService) SetListenerCertificate(listenerArn, certificateArn string) error {
	logrus.Debugf("SetListenerCertificate => listener: %s, cert: %s",
		listenerArn, certificateArn)

	params := &elbv2.ModifyListenerInput{
		ListenerArn: aws.String(listenerArn),
		Certificates: []*elbv2.Certificate{
			{
				CertificateArn: aws.String(certificateArn),
			},
		},
	}
	_, err := svc.elbv2c.ModifyListener(params)
	if err != nil {
		return fmt.Errorf("ModifyListener SDK error: %v", err)
	}

	return nil
}

/*
 * Target Groups
 */

// EnsureTargetGroup creates a new target group with the specified parameters in the service's VPC
// while overwriting any existing group by that name. It returns the ARN of the target group.
func (svc *ELBService) EnsureTargetGroup(name, protocol, healthCheckPath string, port int64,
	tags map[string]string, stickySessions bool) (string, error) {
	logrus.Debugf("EnsureTargetGroup => name: %s port: %d protocol: %s tags: %v",
		name, port, protocol, tags)

	tg, err := svc.GetTargetGroupByName(name)
	if err != nil {
		return "", err
	}
	if tg != nil {
		logrus.Debugf("Recreating existing target group %s", name)
		err := svc.DeleteTargetGroup(*tg.TargetGroupArn)
		if err != nil {
			return "", err
		}
	}

	return svc.CreateTargetGroup(name, protocol, healthCheckPath, port, tags, stickySessions)
}

// CreateTargetGroup creates a new target group with the specified parameters in the service's VPC.
// It returns the ARN of the target group.
func (svc *ELBService) CreateTargetGroup(name, protocol, healthCheckPath string, port int64,
	tags map[string]string, stickySessions bool) (string, error) {
	logrus.Debugf("createTargetGroup => name: %s port: %d protocol: %s tags: %v",
		name, port, protocol, tags)

	params := &elbv2.CreateTargetGroupInput{
		Name:            aws.String(name),
		Port:            aws.Int64(port),
		Protocol:        aws.String(protocol),
		VpcId:           aws.String(svc.vpcID),
		HealthCheckPath: aws.String(healthCheckPath),
	}
	resp, err := svc.elbv2c.CreateTargetGroup(params)
	if err != nil {
		return "", fmt.Errorf("CreateTargetGroup SDK error: %v", err)
	}

	if len(resp.TargetGroups) == 0 {
		return "", fmt.Errorf("Unexpected API response while creating target group")
	}

	arn := *resp.TargetGroups[0].TargetGroupArn
	if len(tags) > 0 {
		err = svc.addResourceTags(arn, tags)
		if err != nil {
			return "", err
		}
	}

	if stickySessions {
		err := svc.SetTargetGroupStickiness(arn, true)
		if err != nil {
			return "", err
		}
	}

	return arn, nil
}

// DeleteTargetGroup deletes the specified target group.
func (svc *ELBService) DeleteTargetGroup(targetGroupArn string) error {
	logrus.Debugf("deleteTargetGroup => targetGroupArn: %s", targetGroupArn)

	params := &elbv2.DeleteTargetGroupInput{
		TargetGroupArn: aws.String(targetGroupArn),
	}
	_, err := svc.elbv2c.DeleteTargetGroup(params)
	if err != nil && !IsAWSErr(err, AWSErrTargetGroupNotFound) {
		return fmt.Errorf("DeleteTargetGroup SDK error: %v", err)
	}

	return nil
}

// describes the specified target groups.
func (svc *ELBService) describeTargetGroups(targetGroupArns []*string) ([]*elbv2.TargetGroup, error) {
	params := &elbv2.DescribeTargetGroupsInput{
		TargetGroupArns: targetGroupArns,
	}
	resp, err := svc.elbv2c.DescribeTargetGroups(params)
	if err != nil {
		return nil, fmt.Errorf("DescribeTargetGroups SDK error: %v", err)
	}
	return resp.TargetGroups, nil
}

// GetTargetGroupByName returns an elbv2.TargetGroup struct for the specified name or nil if not found.
func (svc *ELBService) GetTargetGroupByName(targetGroupName string) (*elbv2.TargetGroup, error) {
	logrus.Debugf("GetTargetGroupByName => name: %s", targetGroupName)

	params := &elbv2.DescribeTargetGroupsInput{
		//PageSize: aws.Int64(400),
		Names: []*string{
			aws.String(targetGroupName),
		},
	}
	resp, err := svc.elbv2c.DescribeTargetGroups(params)
	if err != nil {
		if IsAWSErr(err, AWSErrTargetGroupNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("DescribeTargetGroups SDK error: %v", err)
	}

	logrus.Debugf("DescribeTargetGroups returned %d results", len(resp.TargetGroups))
	if len(resp.TargetGroups) > 0 {
		for _, tg := range resp.TargetGroups {
			if *tg.VpcId == svc.vpcID {
				return tg, nil
			}
		}
	}

	logrus.Debugf("GetTargetGroupByName => Could not find target group %s", targetGroupName)
	return nil, nil
}

// GetTargetGroupsByTag looks up target groups that have the specified tags and returns their ARNs.
func (svc *ELBService) GetTargetGroupsByTag(key, value string) ([]string, error) {
	logrus.Debugf("GetTargetGroupsByTag => key: %s val: %s", key, value)

	var ret []string
	var allTargetGroups []*elbv2.TargetGroup
	params := &elbv2.DescribeTargetGroupsInput{
		PageSize: aws.Int64(400),
	}

	err := svc.elbv2c.DescribeTargetGroupsPages(params,
		func(page *elbv2.DescribeTargetGroupsOutput, lastPage bool) bool {
			allTargetGroups = append(allTargetGroups, page.TargetGroups...)
			return !lastPage
		})
	if err != nil {
		return ret, fmt.Errorf("DescribeTargetGroupsPages SDK error: %v", err)
	}

	logrus.Debugf("GetTargetGroupsByTag => Found %d candidates", len(allTargetGroups))
	if len(allTargetGroups) == 0 {
		return ret, nil
	}

	// get the tags
	tgArns := make([]*string, len(allTargetGroups))
	for i, tg := range allTargetGroups {
		tgArns[i] = tg.TargetGroupArn
	}

	tagDescriptions, err := svc.describeResourceTags(tgArns)
	if err != nil {
		return ret, fmt.Errorf("Failed to describe target group tags: %v", err)
	}

	// filter tags
	for _, td := range tagDescriptions {
		for _, tag := range td.Tags {
			if *tag.Key == key && *tag.Value == value {
				ret = append(ret, *td.ResourceArn)
			}
		}
	}

	logrus.Debugf("Found %d target groups matching the specified tag", len(ret))
	return ret, nil
}

// describes the registered targets for the specified target group.
// this exludes any targets whose state is draining or unused.
func (svc *ELBService) describeRegisteredTargets(targetGroupArn string) ([]*elbv2.TargetDescription, error) {
	params := &elbv2.DescribeTargetHealthInput{
		TargetGroupArn: aws.String(targetGroupArn),
	}
	resp, err := svc.elbv2c.DescribeTargetHealth(params)
	if err != nil {
		return nil, fmt.Errorf("DescribeTargetHealth SDK error: %v", err)
	}

	var ret []*elbv2.TargetDescription
	for _, d := range resp.TargetHealthDescriptions {
		state := *d.TargetHealth.State
		if state == elbv2.TargetHealthStateEnumDraining || state == elbv2.TargetHealthStateEnumUnused {
			continue
		}
		ret = append(ret, d.Target)
	}
	return ret, nil
}

// SetTargetGroupStickiness sets the stickiness attribute for the specified target group.
func (svc *ELBService) SetTargetGroupStickiness(targetGroupArn string, stickiness bool) error {
	logrus.Debugf("SetTargetGroupStickiness => targetGroupArn: %s, stickiness %t",
		targetGroupArn, stickiness)

	params := &elbv2.ModifyTargetGroupAttributesInput{
		Attributes: []*elbv2.TargetGroupAttribute{
			{
				Key:   aws.String("stickiness.enabled"),
				Value: aws.String(fmt.Sprintf("%t", stickiness)),
			},
		},
		TargetGroupArn: aws.String(targetGroupArn),
	}
	_, err := svc.elbv2c.ModifyTargetGroupAttributes(params)
	if err != nil {
		return fmt.Errorf("ModifyTargetGroupAttributes SDK error: %v", err)
	}

	return nil
}

// GetTargetGroupStickiness checks whether the stickiness attribute is enabled for the
// specified target group.
func (svc *ELBService) GetTargetGroupStickiness(targetGroupArn string) (bool, error) {
	logrus.Debugf("GetTargetGroupStickiness => targetGroupArn: %s", targetGroupArn)

	params := &elbv2.DescribeTargetGroupAttributesInput{
		TargetGroupArn: aws.String(targetGroupArn),
	}
	resp, err := svc.elbv2c.DescribeTargetGroupAttributes(params)
	if err != nil {
		return false, fmt.Errorf("DescribeTargetGroupAttributes SDK error: %v", err)
	}

	stickiness := false
	for _, a := range resp.Attributes {
		if *a.Key == "stickiness.enabled" {
			stickiness, err = strconv.ParseBool(*a.Value)
			if err != nil {
				return false, fmt.Errorf("Could not parse stickiness attribute to boolean: %v", err)
			}
			break
		}
	}

	return stickiness, nil
}

// RegisterInstances registers the specified instances with the specified target group.
func (svc *ELBService) RegisterInstances(targetGroupArn string, instanceIds []string) error {
	logrus.Debugf("RegisterInstances => target group: %s instances: %v",
		targetGroupArn, instanceIds)

	awsTargets := make([]*elbv2.TargetDescription, len(instanceIds))
	for i, id := range instanceIds {
		awsTargets[i] = &elbv2.TargetDescription{
			Id: aws.String(id),
		}
	}

	params := &elbv2.RegisterTargetsInput{
		TargetGroupArn: aws.String(targetGroupArn),
		Targets:        awsTargets,
	}
	_, err := svc.elbv2c.RegisterTargets(params)
	if err != nil {
		return fmt.Errorf("RegisterTargets SDK error: %v", err)
	}

	return nil
}

// DeregisterInstances deregisters the specified instances from the specified target group.
func (svc *ELBService) DeregisterInstances(targetGroupArn string, instanceIds []string) error {
	logrus.Debugf("DeregisterInstances => target group: %s instances: %v",
		targetGroupArn, instanceIds)

	awsTargets := make([]*elbv2.TargetDescription, len(instanceIds))
	for i, id := range instanceIds {
		awsTargets[i] = &elbv2.TargetDescription{
			Id: aws.String(id),
		}
	}
	params := &elbv2.DeregisterTargetsInput{
		TargetGroupArn: aws.String(targetGroupArn),
		Targets:        awsTargets,
	}
	_, err := svc.elbv2c.DeregisterTargets(params)
	if err != nil {
		return fmt.Errorf("DeregisterTargets SDK error: %v", err)
	}

	return nil
}

// adds the specified tags to the specified ELBv2 resource.
func (svc *ELBService) addResourceTags(resourceArn string, tags map[string]string) error {
	logrus.Debugf("addResourceTags => resourceArn: %s, tags %v", resourceArn, tags)

	awsTags := elbTags(tags)
	params := &elbv2.AddTagsInput{
		ResourceArns: []*string{
			aws.String(resourceArn),
		},
		Tags: awsTags,
	}
	_, err := svc.elbv2c.AddTags(params)
	if err != nil {
		return fmt.Errorf("AddTags SDK error: %v", err)
	}

	return nil
}

// returns the tags for the specified ELBv2 resources.
func (svc *ELBService) describeResourceTags(resourceArns []*string) ([]*elbv2.TagDescription, error) {
	params := &elbv2.DescribeTagsInput{
		ResourceArns: resourceArns,
	}
	resp, err := svc.elbv2c.DescribeTags(params)
	if err != nil {
		return nil, fmt.Errorf("DescribeTags SDK error: %v", err)
	}

	return resp.TagDescriptions, nil
}

// WaitLoadBalancerActive blocks until the state of the specified load balancer
// is 'active'. It times out after ELBActiveMaxWait seconds.
func (svc *ELBService) WaitLoadBalancerActive(loadBalancerArn string) error {
	logrus.Debugf("waitLoadBalancerActive => loadBalancerArn: %s", loadBalancerArn)

	params := &elbv2.DescribeLoadBalancersInput{
		LoadBalancerArns: []*string{aws.String(loadBalancerArn)},
	}

	deadline := time.Now().Add(ELBActiveMaxWait)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for tick := range ticker.C {
		resp, err := svc.elbv2c.DescribeLoadBalancers(params)
		if err != nil {
			if IsAWSErr(err, AWSErrLoadBalancerNotFound) {
			} else {
				return fmt.Errorf("DescribeLoadBalancers SDK error: %v", err)
			}
		}

		if err == nil && len(resp.LoadBalancers) > 0 {
			state := *resp.LoadBalancers[0].State
			switch *state.Code {
			case elbv2.LoadBalancerStateEnumFailed:
				reason := "unknown"
				if state.Reason != nil {
					reason = *state.Reason
				}
				return fmt.Errorf("Load balancer state is 'failed' => reason: %s", reason)
			case elbv2.LoadBalancerStateEnumActive:
				return nil
			}
		}

		if tick.After(deadline) {
			break
		}
	}

	return fmt.Errorf("Timed out after %", ELBActiveMaxWait.String())
}

// WaitELBInterfacesRemoved blocks until all interfaces of the specified load balancer
// have been removed. It times out after ELBDeletedMaxWait seconds. This should be
// called before trying to remove security groups associated with the ELB.
func (svc *ELBService) WaitELBInterfacesRemoved(loadBalancerArn string) error {
	logrus.Debugf("WaitLoadBalancerDeleted => loadBalancerArn: %s", loadBalancerArn)

	parts := strings.SplitN(loadBalancerArn, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("Could not parse load balancer ARN: %s", loadBalancerArn)
	}

	// The descriptions of interfaces for a load balancer have the following format:
	// "ELB app/<load balance name>/<load balancer id>"
	desc := fmt.Sprintf("ELB %s", parts[1])
	params := &ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			NewEC2Filter("description", desc),
			NewEC2Filter("vpc-id", svc.vpcID),
		},
	}

	deadline := time.Now().Add(ELBDeletedMaxWait)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for tick := range ticker.C {
		resp, err := svc.ec2c.DescribeNetworkInterfaces(params)
		if err != nil {
			return fmt.Errorf("DescribeNetworkInterfaces SDK error: %v", err)
		}
		if len(resp.NetworkInterfaces) == 0 {
			return nil
		}

		if tick.After(deadline) {
			break
		}
	}

	return fmt.Errorf("Timed out after %", ELBDeletedMaxWait.String())
}
