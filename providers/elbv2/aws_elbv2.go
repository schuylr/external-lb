package awselbv2

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/rancher/external-lb/model"
	"github.com/rancher/external-lb/providers"
	"github.com/rancher/external-lb/providers/elbv2/elbsvc"
)

const (
	ProviderName = "AWS Application Load Balancer"
	ProviderSlug = "elbv2"
)

const (
	TagTargetPoolName       = "target-pool-name"
	TagOwner                = "owner"
	TagOwnerValue           = "rancher/external-lb"
	TagLoadBalancerRelation = "for-elb"
)

const (
	PrefixTargetGroupName   = "rancher"
	PrefixSecurityGroupName = "rancher-elbv2"
	LBSecurityGroupDesc     = "ELBv2 ingress rules managed by rancher/external-lb"
)

const (
	TemplateTargetGroupName     = "%s-%s-%s" // prefix, service, hash
	TemplateLBSecurityGroupName = "%s/%s"    // prefix, load balancer name
	TemplateNoOpTargetGroupName = "noop-%s"  // load balancer name
)

const (
	EnvVarAWSAccessKey      = "ELBV2_AWS_ACCESS_KEY"
	EnvVarAWSSecretKey      = "ELBV2_AWS_SECRET_KEY"
	EnvVarAWSRegion         = "ELBV2_AWS_REGION"
	EnvVarAWSVpcID          = "ELBV2_AWS_VPCID"
	EnvVarUsePrivateIP      = "ELBV2_USE_PRIVATE_IP"
	EnvVarAccessLogsEnabled = "ELBV2_ACCESS_LOGS_ENABLED"
	EnvVarAccessLogsBucket  = "ELBV2_ACCESS_LOGS_BUCKET"
	EnvVarAccessLogsPrefix  = "ELBV2_ACCESS_LOGS_PREFIX"
	EnvVarConnectionTimeout = "ELBV2_CONNECTION_TIMEOUT"
	EnvVarDrainingTimeout   = "ELBV2_DRAINING_TIMEOUT"
)

// AWSELBv2Provider implements the providers.Provider interface.
type AWSELBv2Provider struct {
	svc          *elbsvc.ELBService
	region       string
	vpcID        string
	usePrivateIP bool
	options      ELBOptions
	ipToInstance map[string]*elbsvc.EC2Instance
}

// ELBOptions specifies global options for
// all of the created load balancers
type ELBOptions struct {
	accessLogsEnabled  bool
	accessLogsBucket   string
	accessLogsPrefix   string
	idleTimeoutSeconds int // range: 1-3600
	drainingTimeout    int // range: 0-3600
}

func init() {
	providers.RegisterProvider(ProviderSlug, new(AWSELBv2Provider))
}

func (p *AWSELBv2Provider) Init() error {
	var err error
	accessKey := os.Getenv(EnvVarAWSAccessKey)
	secretKey := os.Getenv(EnvVarAWSSecretKey)

	p.region = os.Getenv(EnvVarAWSRegion)
	p.vpcID = os.Getenv(EnvVarAWSVpcID)
	p.options.accessLogsBucket = os.Getenv(EnvVarAccessLogsBucket)
	p.options.accessLogsPrefix = os.Getenv(EnvVarAccessLogsPrefix)
	p.ipToInstance = make(map[string]*elbsvc.EC2Instance)

	if env := os.Getenv(EnvVarAccessLogsEnabled); len(env) > 0 {
		p.options.accessLogsEnabled, err = strconv.ParseBool(env)
		if err != nil {
			return fmt.Errorf("'%s' must be set to a string "+
				"representing a boolean value", EnvVarAccessLogsEnabled)
		}
	}

	p.options.idleTimeoutSeconds = 60 // default connection timeout
	if env := os.Getenv(EnvVarConnectionTimeout); len(env) > 0 {
		p.options.idleTimeoutSeconds, err = strconv.Atoi(env)
		if err != nil {
			return fmt.Errorf("'%s' must be set to as string "+
				"representing an integer value", EnvVarConnectionTimeout)
		}
		if 1 > p.options.idleTimeoutSeconds || p.options.idleTimeoutSeconds > 3600 {
			return fmt.Errorf("'%s' must have a value within the range of 1-3600", EnvVarConnectionTimeout)
		}
	}

	if env := os.Getenv(EnvVarUsePrivateIP); len(env) > 0 {
		p.usePrivateIP, err = strconv.ParseBool(env)
		if err != nil {
			return fmt.Errorf("'%s' must be set to a string "+
				"representing a boolean value", EnvVarUsePrivateIP)
		}
	}

	if p.vpcID == "" || p.region == "" {
		p.vpcID, p.region, err = elbsvc.GetInstanceInfo()
		if err != nil {
			return err
		}
	}

	logrus.Debugf("Initialized provider: region: %s, vpc: %s, usePrivateIP %t",
		p.region, p.vpcID, p.usePrivateIP)

	p.svc, err = elbsvc.NewService(accessKey, secretKey, p.region, p.vpcID)
	if err != nil {
		return err
	}

	if err := p.svc.CheckAPIConnection(); err != nil {
		return fmt.Errorf("AWS API connection check failed: %v", err)
	}

	logrus.Infof("Configured %s provider in region %s and VPC %s",
		p.GetName(), p.region, p.vpcID)

	return nil
}

/*
 * Methods implementing the providers.Provider interface
 */

func (*AWSELBv2Provider) GetName() string {
	return ProviderName
}

func (p *AWSELBv2Provider) HealthCheck() error {
	return p.svc.CheckAPIConnection()
}

func (p *AWSELBv2Provider) GetLBConfigs() ([]model.LBConfig, error) {
	logrus.Debugf("GetLBConfigs =>")

	var lbConfigs []model.LBConfig
	in, err := p.svc.GetLoadBalancers()
	if err != nil {
		return lbConfigs, fmt.Errorf("Failed to get load ELBv2 load balancers: %v", err)
	}

	// only load balancers managed by us
	var loadBalancers []*elbsvc.LoadBalancerInfo
	tags := map[string]string{
		TagOwner: TagOwnerValue,
	}

	for _, lb := range in {
		if containsTags(tags, lb.Tags) {
			loadBalancers = append(loadBalancers, lb)
		}
	}

	if len(loadBalancers) == 0 {
		logrus.Debug("GetLBConfigs => No load balancers found")
		return lbConfigs, nil
	}

	for _, lb := range loadBalancers {
		var frontends []model.LBFrontend
		for _, listener := range lb.Listeners {
			var targetPools []model.LBTargetPool
			for _, backend := range listener.Backends {
				// ignore backends not created by us
				if _, ok := backend.Tags[TagTargetPoolName]; !ok {
					continue
				}
				pool := model.LBTargetPool{
					Name:           backend.Tags[TagTargetPoolName],
					Port:           backend.BackendPort,
					Protocol:       backend.BackendProtocol,
					PathPattern:    backend.PathPattern,
					StickySessions: backend.StickySessions,
				}

				var instanceIPs []string
				if len(backend.Instances) > 0 {
					instances, err := p.svc.GetInstancesByID(backend.Instances)
					if err != nil {
						return lbConfigs, fmt.Errorf("Failed to lookup EC2 instances: %v", err)
					}
					for _, in := range instances {
						if p.usePrivateIP {
							instanceIPs = append(instanceIPs, in.PrivateIPAddress)
						} else {
							instanceIPs = append(instanceIPs, in.PublicIPAddress)
						}
					}
					pool.TargetIPs = instanceIPs
				}

				targetPools = append(targetPools, pool)
			}

			frontend := model.LBFrontend{
				Port:        listener.Port,
				Protocol:    listener.Protocol,
				Certificate: listener.CertificateArn,
				TargetPools: targetPools,
			}
			frontends = append(frontends, frontend)
		}

		lbConfig := model.LBConfig{
			EndpointName: lb.Name,
			Frontends:    frontends,
		}

		lbConfigs = append(lbConfigs, lbConfig)
	}

	logrus.Debugf("GetLBConfigs => Returning %d load balancers", len(lbConfigs))
	return lbConfigs, nil
}

func (p *AWSELBv2Provider) AddLBConfig(config model.LBConfig) (string, error) {
	logrus.Debugf("AddLBConfig => config: %v", config)

	// Validate the provided name of the load balancer
	if sanitizeAwsName(config.EndpointName) != config.EndpointName {
		return "", fmt.Errorf("Invalid endpoint name. ELBv2 load balancer names" +
			" must have max. 32 characters and consist of only alphanumeric" +
			" characters or dashes.")
	}

	// There should be at least one frontend
	if len(config.Frontends) == 0 {
		return "", fmt.Errorf("Can not create ELBv2 load balancer without frontends")
	}

	found, err := p.svc.GetLoadBalancerByName(config.EndpointName)
	if err != nil {
		return "", err
	}
	if found != nil {
		return "", fmt.Errorf("An ELBv2 load balancer named %s already exists", config.EndpointName)
	}

	allInstances, err := p.getEC2Instances(config)
	if err != nil {
		return "", fmt.Errorf("Failed to get EC2 instances: %v", err)
	}

	azSubnets, err := p.getEC2InstancesAvailabilityZones(allInstances)
	if err != nil {
		return "", err
	}

	err = p.ensureLbAvailabilityZones(azSubnets)
	if err != nil {
		return "", err
	}

	subnets := make([]string, len(azSubnets))
	i := 0
	for _, subnet := range azSubnets {
		subnets[i] = subnet
		i++
	}

	securityGroupId, err := p.getLBSecurityGroupID(config.EndpointName)
	if err != nil {
		return "", err
	}

	// allow internet to acccess the load balancer frontend ports
	err = p.ensureLoadBalancerIngress(securityGroupId, config)
	if err != nil {
		return "", err
	}

	// allow load balancer to access the backend instances
	err = p.ensureInstanceIngress(securityGroupId, allInstances)
	if err != nil {
		return "", err
	}

	tags := map[string]string{
		TagOwner: TagOwnerValue,
	}

	newLb := &elbsvc.NewLoadBalancer{
		Name: config.EndpointName,
		// TODO: internal load balancers
		Scheme:            elbsvc.ELBSchemeInternet,
		SecurityGroup:     securityGroupId,
		Subnets:           subnets,
		Tags:              tags,
		AccessLogsEnabled: p.options.accessLogsEnabled,
		AccessLogsBucket:  p.options.accessLogsBucket,
		AccessLogsPrefix:  p.options.accessLogsPrefix,
		IdleTimoutSeconds: p.options.idleTimeoutSeconds,
	}

	lbInfo, err := p.svc.CreateLoadBalancer(newLb)
	if err != nil {
		return "", err
	}

	logrus.Infof("Created AWS ELBv2 load balancer %s in subnets %v", newLb.Name, newLb.Subnets)

	logrus.Infof("New load balancers can take up to 2 minutes before starting to serve traffic")

	for _, frontend := range config.Frontends {
		if err := p.ensureListener(lbInfo.Name, lbInfo.LoadBalancerArn, frontend,
			new(elbsvc.Listener)); err != nil {
			return "", err
		}
	}

	logrus.Debug("GetLBConfigs => Done")
	return lbInfo.DNSName, nil
}

func (p *AWSELBv2Provider) UpdateLBConfig(config model.LBConfig) (string, error) {
	logrus.Debugf("UpdateLBConfig => config: %v", config)
	lbInfo, err := p.svc.GetLoadBalancerByName(config.EndpointName)
	if err != nil {
		return "", err
	}
	if lbInfo == nil {
		return "", fmt.Errorf("Could not find ELBv2 load balancer named %s", config.EndpointName)
	}

	// there should be at least one frontend
	if len(config.Frontends) == 0 {
		return "", fmt.Errorf("Can not create LB without any frontends")
	}

	allInstances, err := p.getEC2Instances(config)
	if err != nil {
		return "", fmt.Errorf("Failed to get EC2 instances: %v", err)
	}

	azSubnets, err := p.getEC2InstancesAvailabilityZones(allInstances)
	if err != nil {
		return "", err
	}

	// check if need to run the load balancer in additional subnets
	var addSubnets []string
	for az, subnet := range azSubnets {
		if _, ok := lbInfo.AvailabilityZones[az]; !ok {
			addSubnets = append(addSubnets, subnet)
		}
	}

	if len(addSubnets) > 0 {
		for _, subnet := range lbInfo.AvailabilityZones {
			addSubnets = append(addSubnets, subnet)
		}
		err := p.svc.SetLoadBalancerSubnets(lbInfo.LoadBalancerArn, addSubnets)
		if err != nil {
			return "", err
		}
	}

	securityGroupId, err := p.getLBSecurityGroupID(config.EndpointName)
	if err != nil {
		return "", err
	}

	// making sure the security group is still associated with the load balancer
	if !containsString(securityGroupId, lbInfo.SecurityGroups) {
		ids := append(lbInfo.SecurityGroups, securityGroupId)
		err := p.svc.SetLoadBalancerSecurityGroups(lbInfo.LoadBalancerArn, ids)
		if err != nil {
			return "", err
		}
	}

	err = p.ensureLoadBalancerIngress(securityGroupId, config)
	if err != nil {
		return "", err
	}

	err = p.ensureInstanceIngress(securityGroupId, allInstances)
	if err != nil {
		return "", err
	}

	var addFrontends []model.LBFrontend
	var removeListeners []*elbsvc.Listener
	updateListeners := make(map[int]*elbsvc.Listener)
	updateFrontends := make(map[int]model.LBFrontend)

	// check if we need to remove any listeners
	for _, listener := range lbInfo.Listeners {
		keep := false
		for _, frontend := range config.Frontends {
			if listener.Port == frontend.Port && listener.Protocol == frontend.Protocol {
				keep = true
				break
			}
		}
		if !keep {
			removeListeners = append(removeListeners, listener)
		}
	}

	for _, listener := range removeListeners {
		if err := p.removeListener(listener); err != nil {
			return "", err
		}
	}

	// check if we need to add or update any listeners
	updateIdx := 0
	for _, frontend := range config.Frontends {
		add := true
		for _, listener := range lbInfo.Listeners {
			if listener.Port == frontend.Port && listener.Protocol == frontend.Protocol {
				updateListeners[updateIdx] = listener
				updateFrontends[updateIdx] = frontend
				updateIdx++
				add = false
				break
			}
		}
		if add {
			addFrontends = append(addFrontends, frontend)
		}
	}

	for _, frontend := range addFrontends {
		if err := p.ensureListener(lbInfo.Name, lbInfo.LoadBalancerArn, frontend,
			new(elbsvc.Listener)); err != nil {
			return "", err
		}
	}

	for idx, listener := range updateListeners {
		frontend := updateFrontends[idx]
		if err := p.ensureListener(lbInfo.Name, lbInfo.LoadBalancerArn, frontend,
			listener); err != nil {
			return "", err
		}
	}

	logrus.Debug("UpdateLBConfig => Done!")
	return lbInfo.DNSName, nil
}

// delete the ELB application load balancer
func (p *AWSELBv2Provider) RemoveLBConfig(config model.LBConfig) error {
	logrus.Debugf("RemoveLBConfig => config: %v", config)
	lbInfo, err := p.svc.GetLoadBalancerByName(config.EndpointName)
	if err != nil {
		return err
	}
	if lbInfo == nil {
		logrus.Warnf("Tried to remove non-existent load balancer %s", config.EndpointName)
		return nil
	}

	if err := p.svc.DeleteLoadBalancer(lbInfo.LoadBalancerArn); err != nil {
		return err
	}

	logrus.Infof("Removed AWS ELBv2 load balancer %s", config.EndpointName)

	// get target groups and rules associated to the load balancer
	var targetGroups, rules []string
	for _, listener := range lbInfo.Listeners {
		for _, backend := range listener.Backends {
			targetGroups = append(targetGroups, backend.TargetGroupArn)
			if !backend.IsDefault {
				rules = append(rules, backend.RuleArn)
			}
		}
	}

	// get orphaned target groups for this load balancer
	orphaned, err := p.svc.GetTargetGroupsByTag(TagLoadBalancerRelation, config.EndpointName)
	if err != nil {
		logrus.Error(err)
	}
	targetGroups = append(targetGroups, orphaned...)
	targetGroups = removeDuplicates(targetGroups)

	// TODO: do i really need to delete the rules explicitely?
	/*	for _, arn := range rules {
		err := p.svc.DeleteListenerRule(arn)
		if err != nil {
			logrus.Error(err)
		}
	}*/

	// deal with that eventual consistency:
	// removing target groups may result in
	// ResourceInUse errors initially.
	tries := 0
	for tries < 5 {
		for i := len(targetGroups) - 1; i >= 0; i-- {
			arn := targetGroups[i]
			if err := p.svc.DeleteTargetGroup(arn); err != nil {
				if elbsvc.IsAWSErr(err, elbsvc.AWSErrResourceInUse) {
					logrus.Debug("Ignoring ResourceInUse error while cleaning up target group")
				} else {
					logrus.Warn(err)
				}
				continue
			}

			targetGroups = append(targetGroups[:i], targetGroups[i+1:]...)
		}

		if len(targetGroups) == 0 {
			break
		}

		time.Sleep(2 * time.Second)
		tries++
	}

	if len(targetGroups) != 0 {
		logrus.Warnf("Failed to remove all target groups for ELB %s. "+
			"You may want to manually remove them.", config.EndpointName)
	}

	// get the load balancer security group ID
	sgname := fmt.Sprintf(TemplateLBSecurityGroupName, PrefixSecurityGroupName, config.EndpointName)
	sg, err := p.svc.GetSecurityGroupByName(sgname)
	if err != nil {
		return err
	}

	if sg != nil {
		sgId := *sg.GroupId
		// revoke access from any instance security groups
		if err := p.ensureInstanceIngress(sgId, nil); err != nil {
			return err
		}

		go func() {
			logrus.Infof("Started background cleaning job for load balancer '%s'", config.EndpointName)

			if err := p.svc.WaitELBInterfacesRemoved(lbInfo.LoadBalancerArn); err != nil {
				logrus.Warnf("While waiting for ELB interfaces to be removed: %s", err.Error())
			}

			// delete the security group
			if err := p.svc.DeleteSecurityGroup(sgId); err != nil {
				if elbsvc.IsAWSErr(err, elbsvc.AWSErrDependendyViolation) {
					logrus.Debugf("Ignoring DependencyViolation error while deleting security group")
				} else {
					logrus.Error(err)
				}

				logrus.Warnf("Failed to remove ELB security group. You "+
					"may want to manually remove this group: %s", sgId)
			} else {
				logrus.Infof("Finished background cleaning job for ELB '%s'", config.EndpointName)
			}
		}()
	}

	logrus.Debug("RemoveLBConfigs => Done")
	return nil
}

/*
 * Private methods
 */

// ensures that the specified listener matches the specified frontend
// by adding, deleting and updating backends.
func (p *AWSELBv2Provider) ensureListener(lbname, lbarn string, frontend model.LBFrontend,
	listener *elbsvc.Listener) error {
	logrus.Debugf("ensureListener => loadBalancerName: %s, loadBalancerArn: %s, frontend: %v, listener: %v",
		lbname, lbarn, frontend, listener)

	var addTargetPools []model.LBTargetPool
	var removeBackends []*elbsvc.Backend
	var newDefTargetPoolName string
	var currentDefTargetPoolName string
	var currentDefTargetGroupArn string

	var placeholderTargetActive bool

	updateBackends := make(map[int]*elbsvc.Backend)
	updateTargetPools := make(map[int]model.LBTargetPool)

	nameToTargetPool := make(map[string]model.LBTargetPool)
	nameToPriority := make(map[string]int64)
	patternToName := make(map[string]string)

	var err error
	var patterns []string
	for _, tp := range frontend.TargetPools {
		if _, exist := patternToName[tp.PathPattern]; exist {
			return fmt.Errorf("Multiple services for the same listener can't " +
				"have equal or empty path patterns")
		}
		patternToName[tp.PathPattern] = tp.Name
		nameToTargetPool[tp.Name] = tp
		patterns = append(patterns, tp.PathPattern)
	}

	// we prioritize the target groups in descending length of their
	// path pattern and determine the default target pool for the
	// listener, ie. the one that has an empty path pattern.
	sortByLengthDesc(patterns)
	priority := int64(10)
	for _, p := range patterns {
		if len(p) == 0 {
			newDefTargetPoolName = patternToName[p]
		} else {
			nameToPriority[patternToName[p]] = priority
			priority++
		}
	}
	patterns, patternToName = nil, nil

	// if the listener hasn't been created yet, configure it now and return early.
	if len(listener.ListenerArn) == 0 {
		var defTgArn string
		for _, targetPool := range frontend.TargetPools {
			// if we have a default target group, create it now so we can reference
			// it when creating the listener.
			if targetPool.Name == newDefTargetPoolName {
				logrus.Debugf("Creating default target group %s for listener '%s' on ELB '%s'",
					targetPool.Name, frontend.Port, lbname)
				defTgArn, err = p.createBackend(lbname, targetPool)
				if err != nil {
					return err
				}
			} else {
				addTargetPools = append(addTargetPools, targetPool)
			}
		}

		// if there is no default target group (ie. one with an empty path pattern),
		// we create a placeholder target group to reference when creating the listener.
		if len(defTgArn) == 0 {
			logrus.Debugf("Creating placeholder target group for listener %d on ELB '%s'", frontend.Port, lbname)
			defTgArn, err = p.ensurePlaceholderTargetGroup(lbname, frontend.Port)
			if err != nil {
				return err
			}
		}

		listenerArn, err := p.svc.CreateListener(lbarn, defTgArn, frontend.Protocol,
			frontend.Port, frontend.Certificate)
		if err != nil {
			return fmt.Errorf("Failed to create listener for protocol %s, port %d: %v", frontend.Protocol, frontend.Port, err)
		}

		logrus.Debugf("Adding %d backends", len(addTargetPools))
		for _, targetPool := range addTargetPools {
			tgArn, err := p.createBackend(lbname, targetPool)
			if err != nil {
				return err
			}

			if err := p.svc.CreateListenerPathRule(listenerArn, tgArn, targetPool.PathPattern,
				nameToPriority[targetPool.Name]); err != nil {
				return err
			}
		}

		return nil
	}

	// Determine the ARN and name of the current default target group.
	for _, backend := range listener.Backends {
		if backend.IsDefault {
			currentDefTargetGroupArn = backend.TargetGroupArn
			if name, ok := backend.Tags[TagTargetPoolName]; ok {
				currentDefTargetPoolName = name
			}
			break
		}
	}

	var defaultTargetChanged bool
	if currentDefTargetPoolName != "" && newDefTargetPoolName != currentDefTargetPoolName {
		defaultTargetChanged = true
		logrus.Debugf("Default target group for listener %s/%d will change."+
			"Setting the placeholder temporarily to sort stuff out", lbname, frontend.Port)
	}

	// if we don't have a default target group, we use a NOOP placeholder target group
	// as default. if the default target group has changed we set it temporarily so that
	// we can add/remove/update target groups without falling into some dependency trap.
	if newDefTargetPoolName == "" || defaultTargetChanged {
		logrus.Debugf("Ensuring placeholder target group for listener %d on ELB %s", frontend.Port, lbname)
		tgArn, err := p.ensurePlaceholderTargetGroup(lbname, frontend.Port)
		if err != nil {
			return err
		}

		if tgArn != currentDefTargetGroupArn {
			if err := p.svc.SetListenerDefaultTargetGroup(listener.ListenerArn, tgArn); err != nil {
				return err
			}
		}

		placeholderTargetActive = true
	}

	// check which backends we need to add or update
	updateIdx := 0
	for _, targetPool := range frontend.TargetPools {
		add := true
		for _, backend := range listener.Backends {
			if name, ok := backend.Tags[TagTargetPoolName]; ok {
				if name == targetPool.Name {
					updateBackends[updateIdx] = backend
					updateTargetPools[updateIdx] = targetPool
					updateIdx++
					add = false
					break
				}
			}
		}

		if add {
			addTargetPools = append(addTargetPools, targetPool)
		}
	}

	// check which backends we need to remove
	for _, backend := range listener.Backends {
		keep := false
		if name, ok := backend.Tags[TagTargetPoolName]; ok {
			for _, targetPool := range frontend.TargetPools {
				if name == targetPool.Name {
					keep = true
					break
				}
			}
		} else {
			// ignore backends without the tag
			continue
		}

		if !keep {
			removeBackends = append(removeBackends, backend)
		}
	}

	// remove the targets first so that we don't
	// fall into the rule priorites conflicts trap.
	logrus.Debugf("Removing %d backends", len(removeBackends))
	for _, backend := range removeBackends {
		logrus.Debugf("Removing backend %s", backend.TargetGroupName)

		if !backend.IsDefault {
			if err := p.svc.DeleteListenerRule(backend.RuleArn); err != nil {
				return err
			}
		}

		if err := p.svc.DeleteTargetGroup(backend.TargetGroupArn); err != nil {
			return err
		}
	}

	// check which listener rules need to be reordered
	rulesPriorityMap := make(map[string]int64)
	for _, backend := range updateBackends {
		name := backend.Tags[TagTargetPoolName]
		if priority, ok := nameToPriority[name]; ok {
			// a default backend does not have a priority
			if !backend.IsDefault && backend.Priority != priority {
				rulesPriorityMap[backend.RuleArn] = priority
			}
		} else {
			// either this backend will be removed or become the
			// default target. Either way we need to remove it's rule
			// so we don't get priority conflicts when reordering.
			if !backend.IsDefault {
				logrus.Debugf("Removing rule for target group %s", name)
				if err := p.svc.DeleteListenerRule(backend.RuleArn); err != nil {
					return err
				}
			}
		}
	}

	logrus.Debugf("Reordering %d rules: %v", len(rulesPriorityMap), rulesPriorityMap)

	if len(rulesPriorityMap) > 0 {
		if err := p.svc.ReorderRules(rulesPriorityMap); err != nil {
			return err
		}
	}

	// update backends
	logrus.Debugf("Updating %d backends", len(updateBackends))
	for idx, backend := range updateBackends {
		targetPool := updateTargetPools[idx]

		// first check if properties have changed that can't be modified.
		// in this case we need to recreate the target group.
		if backend.BackendProtocol != targetPool.Protocol || backend.BackendPort != targetPool.Port {
			logrus.Debugf("Target group %s needs to be recreated", targetPool.Name)
			// if this is the default target group we temporarily set a default placeholder
			// in order to be able to delete the group.
			if backend.IsDefault && !placeholderTargetActive {
				logrus.Debugf("Ensuring placeholder target group for listener %s/%d", lbname, frontend.Port)
				tgArn, err := p.ensurePlaceholderTargetGroup(lbname, frontend.Port)
				if err != nil {
					return err
				}

				if tgArn != currentDefTargetGroupArn {
					logrus.Debug("Setting placeholder target group as default")
					if err := p.svc.SetListenerDefaultTargetGroup(listener.ListenerArn, tgArn); err != nil {
						return err
					}
				}
				placeholderTargetActive = true
			}

			if !backend.IsDefault {
				// delete the rule attaching it to the listener
				logrus.Debugf("Removing rule for target group %s", targetPool.Name)
				if err := p.svc.DeleteListenerRule(backend.RuleArn); err != nil {
					return err
				}
			}

			// recreate the target group
			newTgArn, err := p.createBackend(lbname, targetPool)
			if err != nil {
				return err
			}

			// if this should be the default target make it so
			if targetPool.Name == newDefTargetPoolName {
				if err := p.svc.SetListenerDefaultTargetGroup(listener.ListenerArn, newTgArn); err != nil {
					return err
				}
			} else { // otherwise create a rule for it
				if err := p.svc.CreateListenerPathRule(listener.ListenerArn, newTgArn,
					targetPool.PathPattern, nameToPriority[targetPool.Name]); err != nil {
					return err
				}
			}

			// set the new target group ARN in the backend struct
			// and the backend.Instances to null
			if newTgArn != backend.TargetGroupArn {
				backend.TargetGroupArn = newTgArn
				backend.Instances = make([]string, 0)
			}

		} else { // otherwise check if we need to modify anything

			// if the path pattern for a regular target has changed then we must modify the rule.
			if backend.PathPattern != targetPool.PathPattern && !backend.IsDefault && targetPool.Name != newDefTargetPoolName {
				logrus.Debugf("Updating path pattern for target group %s", targetPool.Name)
				if err := p.svc.ModifyListenerRulePathPattern(backend.RuleArn, targetPool.PathPattern); err != nil {
					return err
				}
			}

			// if this has been promoted to default target we need to make it so
			if targetPool.Name == newDefTargetPoolName && !backend.IsDefault {
				// do we need to remote the previous rule?
				logrus.Debugf("Removing rule for target group %s", targetPool.Name)
				if err := p.svc.DeleteListenerRule(backend.RuleArn); err != nil {
					return err
				}
				logrus.Debugf("Setting target group %s as new default target", targetPool.Name)
				if err := p.svc.SetListenerDefaultTargetGroup(listener.ListenerArn, backend.TargetGroupArn); err != nil {
					return err
				}
			}

			// if this has been demoted to regular target we need to create a rule
			if backend.IsDefault && targetPool.Name != newDefTargetPoolName {
				logrus.Debugf("Creating rule for denoted target group %s", targetPool.Name)
				if err := p.svc.CreateListenerPathRule(listener.ListenerArn, backend.TargetGroupArn,
					targetPool.PathPattern, nameToPriority[targetPool.Name]); err != nil {
					return err
				}
			}
		}

		// update the instances for this backend
		var wantInstanceIds []string
		for _, ip := range targetPool.TargetIPs {
			if instance, ok := p.ipToInstance[ip]; ok {
				wantInstanceIds = append(wantInstanceIds, instance.ID)
			} else {
				logrus.Errorf("Could not find EC2 instance for IP address %s", ip)
			}
		}

		registerInstances := differenceStringSlice(wantInstanceIds, backend.Instances)
		deregisterInstances := differenceStringSlice(backend.Instances, wantInstanceIds)
		logrus.Debugf("Registering instances to target group %s: %v", targetPool.Name, registerInstances)
		logrus.Debugf("Deregistering instances to target group %s: %v", targetPool.Name, deregisterInstances)

		if len(registerInstances) > 0 {
			err := p.svc.RegisterInstances(backend.TargetGroupArn, registerInstances)
			if err != nil {
				return err
			}
		}

		if len(deregisterInstances) > 0 {
			err := p.svc.DeregisterInstances(backend.TargetGroupArn, deregisterInstances)
			if err != nil {
				return err
			}
		}
	}

	// add backends
	logrus.Debugf("Adding %d backends", len(addTargetPools))
	for _, targetPool := range addTargetPools {
		tgArn, err := p.createBackend(lbname, targetPool)
		if err != nil {
			return err
		}

		// if this should be the default make it so
		if targetPool.Name == newDefTargetPoolName {
			logrus.Debugf("Setting target group %s as new default", targetPool.Name)
			if err := p.svc.SetListenerDefaultTargetGroup(listener.ListenerArn, tgArn); err != nil {
				return err
			}
		} else { // create a rule for it
			logrus.Debugf("Creating rule for target group %s", targetPool.Name)
			if err := p.svc.CreateListenerPathRule(listener.ListenerArn, tgArn,
				targetPool.PathPattern, nameToPriority[targetPool.Name]); err != nil {
				return err
			}
		}
	}

	// update listener certificate
	if frontend.Certificate != listener.CertificateArn {
		if err := p.svc.SetListenerCertificate(listener.ListenerArn, frontend.Certificate); err != nil {
			return fmt.Errorf("Failed to change listener certificate: %v", err)
		}
	}

	return nil
}

// returns the instances referenced by the TargetIPs in the specified
// model.LBConfig and updates the ipToInstance field in the provider struct.
func (p *AWSELBv2Provider) getEC2Instances(config model.LBConfig) ([]*elbsvc.EC2Instance, error) {
	var targetIPs []string
	for _, fe := range config.Frontends {
		for _, tp := range fe.TargetPools {
			targetIPs = append(targetIPs, tp.TargetIPs...)
		}
	}

	targetIPs = removeDuplicates(targetIPs)
	if len(targetIPs) == 0 {
		return make([]*elbsvc.EC2Instance, 0), nil
	}

	ec2Instances, err := p.svc.LookupInstancesByIPAddress(targetIPs, p.usePrivateIP)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("getEC2Instances => Looked up %d IP addresses, got %d instances",
		len(targetIPs), len(ec2Instances))

	for _, instance := range ec2Instances {
		if p.usePrivateIP {
			p.ipToInstance[instance.PrivateIPAddress] = instance
		} else {
			p.ipToInstance[instance.PublicIPAddress] = instance
		}
	}

	return ec2Instances, nil
}

// creates a target group for the specified model.LBTargetPool, registers the instances
// and returns the ARN of the target group.
func (p *AWSELBv2Provider) createBackend(loadBalancerName string, targetPool model.LBTargetPool) (string, error) {
	logrus.Debugf("createBackend => targetPool: %v", targetPool)
	name := makeTargetGroupName(targetPool.Name)
	tags := map[string]string{
		TagTargetPoolName:       targetPool.Name,
		TagLoadBalancerRelation: loadBalancerName,
		TagOwner:                TagOwnerValue,
	}

	tgArn, err := p.svc.EnsureTargetGroup(name, targetPool.Protocol, targetPool.Port, targetPool.HealthCheckPort,
		tags, targetPool.StickySessions, p.options.drainingTimeout)
	if err != nil {
		return "", fmt.Errorf("Failed to ensure target group %s: %v", name, err)
	}

	var registerInstances []string
	for _, ip := range targetPool.TargetIPs {
		if instance, ok := p.ipToInstance[ip]; ok {
			registerInstances = append(registerInstances, instance.ID)
		} else {
			logrus.Errorf("Can not register target. No EC2 instance found for IP %s", ip)
		}
	}

	if len(registerInstances) > 0 {
		err := p.svc.RegisterInstances(tgArn, registerInstances)
		if err != nil {
			return "", err
		}
	}

	return tgArn, nil
}

func (p *AWSELBv2Provider) removeListener(listener *elbsvc.Listener) error {
	if err := p.svc.DeleteListener(listener.ListenerArn); err != nil {
		return fmt.Errorf("Error removing listener: %v", err)
	}

	for _, be := range listener.Backends {
		if err := p.svc.DeleteTargetGroup(be.TargetGroupArn); err != nil {
			return fmt.Errorf("Error removing listener target group: %v", err)
		}
	}

	return nil
}

// ensures the placeholder target group for the specified listener exists and returns it's ARN.
// a placeholder target groups does not forward any traffic and is used when there is no default
// service (w/o path pattern) specified for the load balancer.
func (p *AWSELBv2Provider) ensurePlaceholderTargetGroup(loadBalancerName string, listenerPort int64) (string, error) {
	name := fmt.Sprintf(TemplateNoOpTargetGroupName, loadBalancerName)
	name = sanitizeAwsName(name)
	tg, err := p.svc.GetTargetGroupByName(name)
	if err != nil {
		return "", fmt.Errorf("Failed to lookup target group %s: %v", name, err)
	}
	if tg != nil {
		return *tg.TargetGroupArn, nil
	}

	tags := map[string]string{
		TagLoadBalancerRelation: loadBalancerName,
		TagOwner:                TagOwnerValue,
	}
	tgArn, err := p.svc.CreateTargetGroup(name, "HTTP", int64(80), int64(0), tags, false, 0)
	if err != nil {
		return "", fmt.Errorf("Failed to create placeholder target group %s: %v", name, err)
	}

	return tgArn, nil
}

// returns a map containing the availability zones the specified instances are running in as keys and a subnet in each
// zone as value.
func (p *AWSELBv2Provider) getEC2InstancesAvailabilityZones(instances []*elbsvc.EC2Instance) (map[string]string, error) {
	var subnetIDs []string
	for _, inst := range instances {
		subnetIDs = append(subnetIDs, inst.SubnetID)
	}

	subnetIDs = removeDuplicates(subnetIDs)
	ret := make(map[string]string)

	if len(subnetIDs) == 0 {
		return ret, nil
	}

	subnets, err := p.svc.DescribeSubnets(subnetIDs)
	if err != nil {
		return nil, fmt.Errorf("Failed to get instances availability zones: %v", err)
	}

	for _, s := range subnets {
		if _, ok := ret[*s.AvailabilityZone]; !ok {
			ret[*s.AvailabilityZone] = *s.SubnetId
		}
	}
	return ret, nil
}

// ensures that the given [az]subnet map contains at least two availability zones from
// the VPC of the load balancer.
func (p *AWSELBv2Provider) ensureLbAvailabilityZones(azSubnet map[string]string) error {
	logrus.Debugf("ensureTwoAvailabilityZones => azSubnet: %v", azSubnet)
	if len(azSubnet) > 1 {
		return nil
	}
	vpcAzSubnets, err := p.svc.GetAzSubnets()
	if err != nil {
		return err
	}

	for az, subnet := range vpcAzSubnets {
		if len(azSubnet) == 2 {
			break
		}
		if _, ok := azSubnet[az]; !ok {
			azSubnet[az] = subnet
		}
	}

	if len(azSubnet) > 1 {
		return nil
	}

	return fmt.Errorf("Could not ensure two subnets in two availability zones for VPC %s", p.vpcID)
}

// ensures that the specified load balancer security group grants access to the listener ports.
func (p *AWSELBv2Provider) ensureLoadBalancerIngress(securityGroupId string, config model.LBConfig) error {
	logrus.Debugf("ensureLoadBalancerIngressPermissions => securityGroupId: %s", securityGroupId)
	ports := make([]int64, len(config.Frontends))
	for i, fe := range config.Frontends {
		ports[i] = fe.Port
	}

	ipPerms := elbsvc.IPPermsAuthorizeInternetIngress(ports)
	err := p.svc.EnsureSecurityGroupIngress(securityGroupId, ipPerms)
	if err != nil {
		return fmt.Errorf("Failed to ensure load balancer security group ingress: %v", err)
	}

	return nil
}

// ensures that the specified load balancer security group is authorized to access the given instances.
func (p *AWSELBv2Provider) ensureInstanceIngress(securityGroupId string, instances []*elbsvc.EC2Instance) error {
	logrus.Debugf("ensureInstanceIngress => secGroupId: %s instances: %v", securityGroupId, instances)
	// find the security groups the load balancer is currently authorized in
	filters := []*ec2.Filter{
		elbsvc.NewEC2Filter("ip-permission.group-id", securityGroupId),
		elbsvc.NewEC2Filter("ip-permission.from-port", "0"),
		elbsvc.NewEC2Filter("ip-permission.to-port", "65535"),
		elbsvc.NewEC2Filter("ip-permission.protocol", "tcp"),
		elbsvc.NewEC2Filter("vpc-id", p.vpcID),
	}

	secGroups, err := p.svc.LookupSecurityGroupsByFilter(filters)
	if err != nil {
		return fmt.Errorf("Failed to ensure instance ingress: %v", err)
	}

	logrus.Debugf("Number of groups authorized in: %d", len(secGroups))

	authorizedSecGroups := make([]string, len(secGroups))
	for i, sg := range secGroups {
		authorizedSecGroups[i] = *sg.GroupId
	}

	// find the security groups we need to authorized the load balancer in
	var requiredSecGroups []string
	if id, found := elbsvc.InstancesSecGroupIntersection(instances); found {
		requiredSecGroups = append(requiredSecGroups, id)
	} else {
		for _, instance := range instances {
			ids := instance.SecurityGroups
			if len(ids) == 0 {
				continue
			}
			// trying to be deterministic
			sort.Strings(ids)
			requiredSecGroups = append(requiredSecGroups, ids[0])
		}
		requiredSecGroups = removeDuplicates(requiredSecGroups)
	}

	authorizeInSecGroups := differenceStringSlice(requiredSecGroups, authorizedSecGroups)
	revokeFromSecGroups := differenceStringSlice(authorizedSecGroups, requiredSecGroups)
	logrus.Debugf("authorizeInSecGroups: %v / revokeFromSecGroups: %v", authorizeInSecGroups, revokeFromSecGroups)

	// TODO: limit permissions to the target and health check ports
	ipPerms := elbsvc.IPPermsAuthorizeSecurityGroupIngress(securityGroupId, int64(0), int64(65535))
	for _, id := range authorizeInSecGroups {
		if err := p.svc.AuthorizeSecurityGroupIngress(id, ipPerms); err != nil {
			return fmt.Errorf("Failed to ensure instance ingress: %v", err)
		}
	}

	for _, id := range revokeFromSecGroups {
		if err := p.svc.RevokeSecurityGroupIngress(id, ipPerms); err != nil {
			return fmt.Errorf("Failed to ensure instance ingress: %v", err)
		}
	}

	return nil
}

// returns the ID of the security group for the specified load balancer.
func (p *AWSELBv2Provider) getLBSecurityGroupID(loadBalancerName string) (string, error) {
	name := fmt.Sprintf(TemplateLBSecurityGroupName, PrefixSecurityGroupName, loadBalancerName)
	return p.svc.EnsureSecurityGroup(name, LBSecurityGroupDesc)
}
