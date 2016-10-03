package metadata

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/rancher/external-lb/model"
	"github.com/rancher/go-rancher-metadata/metadata"
	"strconv"
	"strings"
	"time"
)

const (
	metadataUrl = "http://rancher-metadata/2015-12-19"
)

const (
	serviceLabelEndpoint           = "io.rancher.service.external_lb.endpoint"
	serviceLabelEndpointLegacy     = "io.rancher.service.external_lb_endpoint"
	serviceLabelRegion						 = "io.rancher.service.external_lb.region"
	serviceLabelFrontendProtocol   = "io.rancher.service.external_lb.frontend_protocol"
	serviceLabelFrontendPort       = "io.rancher.service.external_lb.frontend_port"
	serviceLabelFrontendSSLCert    = "io.rancher.service.external_lb.frontend_ssl_cert"
	serviceLabelBackendPathPattern = "io.rancher.service.external_lb.backend_path_pattern"
	serviceLabelBackendProtocol    = "io.rancher.service.external_lb.backend_protocol"
	serviceLabelBackendPort        = "io.rancher.service.external_lb.backend_port"
	serviceLabelBackendStickiness  = "io.rancher.service.external_lb.backend_stickiness"
	serviceLabelHealthCheckPort    = "io.rancher.service.external_lb.health_check_port"
)

const (
	defaultFrontendProtocol = "HTTP"
	defaultBackendProtocol  = "HTTP"
	defaultFrontendPort     = int64(80)
)

type MetadataClient struct {
	MetadataClient  metadata.Client
	EnvironmentUUID string
}

func getEnvironmentUUID(m metadata.Client) (string, error) {
	timeout := 30 * time.Second
	var err error
	var stack metadata.Stack
	for i := 1 * time.Second; i < timeout; i *= time.Duration(2) {
		stack, err = m.GetSelfStack()
		if err != nil {
			logrus.Errorf("Error reading stack info: %v...will retry", err)
			time.Sleep(i)
		} else {
			return stack.EnvironmentUUID, nil
		}
	}

	return "", fmt.Errorf("Error reading stack info: %v", err)
}

func NewMetadataClient() (*MetadataClient, error) {
	logrus.Debug("Initializing rancher-metadata client")
	m, err := metadata.NewClientAndWait(metadataUrl)
	if err != nil {
		return nil, err
	}

	envUUID, err := getEnvironmentUUID(m)
	if err != nil {
		return nil, fmt.Errorf("Error reading stack metadata info: %v", err)
	}

	return &MetadataClient{
		MetadataClient:  m,
		EnvironmentUUID: envUUID,
	}, nil
}

func (m *MetadataClient) GetVersion() (string, error) {
	return m.MetadataClient.GetVersion()
}

func (m *MetadataClient) GetMetadataLBConfigs() (map[string]model.LBConfig, error) {
	endpoints := make(map[string]map[int64]model.LBFrontend)
	services, err := m.MetadataClient.GetServices()
	if err != nil {
		return nil, fmt.Errorf("Error reading services: %v", err)
	}

	for _, service := range services {
		endpoint, ok := service.Labels[serviceLabelEndpoint]
		if !ok {
			endpoint, ok = service.Labels[serviceLabelEndpointLegacy]
		}
		if !ok {
			continue
		}

		var awsRegion string
		if val, ok := service.Labels[serviceLabelRegion]; ok {
			awsRegion = val
		} else {
			awsRegion = ""
		}

		// label exists, configure external LB
		logrus.Debugf("Endpoint label exists for service : %s", service.Name)
		frontends := make(map[int64]model.LBFrontend)
		if existingFrontends, ok := endpoints[endpoint]; ok {
			frontends = existingFrontends
		}

		// get frontend properties
		var frontendProtocol string
		if val, ok := service.Labels[serviceLabelFrontendProtocol]; ok {
			frontendProtocol = val
		} else {
			frontendProtocol = defaultFrontendProtocol
		}

		var frontendPort int64
		if val, ok := service.Labels[serviceLabelFrontendPort]; ok {
			if intVal, err := strconv.ParseInt(val, 10, 0); err == nil {
				frontendPort = intVal
			} else {
				logrus.Errorf("Skipping LB configuration for service %s: "+
					"Could not parse value of label '%s' to integer: %v",
					service.Name, serviceLabelFrontendPort, err)
				continue
			}
		} else {
			frontendPort = defaultFrontendPort
		}

		var frontendCert string
		if val, ok := service.Labels[serviceLabelFrontendSSLCert]; ok {
			frontendCert = val
		}

		// check if there is an existing frontend spec for that port
		var frontend model.LBFrontend
		if fe, ok := frontends[frontendPort]; ok {
			if fe.Protocol != frontendProtocol || fe.Certificate != frontendCert {
				logrus.Errorf("Skipping LB configuration for service %s: "+
					"Frontend specs conflict with frontend specs of another service.",
					service.Name)
				continue
			}
			frontend = fe
		} else {
			frontend = model.LBFrontend{
				Port:        frontendPort,
				Protocol:    frontendProtocol,
				Certificate: frontendCert,
			}
		}

		// verify that a certificate is specified for HTTPS frontends
		if frontend.Protocol == "HTTPS" && frontend.Certificate == "" {
			logrus.Errorf("Skipping LB configuration for service %s: "+
				"Certificate not specified for HTTPS frontend.",
				service.Name)
			continue
		}

		// get target pool properties
		var backendProtocol string
		if val, ok := service.Labels[serviceLabelBackendProtocol]; ok {
			backendProtocol = val
		} else {
			backendProtocol = defaultBackendProtocol
		}

		var pathPattern string
		if val, ok := service.Labels[serviceLabelBackendPathPattern]; ok {
			pathPattern = val
		}

		var stickiness bool
		if val, ok := service.Labels[serviceLabelBackendStickiness]; ok {
			if stickiness, err = strconv.ParseBool(val); err != nil {
				logrus.Errorf("Skipping LB configuration for service %s: "+
					"Could not parse value of label '%s' to boolean: %v",
					service.Name, serviceLabelBackendStickiness, err)
				continue
			}
		}

		var portString string
		if val, ok := service.Labels[serviceLabelBackendPort]; ok {
			portString = val
		} else {
			if len(service.Ports) == 0 {
				logrus.Warnf("Skipping LB configuration for service %s: "+
					"Service does not have any exposed ports", service.Name)
				continue
			}
			// default to the first exposed port of the service
			portspec := strings.Split(service.Ports[0], ":")
			if len(portspec) != 2 {
				logrus.Errorf("Skipping LB configuration for service %s: "+
					"Unexpected format of service port field: %s",
					service.Name, service.Ports[0])
				continue
			}
			portString = portspec[0]
		}

		var backendPort int64
		if backendPort, err = strconv.ParseInt(portString, 10, 0); err != nil {
			logrus.Errorf("Skipping LB configuration for service %s: "+
				"Could not parse backend port spec '%s' to integer: %v",
				service.Name, portString, err)
			continue
		}

		healthCheckPort := backendPort
		if val, ok := service.Labels[serviceLabelHealthCheckPort]; ok {
			if healthCheckPort, err = strconv.ParseInt(val, 10, 32); err != nil {
				logrus.Errorf("Skipping LB configuration for service %s: "+
					"Could not parse value of label '%s' to integer: %v",
					service.Name, serviceLabelHealthCheckPort, err)
				continue
			}
		}

		targetPoolName := service.Name + "_" + service.StackName + "_" + m.EnvironmentUUID
		targetPool := model.LBTargetPool{
			Name:            targetPoolName,
			Protocol:        backendProtocol,
			Port:            backendPort,
			PathPattern:     pathPattern,
			StickySessions:  stickiness,
			HealthCheckPort: healthCheckPort,
		}

		// populate the target pool with the target IPs
		if err := m.getContainerLBTargets(&targetPool, service); err != nil {
			logrus.Errorf("Skipping LB configuration for service %s: %v",
				service.Name, err)
			continue
		}

		frontend.TargetPools = append(frontend.TargetPools, targetPool)
		frontends[frontendPort] = frontend
		endpoints[endpoint] = frontends
	}

	lbConfigs := make(map[string]model.LBConfig)
	for endpoint, frontendMap := range endpoints {
		var frontends []model.LBFrontend
		for _, fe := range frontendMap {
			frontends = append(frontends, fe)
		}
		config := model.LBConfig{
			EndpointName: endpoint,
			AwsRegion:		awsRegion,
			Frontends:    frontends,
		}
		lbConfigs[endpoint] = config
	}

	return lbConfigs, nil
}

func (m *MetadataClient) getContainerLBTargets(targetPool *model.LBTargetPool, service metadata.Service) error {
	for _, container := range service.Containers {
		if !containerStateOK(container) {
			logrus.Debugf("Skipping container %s with state '%s' and health '%s'",
				container.Name, container.State, container.HealthState)
			continue
		}
		for _, port := range container.Ports {
			// split the container port to get the publicip:port
			portspec := strings.Split(port, ":")
			if len(portspec) != 3 {
				logrus.Warnf("Unexpected format of port spec for container %s: %s", container.Name, port)
				continue
			}

			containerPort, err := strconv.ParseInt(portspec[1], 10, 0)
			if err != nil {
				logrus.Warnf("Failed to parse container port '%s' to integer: %v", portspec[1], err)
				continue
			}

			if containerPort != targetPool.Port {
				logrus.Debugf("Container portspec '%s' does not match target pool port %d", port, targetPool.Port)
				continue
			}

			targetPool.TargetIPs = append(targetPool.TargetIPs, portspec[0])
		}
	}

	logrus.Debugf("Found %d target IPs for service %s", len(targetPool.TargetIPs), service.Name)
	return nil
}

func containerStateOK(container metadata.Container) bool {
	switch container.State {
	case "running":
	default:
		return false
	}

	switch container.HealthState {
	case "healthy":
	case "updating-healthy":
	case "":
	default:
		return false
	}

	return true
}
