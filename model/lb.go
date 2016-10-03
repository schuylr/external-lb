package model

type LBConfig struct {
	EndpointName string
	AwsRegion 	 string
	Frontends    []LBFrontend
}

type LBFrontend struct {
	// Frontend listening port
	Port int64
	// Frontend protocol to use:
	// HTTP or HTTPS.
	Protocol string
	// Certificate to use when terminating
	// SSL on the load balancer.
	Certificate string
	// Target pools to route traffic to.
	TargetPools []LBTargetPool
}

type LBTargetPool struct {
	// Name of the target pool.
	Name string
	// Port to forward traffic to.
	Port int64
	// Protocol to use for forwarding traffic:
	// HTTP or HTTPS.
	Protocol string
	// Path pattern to match in request in
	// order to forward to this target pool.
	PathPattern string
	// IP addresses to forward traffic to.
	TargetIPs []string
	// Whether to enable sticky sessions
	// for this target pool.
	StickySessions bool
	// Port that should be used to perform
	// health checks on the targets. Defaults
	// to target port.
	HealthCheckPort int64
}
