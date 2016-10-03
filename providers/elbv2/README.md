AWS ELBv2 (Application Load Balancer) Provider
==========

### About AWS ELB Application Load Balancer
The new ELB Application Load Balancer option ([launched by AWS in August 2016](https://aws.amazon.com/blogs/aws/new-aws-application-load-balancer/)) runs at Layer 7, has support for content-based routing and natively supports the WebSocket and HTTP/2 protocols.

### About this provider
This provider dynamically creates and manages Application Load Balancers on AWS to load balance traffic for Rancher services that have an exposed port and the label `io.rancher.service.external_lb.endpoint`.
A single Application Load Balancer can be used to load balance traffic for multiple Rancher services by employing path-based routing rules.
The load balancer's behavior can be configured using a set of optional labels for the service(s) that are using it.

### Usage notes
* ELB load balancers can only forward traffic to EC2 instances running in the same VPC as the load balancer. Make sure that the services you are load balancing are scaled across hosts in a single VPC.
* To check the health of the application backends Elastic Load Balancing issues HTTP(S) GET requests on the target's port and path "/". Make sure your services respond with an HTTP status code 200 to these requests.

Configuration Labels
==========

| Label | Description | Default value |
|-----------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| io.rancher.service.external_lb.endpoint | The name of the ELBv2 load balancer to create and manage. The name must not be in use by an existing ELBv2 in your AWS account. It must consist of only alphanumeric characters or dashes and not be longer than 32 characters.  | `-` |
| io.rancher.service.external_lb.region | The region of the ELBv2 load balancer to create and manage. There must be a manager in the same region to create this ELB. | `""` |
| io.rancher.service.external_lb.frontend_protocol | The protocol to use for the listener. Valid values: "HTTP", "HTTPS" | `HTTP` |
| io.rancher.service.external_lb.frontend_port | The port to use for the listener. | `80` |
| io.rancher.service.external_lb.frontend_ssl_cert | The ARN of a SSL certificate in AWS Certificate Manager or AWS IAM. Required if protocol is set to HTTPS. | `-` |
| io.rancher.service.external_lb.backend_path_pattern | The path pattern to match in order to forward traffic to this service. If the label is omitted, the service will become the default target of the listener and all requests that don't match the path pattern of any other service will be forwarded to it. | `-` |
| io.rancher.service.external_lb.backend_protocol | The protocol to use when forwarding traffic to this service. | `HTTP` |
| io.rancher.service.external_lb.backend_port | The port to use when forwarding traffic to this service. Defaults to the first exposed port of the service. | `<Ports[0]>` |
| io.rancher.service.external_lb.backend_stickiness | Set to 'true' in order to enable sticky sessions for this service. | `false` |
| io.rancher.service.external_lb.health_check_port | The port ELB should use when performing health checks on the targets of this service. The default is to use the traffic backend port. Health checks are HTTP requests using the path `'/'` and expecting a HTTP 200 code in the response. | `-` |

Note: The only label required to create a fully working ELB Application Load Balancer for a service in Rancher is `io.rancher.service.external_lb.endpoint`. The other labels are optional.

Environment Variables
==========

The following environment variables are used to configure global options for this provider.

| Variable | Description | Default value |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|
| ELBV2_AWS_ACCESS_KEY | Your AWS Access Key. Make sure this key has sufficient permissions for the operations required to manage an ELB load balancer. | `-` |
| ELBV2_AWS_SECRET_KEY | Your AWS Secret Key. | `-` |
| ELBV2_AWS_REGION | By default the load balancer will be created in the region of the instance this service is running on. You can override the region by setting this variable. | `-` |
| ELBV2_AWS_VPCID | By default the load balancer will be created in the VPC of the instance this service is running on. You can override the VPC by setting this variable to the VPC ID to use. | `-` |
| ELBV2_USE_PRIVATE_IP | If your EC2 instances are registered in Rancher with their private IP addresses, then set this variable to `true`. | `false` |
| ELBV2_CONNECTION_TIMEOUT | The connection idle timeout in seconds for the load balancers. Valid range: 1-3600. | `60` |
| ELBV2_ACCESS_LOGS_ENABLED | Set this to `true` to enable access logging for the load balancers. Logs are stored in the specified S3 bucket. | `false` |
| ELBV2_ACCESS_LOGS_BUCKET | The name of the S3 bucket to store the access logs in. It must be located in the same region as the load balancer and have a bucket policy granting ELB write permissions. | `-` |
| ELBV2_ACCESS_LOGS_PREFIX | An optional S3 bucket prefix. If not specified the logs are stored in the root of the bucket. | `-` |

Note: Instead of specifying AWS credentials as environment variables you can create an IAM policy and role and associate it with your EC2 instances.

Example IAM policy with the minimum permissions required
==========

TODO

License
=======
Copyright (c) 2016 [Rancher Labs, Inc.](http://rancher.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
