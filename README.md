external-lb (advanced branch)
==========
Rancher service facilitating integration of rancher with external load balancer providers. This service creates and manages external load balancers to load balance services created in Rancher.
Initial version supports AWS ELB Application Load Balancer; but a pluggable provider model makes it easy to implement other providers later.

Design
==========
* Gets deployed as a Rancher service containerized app. 

* Any service that should be load balanced by an external provider must have exposed a public port and the label 'io.rancher.service.external_lb.endpoint'

* The value of this label should should be a valid name that can be used to create a new load balancer on the provider side.

* The external-lb service will fetch info from rancher-metadata server at a periodic interval, then compare it with the data returned by the LB provider, and propagate the changes to the LB provider.

Contact
========
For bugs, questions, comments, corrections, suggestions, etc., open an issue in
 [rancher/rancher](//github.com/rancher/rancher/issues).

Or just [click here](//github.com/rancher/rancher/issues/new?title=%5Brancher-dns%5D%20) to create a new issue.

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
