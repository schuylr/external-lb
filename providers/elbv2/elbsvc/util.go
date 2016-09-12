package elbsvc

import (
	"sort"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elbv2"
)

const (
	AWSErrPermissionNotFound     = "InvalidPermission.NotFound"
	AWSErrPermissionDuplicate    = "InvalidPermission.Duplicate"
	AWSErrSecurityGroupNotFound  = "InvalidGroup.NotFound"
	AwsErrSecurityGroupDuplicate = "InvalidGroup.Duplicate"
	AWSErrTargetGroupNotFound    = "TargetGroupNotFound"
	AWSErrRuleNotFound           = "RuleNotFound"
	AWSErrDependendyViolation    = "DependencyViolation"
	AWSErrDryRunOperation        = "DryRunOperation"
	AWSErrLoadBalancerNotFound   = "LoadBalancerNotFound"
)

func IPPermsAuthorizeSecurityGroupIngress(securityGroupID string, fromPort, toPort int64) []*ec2.IpPermission {
	return []*ec2.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(fromPort),
			ToPort:     aws.Int64(toPort),
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				{
					GroupId: aws.String(securityGroupID),
				},
			},
		},
	}
}

func IPPermsAuthorizeInternetIngress(tcpPorts []int64) []*ec2.IpPermission {
	ret := make([]*ec2.IpPermission, len(tcpPorts)+1)
	for i, port := range tcpPorts {
		ret[i] = &ec2.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(port),
			ToPort:     aws.Int64(port),
			IpRanges: []*ec2.IpRange{
				{
					CidrIp: aws.String("0.0.0.0/0"),
				},
			},
		}
	}

	// Required for MTU Path Discovery
	ret[len(tcpPorts)] = &ec2.IpPermission{
		IpProtocol: aws.String("icmp"),
		FromPort:   aws.Int64(3),
		ToPort:     aws.Int64(4),
		IpRanges: []*ec2.IpRange{
			{
				CidrIp: aws.String("0.0.0.0/0"),
			},
		},
	}

	return ret
}

func IsAWSErr(err error, code string) bool {
	switch e := err.(type) {
	case awserr.Error:
		if e.Code() == code {
			return true
		}
	}
	return false
}

func NewEC2Filter(name string, values ...string) *ec2.Filter {
	awsValues := make([]*string, len(values))
	for i, val := range values {
		awsValues[i] = aws.String(val)
	}
	return &ec2.Filter{
		Name:   aws.String(name),
		Values: awsValues,
	}
}

// takes a map[string]string and converts it to an elbv2.Tag slice.
func elbTags(tags map[string]string) []*elbv2.Tag {
	s := make([]*elbv2.Tag, len(tags))
	i := 0
	for k, v := range tags {
		s[i] = &elbv2.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		i++
	}
	return s
}

// takes an elbv2.Tag slice and converts it to a map[string]string.
func mapTags(tags []*elbv2.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[*t.Key] = *t.Value
	}
	return m
}

// tries to find an intersecting security group for the given instances.
func InstancesSecGroupIntersection(instances []*EC2Instance) (string, bool) {
	union := make(map[string]bool)
	intersects := make(map[string]bool)
	for _, instance := range instances {
		for _, id := range instance.SecurityGroups {
			union[id] = true
			intersects[id] = true
		}
	}

	for key, _ := range union {
		for _, instance := range instances {
			found := false
			for _, id := range instance.SecurityGroups {
				if id == key {
					found = true
					break
				}
			}
			if !found {
				delete(intersects, key)
				break
			}
		}
	}

	if len(intersects) > 0 {
		ids := make([]string, len(intersects))
		i := 0
		for id, _ := range intersects {
			ids[i] = id
			i++
		}
		// try to be deterministic
		sort.Strings(ids)
		return ids[0], true
	}

	return "", false
}
