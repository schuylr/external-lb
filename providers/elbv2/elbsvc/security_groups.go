package elbsvc

import (
	"fmt"
	"reflect"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// EnsureSecurityGroup returns the ID of the security group in the service's VPC matching
// the specified name. If it does not exists, it is created.
func (svc *ELBService) EnsureSecurityGroup(name, description string) (string, error) {
	logrus.Debugf("EnsureSecurityGroup => name: %s", name)
	sg, err := svc.GetSecurityGroupByName(name)
	if err != nil {
		return "", err
	}

	if sg != nil {
		logrus.Debugf("Found existing security group %s with ID %s", name, *sg.GroupId)
		return *sg.GroupId, nil
	}

	logrus.Debugf("Creating security group %s", name)
	params := &ec2.CreateSecurityGroupInput{
		Description: aws.String(description),
		GroupName:   aws.String(name),
		VpcId:       aws.String(svc.vpcID),
	}
	resp, err := svc.ec2c.CreateSecurityGroup(params)
	if err != nil {
		return "", fmt.Errorf("Failed to ensure security group %s: %v", name, err)
	}

	return *resp.GroupId, nil
}

// GetSecurityGroupByName returns an ec2.SecurityGroup struct for the security group
// matching the specified name in the service's VPC. Returns nil if such group does
// not exist.
func (svc *ELBService) GetSecurityGroupByName(name string) (*ec2.SecurityGroup, error) {
	logrus.Debugf("GetSecurityGroupID => name: %s", name)
	filters := []*ec2.Filter{
		NewEC2Filter("group-name", name),
		NewEC2Filter("vpc-id", svc.vpcID),
	}

	result, err := svc.LookupSecurityGroupsByFilter(filters)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, nil
	}

	return result[0], nil
}

// DeleteSecurityGroup deletes the security group specified by ID.
func (svc *ELBService) DeleteSecurityGroup(id string) error {
	logrus.Debugf("DeleteSecurityGroup => securityGroupId: %s", id)
	params := &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(id),
	}
	_, err := svc.ec2c.DeleteSecurityGroup(params)
	if err != nil && !IsAWSErr(err, AWSErrSecurityGroupNotFound) {
		return err
	}

	return nil
}

// EnsureSecurityGroupIngress ensures that no more than the specified ingress
// permissions are authorized in the specified security group.
func (svc *ELBService) EnsureSecurityGroupIngress(id string, ipPerms []*ec2.IpPermission) error {
	logrus.Debugf("EnsureSecurityGroupIngress => securityGroupId: %s", id)
	filters := []*ec2.Filter{
		NewEC2Filter("group-id", id),
		NewEC2Filter("vpc-id", svc.vpcID),
	}

	groups, err := svc.LookupSecurityGroupsByFilter(filters)
	if err != nil {
		return err
	}

	if groups == nil {
		return fmt.Errorf("Could not find security group with ID %s", id)
	}

	currentPerms := groups[0].IpPermissions
	var revokePerms, authorizePerms []*ec2.IpPermission
	for _, p1 := range currentPerms {
		revoke := true
		for _, p2 := range ipPerms {
			if reflect.DeepEqual(p1, p2) {
				revoke = false
				break
			}
		}
		if revoke {
			revokePerms = append(revokePerms, p1)
		}
	}
	for _, p1 := range ipPerms {
		add := true
		for _, p2 := range currentPerms {
			if reflect.DeepEqual(p1, p2) {
				add = false
				break
			}
		}
		if add {
			authorizePerms = append(authorizePerms, p1)
		}
	}

	logrus.Debugf("EnsureSecurityGroupIngress => revoke perms: %d, authorize perms: %d",
		len(revokePerms), len(authorizePerms))

	if len(revokePerms) > 0 {
		if err := svc.RevokeSecurityGroupIngress(id, revokePerms); err != nil {
			return err
		}
	}

	if len(authorizePerms) > 0 {
		if err := svc.AuthorizeSecurityGroupIngress(id, authorizePerms); err != nil {
			return err
		}
	}

	return nil
}

// LookupSecurityGroupsByFilter looks up security groups in the service's
// VPC matching the specified filter. Returns nil if none were found.
func (svc *ELBService) LookupSecurityGroupsByFilter(filters []*ec2.Filter) ([]*ec2.SecurityGroup, error) {
	logrus.Debug("LookupSecurityGroupsByFilter =>")
	params := &ec2.DescribeSecurityGroupsInput{
		Filters: filters,
	}
	resp, err := svc.ec2c.DescribeSecurityGroups(params)
	if err != nil {
		return nil, fmt.Errorf("DescribeSecurityGroups SDK error: %v", err)
	}

	logrus.Debugf("LookupSecurityGroupsByFilter => Found %d security groups", len(resp.SecurityGroups))

	if len(resp.SecurityGroups) > 0 {
		return resp.SecurityGroups, nil
	}

	return nil, nil
}

// AuthorizeSecurityGroupIngress authorizes the specified
// ec2.IpPermissions in the specified security group.
func (svc *ELBService) AuthorizeSecurityGroupIngress(id string, ipPerms []*ec2.IpPermission) error {
	logrus.Debugf("AuthorizeSecurityGroupIngress => id: %s", id)
	params := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       aws.String(id),
		IpPermissions: ipPerms,
	}
	_, err := svc.ec2c.AuthorizeSecurityGroupIngress(params)
	if err != nil {
		if IsAWSErr(err, AWSErrPermissionDuplicate) {
			if len(ipPerms) == 1 {
				return nil
			}
			// if one or more permissions are already authorized
			// we need to authorize the permissions individually
			for _, p := range ipPerms {
				params.IpPermissions = []*ec2.IpPermission{p}
				_, err := svc.ec2c.AuthorizeSecurityGroupIngress(params)
				if err != nil && !IsAWSErr(err, AWSErrPermissionDuplicate) {
					return fmt.Errorf("AuthorizeSecurityGroupIngress SDK error: %v", err)
				}
			}
			return nil
		}
		return err
	}

	return nil
}

// RevokeSecurityGroupIngress revokes the specified  permissions from the specified security group.
func (svc *ELBService) RevokeSecurityGroupIngress(id string, ipPerms []*ec2.IpPermission) error {
	logrus.Debugf("RevokeSecurityGroupIngress => id: %s", id)
	params := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       aws.String(id),
		IpPermissions: ipPerms,
	}
	_, err := svc.ec2c.RevokeSecurityGroupIngress(params)
	if err != nil {
		if IsAWSErr(err, AWSErrPermissionNotFound) {
			if len(ipPerms) == 1 {
				return nil
			}
			// if one or more permissions are already revoked
			// we need to revoke the permissions individually
			for _, p := range ipPerms {
				params.IpPermissions = []*ec2.IpPermission{p}
				_, err := svc.ec2c.RevokeSecurityGroupIngress(params)
				if err != nil && !IsAWSErr(err, AWSErrPermissionNotFound) {
					return fmt.Errorf("RevokeSecurityGroupIngress SDK error: %v", err)
				}
			}
			return nil
		}
		return err
	}

	return nil
}
