package elbsvc

import (
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elbv2"
)

const SDKMaxRetries = 3

// ELBService is an abstraction over the AWS SDK that provides operations required to
// manage the life cycle of AWS ELBv2 load balancers in a specific region and VPC.
type ELBService struct {
	elbv2c   *elbv2.ELBV2
	ec2c     *ec2.EC2
	metadata *ec2metadata.EC2Metadata
	region   string
	vpcID    string
}

// NewService initializes and returns a new ELBService instance for the specified region and VPC
// using either the specified static credentials or the AWS SDK's default credential chain which
// looks up credentials in the following locations:
// - Environment variables: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
// - Instance IAM role
func NewService(accessKey, secretKey, region, vpcID string) (*ELBService, error) {
	logrus.Debugf("NewService => accessKey: ***, secretKey: ***, region %s, vpcID %s",
		region, vpcID)
	awsConfig := aws.NewConfig().
		WithLogger(aws.NewDefaultLogger()).
		WithRegion(region).
		WithMaxRetries(SDKMaxRetries)

	// if static credentials were specified overwrite the default credentials chain
	if accessKey != "" && secretKey != "" {
		creds := credentials.NewStaticCredentials(accessKey, secretKey, "")
		awsConfig = awsConfig.WithCredentials(creds)
	}

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	service := &ELBService{
		elbv2c:   elbv2.New(sess),
		ec2c:     ec2.New(sess),
		metadata: ec2metadata.New(sess),
		region:   region,
		vpcID:    vpcID,
	}

	return service, nil
}

// CheckAPIConnection checks both the connection and authorization at the AWS API.
func (svc *ELBService) CheckAPIConnection() error {
	_, err := svc.ec2c.DescribeInstances(&ec2.DescribeInstancesInput{
		DryRun: aws.Bool(true),
	})
	if err != nil && IsAWSErr(err, AWSErrDryRunOperation) {
		return nil
	}

	return err
}
