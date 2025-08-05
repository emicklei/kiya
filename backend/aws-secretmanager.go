package backend

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var _ Backend = (*AWSSecretManager)(nil)

// AWSSecretManager (asm) implements Backend for AWS Secret Manager service.
type AWSSecretManager struct {
	client *secretsmanager.Client
}

// NewAWSSecretManager returns a new AWSSecretManager with an initialized AWS SSM client.
func NewAWSSecretManager(ctx context.Context, p *Profile) (*AWSSecretManager, error) {
	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &AWSSecretManager{
		client: secretsmanager.NewFromConfig(cfg),
	}, nil
}

// CheckExists implements Backend.
func (m *AWSSecretManager) CheckExists(ctx context.Context, p *Profile, key string) (bool, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(key),
	}
	_, err := m.client.GetSecretValue(ctx, input)
	// other error?
	if err != nil {
		return false, err
	}
	return true, nil
}

// Close implements Backend.
func (m *AWSSecretManager) Close() error {
	// noop
	return nil
}

// Delete implements Backend.
func (m *AWSSecretManager) Delete(ctx context.Context, p *Profile, key string) error {
	input := &secretsmanager.DeleteSecretInput{
		SecretId: aws.String(key),
	}
	_, err := m.client.DeleteSecret(ctx, input)
	if err != nil {
		return err
	}
	return nil
}

// Get implements Backend.
func (m *AWSSecretManager) Get(ctx context.Context, p *Profile, key string) ([]byte, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(key),
	}
	//Secrets Manager returns the AWSCURRENT version.
	out, err := m.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, err
	}
	return out.SecretBinary, nil
}

// List implements Backend.
func (m *AWSSecretManager) List(ctx context.Context, p *Profile) (list []Key, err error) {
	var nextToken *string = nil
	done := false
	for !done {
		input := &secretsmanager.ListSecretsInput{
			MaxResults: aws.Int32(100), // AWS API max is 100
			NextToken:  nextToken,
		}
		out, err := m.client.ListSecrets(ctx, input)
		if err != nil {
			return nil, err
		}
		for _, each := range out.SecretList {
			key := Key{
				Name:      *each.Name,
				CreatedAt: *each.CreatedDate,
			}
			if each.Description != nil {
				key.Info = *each.Description
			}
			if each.OwningService != nil {
				key.Owner = *each.OwningService
			}
			list = append(list, key)
		}
		done = out.NextToken == nil
		nextToken = out.NextToken
	}
	return list, nil
}

// Put implements Backend.
func (m *AWSSecretManager) Put(ctx context.Context, p *Profile, key string, value string, overwrite bool) error {
	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/secretsmanager@v1.36.1#PutSecretValueInput
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(key),
		SecretString: aws.String(value),
	}
	_, err := m.client.PutSecretValue(ctx, input)
	if err != nil {
		return err
	}
	return nil
}

// SetParameter implements Backend.
func (m *AWSSecretManager) SetParameter(key string, value interface{}) {
	// noop
}
