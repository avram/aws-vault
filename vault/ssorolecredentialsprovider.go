package vault

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/skratchdot/open-golang/open"
)

const (
	ssoClientName         = "aws-vault"
	ssoClientType         = "public"
	oAuthTokenGrantType   = "urn:ietf:params:oauth:grant-type:device_code"
	authorizationTemplate = "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . SSOOIDCClient
type SSOOIDCClient interface {
	CreateToken(*ssooidc.CreateTokenInput) (*ssooidc.CreateTokenOutput, error)
	RegisterClient(*ssooidc.RegisterClientInput) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(*ssooidc.StartDeviceAuthorizationInput) (*ssooidc.StartDeviceAuthorizationOutput, error)
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . SSOClient
type SSOClient interface {
	GetRoleCredentials(*sso.GetRoleCredentialsInput) (*sso.GetRoleCredentialsOutput, error)
}

// SSORoleCredentialsProvider creates temporary credentials for an SSO Role.
type SSORoleCredentialsProvider struct {
	OIDCProvider *SSOOIDCProvider
	SSOClient    SSOClient
	AccountID    string
	RoleName     string
	ExpiryWindow time.Duration
	credentials.Expiry
}

// Retrieve generates a new set of temporary credentials using SSO GetRoleCredentials.
func (p *SSORoleCredentialsProvider) Retrieve() (credentials.Value, error) {
	creds, err := p.GetRoleCredentials()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*creds.Expiration, p.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
	}, nil
}

func (p *SSORoleCredentialsProvider) GetRoleCredentials() (*sts.Credentials, error) {
	token, err := p.OIDCProvider.GetAccessToken()
	if err != nil {
		return nil, err
	}

	resp, err := p.SSOClient.GetRoleCredentials(&sso.GetRoleCredentialsInput{
		AccessToken: aws.String(token.Token),
		AccountId:   aws.String(p.AccountID),
		RoleName:    aws.String(p.RoleName),
	})
	if err != nil {
		return nil, err
	}

	expiration := aws.MillisecondsTimeValue(resp.RoleCredentials.Expiration)

	// This is needed because sessions.Store expects a sts.Credentials object.
	creds := &sts.Credentials{
		AccessKeyId:     resp.RoleCredentials.AccessKeyId,
		SecretAccessKey: resp.RoleCredentials.SecretAccessKey,
		SessionToken:    resp.RoleCredentials.SessionToken,
		Expiration:      aws.Time(expiration),
	}

	log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(expiration).String())

	return creds, nil
}

type SSOAccessToken struct {
	Token      string
	Expiration time.Time
}

type SSOOIDCProvider struct {
	OIDCClient           SSOOIDCClient
	StartURL             string
	DisableSystemBrowser bool
}

func (p *SSOOIDCProvider) GetAccessToken() (*SSOAccessToken, error) {
	client, err := p.OIDCClient.RegisterClient(&ssooidc.RegisterClientInput{
		ClientName: aws.String(ssoClientName),
		ClientType: aws.String(ssoClientType),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created new SSO client for %s (expires at: %s)", p.StartURL, time.Unix(aws.Int64Value(client.ClientSecretExpiresAt), 0))

	token, err := p.createClientToken(client)
	if err != nil {
		return nil, err
	}
	log.Printf("Created new SSO access token for %s (expires at: %s)", p.StartURL, token.Expiration.String())

	// FIXME: we're ignoring the expiry and not caching
	return token, nil
}

func (p *SSOOIDCProvider) createClientToken(creds *ssooidc.RegisterClientOutput) (*SSOAccessToken, error) {
	auth, err := p.OIDCClient.StartDeviceAuthorization(&ssooidc.StartDeviceAuthorizationInput{
		ClientId:     creds.ClientId,
		ClientSecret: creds.ClientSecret,
		StartUrl:     aws.String(p.StartURL),
	})
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, authorizationTemplate, aws.StringValue(auth.VerificationUriComplete))

	if !p.DisableSystemBrowser {
		if err := open.Run(aws.StringValue(auth.VerificationUriComplete)); err != nil {
			log.Printf("failed to open browser: %s", err)
		}
	}

	var (
		// These are the default values defined in the following RFC:
		// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
		slowDownDelay = 5 * time.Second
		retryInterval = 5 * time.Second
	)
	if i := aws.Int64Value(auth.Interval); i > 0 {
		retryInterval = time.Duration(i) * time.Second
	}

	for {
		t, err := p.OIDCClient.CreateToken(&ssooidc.CreateTokenInput{
			ClientId:     creds.ClientId,
			ClientSecret: creds.ClientSecret,
			DeviceCode:   auth.DeviceCode,
			GrantType:    aws.String(oAuthTokenGrantType),
		})
		if err != nil {
			e, ok := err.(awserr.Error)
			if !ok {
				return nil, err
			}
			switch e.Code() {
			case ssooidc.ErrCodeSlowDownException:
				retryInterval += slowDownDelay
				fallthrough
			case ssooidc.ErrCodeAuthorizationPendingException:
				time.Sleep(retryInterval)
				continue
			default:
				return nil, err
			}
		}
		expiresInSecs := time.Duration(aws.Int64Value(t.ExpiresIn)) * time.Second

		return &SSOAccessToken{
			Token:      aws.StringValue(t.AccessToken),
			Expiration: time.Now().Add(expiresInSecs),
		}, nil
	}
}
