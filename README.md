# yorcoidc
OpenID connect client used by Yorc LEXIS plugins

## Usage

### Installation

```shell
go get github.com/lexis-project/yorcoidc
```

### Importing

```go
 import "github.com/lexis-project/yorcoidc"
```

### Get a Client

```go
 client := yorcoidc.GetClient(yorcDeploymentID, url, clientID, clientSecret, realm)
```

## Features

```go
// Client is the client interface to AAI service
type Client interface {
	// ExchangeToken exchanges a token to get an access and a refresh token for this client
	ExchangeToken(ctx context.Context, accessToken string) (string, string, error)
	// IsAccessTokenValid checks if an access token is still valid
	IsAccessTokenValid(ctx context.Context, accessToken string) (bool, error)
	// RefreshToken refreshes the access token
	RefreshToken(ctx context.Context) (string, string, error)
	// GetAccessToken returns the access token
	GetAccessToken() (string, error)
	// GetRefreshToken returns the refresh token
	GetRefreshToken() (string, error)
	// GetUserInfo returns info on the user (name, attributes, etc..)
	GetUserInfo(ctx context.Context, accessToken string) (UserInfo, error)
}
```
