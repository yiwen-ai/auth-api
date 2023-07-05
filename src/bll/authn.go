package bll

import (
	"context"
	"net/http"

	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

type AuthN struct {
	svc *service.Userbase
}

func (b *AuthN) LoginOrNew(ctx context.Context, input *AuthNInput) (*AuthNOutput, error) {
	output := SuccessResponse[AuthNOutput]{}
	if err := b.svc.Post(ctx, "/v1/authn/login_or_new", input, &output); err != nil {
		return nil, err
	}
	return &output.Result, nil
}

type githubUser struct {
	Sub     string `json:"login" cbor:"login"`
	Name    string `json:"name" cbor:"name"`
	Picture string `json:"avatar_url" cbor:"avatar_url"`
}

func (b *AuthN) GithubUser(ctx context.Context, cli *http.Client) (*AuthNInput, error) {
	user := &githubUser{}
	if err := util.RequestJSON(ctx, cli, "GET", "https://api.github.com/user", nil, user); err != nil {
		return nil, err
	}
	return &AuthNInput{
		Sub: user.Sub,
		User: UserInfo{
			Name:    user.Name,
			Picture: user.Picture,
		},
	}, nil
}
