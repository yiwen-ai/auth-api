package bll

import (
	"context"
	"net/http"

	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/logging"
	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

type AuthN struct {
	svc *service.Userbase
	oss *service.OSS
}

func (b *AuthN) LoginOrNew(ctx context.Context, input *AuthNInput) (*AuthNSessionOutput, error) {
	output := SuccessResponse[AuthNSessionOutput]{}
	if err := b.svc.Post(ctx, "/v1/authn/login_or_new", input, &output); err != nil {
		return nil, err
	}

	go b.updateUserPicture(&output.Result, input.User.Picture)
	return &output.Result, nil
}

func (b *AuthN) updateUserPicture(input *AuthNSessionOutput, imgUrl string) {
	if input.UserCreatedAt == 0 || imgUrl == "" {
		return
	}

	ctx := conf.Config.GlobalCtx
	url, err := b.oss.SavePicture(ctx, input.Sub.Base64(), imgUrl)
	if err != nil {
		logging.Errf("SavePicture for %s error: %v", input.UID.String(), err)
		return
	}
	update := UpdateUserInput{
		ID:        input.UID,
		UpdatedAt: input.UserCreatedAt,
		Picture:   url,
	}
	output := SuccessResponse[UserInfo]{}
	if err := b.svc.Patch(ctx, "/v1/user", &update, &output); err != nil {
		logging.Errf("updateUserPicture for %s error: %v", input.UID.String(), err)
	} else {
		logging.Infof("updateUserPicture for %s success, %s", input.UID.String(), url)
	}
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
