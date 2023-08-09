package bll

import (
	"context"

	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/logging"
	"github.com/yiwen-ai/auth-api/src/service"
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

	gctx := conf.WithGlobalCtx(ctx)
	go b.updateUserPicture(gctx, &output.Result, input.User.Picture)
	return &output.Result, nil
}

func (b *AuthN) updateUserPicture(gctx context.Context, input *AuthNSessionOutput, imgUrl string) {
	if input.UserCreatedAt == 0 || imgUrl == "" {
		return
	}

	conf.Config.ObtainJob()
	defer conf.Config.ReleaseJob()

	url, err := b.oss.SavePicture(gctx, input.Sub.Base64(), imgUrl)
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
	if err := b.svc.Patch(gctx, "/v1/user", &update, &output); err != nil {
		logging.Errf("updateUserPicture for %s error: %v", input.UID.String(), err)
	} else {
		logging.Infof("updateUserPicture for %s success, %s", input.UID.String(), url)
	}
}
