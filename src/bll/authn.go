package bll

import (
	"context"

	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/logging"
	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

type AuthN struct {
	svc service.APIHost
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
	picture := input.Sub.Base64()
	if imgUrl == "" || input.Picture != "" {
		return
	}

	conf.Config.ObtainJob()
	defer conf.Config.ReleaseJob()

	url, err := b.oss.SavePicture(gctx, picture, imgUrl)
	if err != nil {
		logging.Errf("SavePicture for %s error: %v", input.UID.String(), err)
		return
	}

	update := struct {
		ID   util.ID `json:"id" cbor:"id"`
		Logo string  `json:"logo" cbor:"logo"`
	}{
		ID:   *input.UID,
		Logo: url,
	}
	output := SuccessResponse[any]{}
	if err := b.svc.Patch(gctx, "/v1/group", &update, &output); err != nil {
		logging.Errf("updateGroupPicture for %s error: %v", input.UID.String(), err)
	} else {
		logging.Infof("updateGroupPicture for %s success, %s", input.UID.String(), url)
	}

	updateUser := UpdateUserInput{
		ID:      input.UID,
		Picture: url,
	}
	if err := b.svc.Patch(gctx, "/v1/user", &updateUser, &output); err != nil {
		logging.Errf("updateUserPicture for %s error: %v", input.UID.String(), err)
	} else {
		logging.Infof("updateUserPicture for %s success, %s", input.UID.String(), url)
	}
}
