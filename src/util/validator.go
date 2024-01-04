package util

// util 模块不要引入其它内部模块
import (
	"github.com/go-playground/validator/v10"
)

var Validator *validator.Validate

func init() {
	Validator = validator.New()

	// Validator.RegisterCustomTypeFunc(ValidateContent, CBORRaw{})
}

// func ValidateContent(field reflect.Value) interface{} {
// 	if data, ok := field.Interface().(CBORRaw); ok {

// 		val := content.DocumentNode{}
// 		err := cbor.Unmarshal(data, &val)
// 		if err == nil {
// 			return val
// 		}
// 		// handle the error how you want
// 	}

// 	return nil
// }
