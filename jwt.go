package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/hryktrd/jwtTest/app"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/gofrs/uuid"
)

// JWTController implements the jwt resource.
type JWTController struct {
	*goa.Controller
}

// NewJWTController creates a jwt controller.
func NewJWTController(service *goa.Service) *JWTController {
	return &JWTController{Controller: service.NewController("JWTController")}
}

// Secure runs the secure action.
func (c *JWTController) Secure(ctx *app.SecureJWTContext) error {
	// JWTController_Secure: start_implement

	// Retrieve the token claims
	token := jwt.ContextJWT(ctx)
	if token == nil {
		return fmt.Errorf("JWT token is missing from context") // internal error
	}
	claims := token.Claims.(jwtgo.MapClaims)

	// Use the claims to authorize
	subject := claims["sub"]
	if subject != "subject" {
		// A real app would probably use an "Unauthorized" response here
		res := &app.GoaJWTTestSuccess{OK: false}
		return ctx.OK(res)
	}

	res := &app.GoaJWTTestSuccess{OK: true}
	return ctx.OK(res)

	// JWTController_Secure: end_implement
}

// Signin runs the signin action.
func (c *JWTController) Signin(ctx *app.SigninJWTContext) error {
	// JWTController_Signin: start_implement

	b, err := ioutil.ReadFile("./jwtkey/jwt.key")
	if err != nil {
		return fmt.Errorf("read private key file: %s", err) // internal error
	}
	privKey, err := jwtgo.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return fmt.Errorf("failed to parse RSA private key: %s", err) // internal error
	}
	token := jwtgo.New(jwtgo.SigningMethodRS512)
	in3m := time.Now().Add(time.Duration(3) * time.Minute).Unix()
	token.Claims = jwtgo.MapClaims{
		"iss":    "Issuer",                         // who creates the token and signs it
		"aud":    "Audience",                       // to whom the token is intended to be sent
		"exp":    in3m,                             // time when the token will expire (10 minutes from now)
		"jti":    uuid.Must(uuid.NewV4()).String(), // a unique identifier for the token
		"iat":    time.Now().Unix(),                // when the token was issued/created (now)
		"nbf":    2,                                // time before which the token is not yet valid (2 minutes ago)
		"sub":    "subject",                        // the subject/principal is whom the token is about
		"scopes": "api:access",                     // token scope - not a standard claim
	}
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		return fmt.Errorf("failed to sign token: %s", err) // internal error
	}
	ctx.ResponseData.Header().Set("Authorization", "Bearer "+signedToken)
	return ctx.NoContent()

	return nil
	// JWTController_Signin: end_implement
}
