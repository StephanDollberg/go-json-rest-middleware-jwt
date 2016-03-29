package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/dgrijalva/jwt-go"
)

var (
	key = []byte("secret key")
)

type DecoderToken struct {
	Token string `json:"token"`
}

func makeTokenString(username string, key []byte) string {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["id"] = username
	token.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	token.Claims["orig_iat"] = time.Now().Unix()
	tokenString, _ := token.SignedString(key)
	return tokenString
}

func TestAuthJWT(t *testing.T) {

	// the middleware to test
	authMiddleware := &Middleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string) error {
			if userId == "admin" && password == "admin" {
				return nil
			}
			return errors.New("Username and passwork should be admin")
		},
		Authorizator: func(userId string, request *rest.Request) bool {
			if request.Method == "GET" {
				return true
			}
			return false
		},
	}

	// api for testing failure
	apiFailure := rest.NewApi()
	apiFailure.Use(authMiddleware)
	apiFailure.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		t.Error("Should never be executed")
	}))
	handler := apiFailure.MakeHandler()

	// simple request fails
	recorded := test.RunRequest(t, handler, test.MakeSimpleRequest("GET", "http://localhost/", nil))
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// auth with right cred and wrong method fails
	wrongMethodReq := test.MakeSimpleRequest("POST", "http://localhost/", nil)
	wrongMethodReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongMethodReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - bearer lower case
	wrongAuthFormat := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongAuthFormat.Header.Set("Authorization", "bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - no space after bearer
	wrongAuthFormat = test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongAuthFormat.Header.Set("Authorization", "bearer"+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - empty auth header
	wrongAuthFormat = test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongAuthFormat.Header.Set("Authorization", "")
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credt, right method but wrong priv key
	wrongPrivKeyReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongPrivKeyReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", []byte("sekret key")))
	recorded = test.RunRequest(t, handler, wrongPrivKeyReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credt, right method, right priv key but timeout
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["id"] = "admin"
	token.Claims["exp"] = 0
	tokenString, _ := token.SignedString(key)

	expiredTimestampReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	expiredTimestampReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, handler, expiredTimestampReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credt, right method, right priv, wrong signing method on request
	tokenBadSigning := jwt.New(jwt.GetSigningMethod("HS384"))
	tokenBadSigning.Claims["id"] = "admin"
	tokenBadSigning.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	tokenBadSigningString, _ := tokenBadSigning.SignedString(key)

	BadSigningReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	BadSigningReq.Header.Set("Authorization", "Bearer "+tokenBadSigningString)
	recorded = test.RunRequest(t, handler, BadSigningReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// api for testing success
	apiSuccess := rest.NewApi()
	apiSuccess.Use(authMiddleware)
	apiSuccess.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		if r.Env["REMOTE_USER"] == nil {
			t.Error("REMOTE_USER is nil")
		}
		user := r.Env["REMOTE_USER"].(string)
		if user != "admin" {
			t.Error("REMOTE_USER is expected to be 'admin'")
		}
		w.WriteJson(map[string]string{"Id": "123"})
	}))

	// auth with right cred and right method succeeds
	validReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	validReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, apiSuccess.MakeHandler(), validReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// login tests
	loginAPI := rest.NewApi()
	loginAPI.SetApp(rest.AppSimple(authMiddleware.LoginHandler))

	// wrong login
	wrongLoginCreds := map[string]string{"username": "admin", "password": "admIn"}
	wrongLoginReq := test.MakeSimpleRequest("POST", "http://localhost/", wrongLoginCreds)
	recorded = test.RunRequest(t, loginAPI.MakeHandler(), wrongLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// empty login
	emptyLoginCreds := map[string]string{}
	emptyLoginReq := test.MakeSimpleRequest("POST", "http://localhost/", emptyLoginCreds)
	recorded = test.RunRequest(t, loginAPI.MakeHandler(), emptyLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// correct login
	before := time.Now().Unix()
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/", loginCreds)
	recorded = test.RunRequest(t, loginAPI.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)
	newToken, err := jwt.Parse(nToken.Token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Errorf("Received new token with wrong signature %s", err)
	}

	if newToken.Claims["id"].(string) != "admin" ||
		int64(newToken.Claims["exp"].(float64)) < before {
		t.Errorf("Received new token with wrong data")
	}

	refreshAPI := rest.NewApi()
	refreshAPI.Use(authMiddleware)
	refreshAPI.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	// refresh with expired max refresh
	unrefreshableToken := jwt.New(jwt.GetSigningMethod("HS256"))
	unrefreshableToken.Claims["id"] = "admin"
	// the combination actually doesn't make sense but is ok for the test
	unrefreshableToken.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	unrefreshableToken.Claims["orig_iat"] = 0
	tokenString, _ = unrefreshableToken.SignedString(key)

	unrefreshableReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	unrefreshableReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshAPI.MakeHandler(), unrefreshableReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// valid refresh
	refreshableToken := jwt.New(jwt.GetSigningMethod("HS256"))
	refreshableToken.Claims["id"] = "admin"
	// we need to substract one to test the case where token is being created in
	// the same second as it is checked -> < wouldn't fail
	refreshableToken.Claims["exp"] = time.Now().Add(time.Hour).Unix() - 1
	refreshableToken.Claims["orig_iat"] = time.Now().Unix() - 1
	tokenString, _ = refreshableToken.SignedString(key)

	validRefreshReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	validRefreshReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshAPI.MakeHandler(), validRefreshReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	rToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &rToken)
	refreshToken, err := jwt.Parse(rToken.Token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Errorf("Received refreshed token with wrong signature %s", err)
	}

	if refreshToken.Claims["id"].(string) != "admin" ||
		int64(refreshToken.Claims["orig_iat"].(float64)) != refreshableToken.Claims["orig_iat"].(int64) ||
		int64(refreshToken.Claims["exp"].(float64)) < refreshableToken.Claims["exp"].(int64) {
		t.Errorf("Received refreshed token with wrong data")
	}
}

func TestAuthJWTPayload(t *testing.T) {
	authMiddleware := &Middleware{
		Realm:            "test zone",
		SigningAlgorithm: "HS256",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		Authenticator: func(userId string, password string) error {
			if userId == "admin" && password == "admin" {
				return nil
			}
			return errors.New("Username and passwork should be admin")
		},
		PayloadFunc: func(userId string) map[string]interface{} {
			// tests normal value
			// tests overwriting of reserved jwt values should have no effect
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
	}

	loginAPI := rest.NewApi()
	loginAPI.SetApp(rest.AppSimple(authMiddleware.LoginHandler))

	// correct payload
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/", loginCreds)
	recorded := test.RunRequest(t, loginAPI.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)
	newToken, err := jwt.Parse(nToken.Token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Errorf("Received new token with wrong signature %s", err)
	}

	if newToken.Claims["testkey"].(string) != "testval" || newToken.Claims["exp"].(float64) == 0 {
		t.Errorf("Received new token without payload")
	}

	// correct payload after refresh
	refreshAPI := rest.NewApi()
	refreshAPI.Use(authMiddleware)
	refreshAPI.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	refreshableToken := jwt.New(jwt.GetSigningMethod("HS256"))
	refreshableToken.Claims["id"] = "admin"
	refreshableToken.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	refreshableToken.Claims["orig_iat"] = time.Now().Unix()
	refreshableToken.Claims["testkey"] = "testval"
	tokenString, _ := refreshableToken.SignedString(key)

	validRefreshReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	validRefreshReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshAPI.MakeHandler(), validRefreshReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	rToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &rToken)
	refreshToken, err := jwt.Parse(rToken.Token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Errorf("Received refreshed token with wrong signature %s", err)
	}

	if refreshToken.Claims["testkey"].(string) != "testval" {
		t.Errorf("Received new token without payload")
	}

	// payload is accessible in request
	payloadAPI := rest.NewApi()
	payloadAPI.Use(authMiddleware)
	payloadAPI.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		testval := r.Env["JWT_PAYLOAD"].(map[string]interface{})["testkey"].(string)
		w.WriteJson(map[string]string{"testkey": testval})
	}))

	payloadToken := jwt.New(jwt.GetSigningMethod("HS256"))
	payloadToken.Claims["id"] = "admin"
	payloadToken.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	payloadToken.Claims["orig_iat"] = time.Now().Unix()
	payloadToken.Claims["testkey"] = "testval"
	payloadTokenString, _ := payloadToken.SignedString(key)

	payloadReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	payloadReq.Header.Set("Authorization", "Bearer "+payloadTokenString)
	recorded = test.RunRequest(t, payloadAPI.MakeHandler(), payloadReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	payload := map[string]string{}
	test.DecodeJsonPayload(recorded.Recorder, &payload)

	if payload["testkey"] != "testval" {
		t.Errorf("Received new token without payload")
	}

}

func TestClaimsDuringAuthorization(t *testing.T) {
	authMiddleware := &Middleware{
		Realm:            "test zone",
		SigningAlgorithm: "HS256",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		PayloadFunc: func(userId string) map[string]interface{} {
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(userId string, password string) error {
			// Not testing authentication, just authorization, so always return true
			return nil
		},
		Authorizator: func(userId string, request *rest.Request) bool {
			jwtClaims := ExtractClaims(request)

			// Check the actual claim, set in PayloadFunc
			return (jwtClaims["testkey"] == "testval")
		},
	}

	// Simple endpoint
	endpoint := func(w rest.ResponseWriter, r *rest.Request) {
		// Dummy endpoint, output doesn't really matter, we are checking
		// the code returned
		w.WriteJson(map[string]string{"Id": "123"})
	}

	// Setup simple app structure
	loginAPI := rest.NewApi()
	loginAPI.SetApp(rest.AppSimple(authMiddleware.LoginHandler))
	loginAPI.Use(&rest.IfMiddleware{
		// Only authenticate non /login requests
		Condition: func(request *rest.Request) bool {
			return request.URL.Path != "/login"
		},
		IfTrue: authMiddleware,
	})
	apiRouter, _ := rest.MakeRouter(
		rest.Post("/login", authMiddleware.LoginHandler),
		rest.Get("/", endpoint),
	)
	loginAPI.SetApp(apiRouter)

	// Authenticate
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/login", loginCreds)
	recorded := test.RunRequest(t, loginAPI.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// Decode received token, to be sent with endpoint request
	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)

	// Request endpoint, triggering Authorization.
	// If we get a 200 then the claims were available in Authorizator method
	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	req.Header.Set("Authorization", "Bearer "+nToken.Token)
	recorded = test.RunRequest(t, loginAPI.MakeHandler(), req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}

func TestAuthJWTasymmetricKeys(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	authMiddleware := &Middleware{
		Realm:            "test zone",
		SigningAlgorithm: "ES256",
		Key:              privateKey,
		VerifyKey:        &privateKey.PublicKey,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		PayloadFunc: func(userId string) map[string]interface{} {
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(userId string, password string) error {
			// Not testing authentication, just authorization, so always return true
			return nil
		},
		Authorizator: func(userId string, request *rest.Request) bool {
			jwtClaims := ExtractClaims(request)

			// Check the actual claim, set in PayloadFunc
			return (jwtClaims["testkey"] == "testval")
		},
	}

	// Simple endpoint
	endpoint := func(w rest.ResponseWriter, r *rest.Request) {
		// Dummy endpoint, output doesn't really matter, we are checking
		// the code returned
		w.WriteJson(map[string]string{"Id": "123"})
	}

	// Setup simple app structure
	loginAPI := rest.NewApi()
	loginAPI.SetApp(rest.AppSimple(authMiddleware.LoginHandler))
	loginAPI.Use(&rest.IfMiddleware{
		// Only authenticate non /login requests
		Condition: func(request *rest.Request) bool {
			return request.URL.Path != "/login"
		},
		IfTrue: authMiddleware,
	})
	apiRouter, _ := rest.MakeRouter(
		rest.Post("/login", authMiddleware.LoginHandler),
		rest.Get("/", endpoint),
	)
	loginAPI.SetApp(apiRouter)

	// Authenticate
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/login", loginCreds)
	recorded := test.RunRequest(t, loginAPI.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// Decode received token, to be sent with endpoint request
	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)

	// Request endpoint, triggering Authorization.
	// If we get a 200 then the claims were available in Authorizator method
	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	req.Header.Set("Authorization", "Bearer "+nToken.Token)
	recorded = test.RunRequest(t, loginAPI.MakeHandler(), req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}
