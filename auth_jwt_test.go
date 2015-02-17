package rest

import (
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/dgrijalva/jwt-go"
	"testing"
	"time"
)

type DecoderToken struct {
	Token string `json:"token"`
}

func makeTokenString(username string, key []byte) string {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["id"] = "admin"
	token.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	token.Claims["orig_iat"] = time.Now().Unix()
	tokenString, _ := token.SignedString(key)
	return tokenString
}

func TestAuthJWT(t *testing.T) {
	key := []byte("secret key")

	// the middleware to test
	authMiddleware := &JWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string) bool {
			if userId == "admin" && password == "admin" {
				return true
			}
			return false
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
	loginApi := rest.NewApi()
	loginApi.SetApp(rest.AppSimple(authMiddleware.LoginHandler))

	// wrong login
	wrongLoginCreds := map[string]string{"username": "admin", "password": "admIn"}
	wrongLoginReq := test.MakeSimpleRequest("POST", "http://localhost/", wrongLoginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), wrongLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// empty login
	emptyLoginCreds := map[string]string{}
	emptyLoginReq := test.MakeSimpleRequest("POST", "http://localhost/", emptyLoginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), emptyLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// correct login
	before := time.Now().Unix()
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/", loginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)
	newToken, err := jwt.Parse(nToken.Token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Errorf("Received new token with wrong signature", err)
	}

	if newToken.Claims["id"].(string) != "admin" ||
		int64(newToken.Claims["exp"].(float64)) < before {
		t.Errorf("Received new token with wrong data")
	}

	refreshApi := rest.NewApi()
	refreshApi.Use(authMiddleware)
	refreshApi.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	// refresh with expired max refresh
	unrefreshableToken := jwt.New(jwt.GetSigningMethod("HS256"))
	unrefreshableToken.Claims["id"] = "admin"
	// the combination actually doesn't make sense but is ok for the test
	unrefreshableToken.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	unrefreshableToken.Claims["orig_iat"] = 0
	tokenString, _ = unrefreshableToken.SignedString(key)

	unrefreshableReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	unrefreshableReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshApi.MakeHandler(), unrefreshableReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// valid refresh
	// the combination actually doesn't make sense but is ok for the test
	refreshableToken := jwt.New(jwt.GetSigningMethod("HS256"))
	refreshableToken.Claims["id"] = "admin"
	refreshableToken.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	refreshableToken.Claims["orig_iat"] = time.Now().Unix()
	tokenString, _ = refreshableToken.SignedString(key)

	validRefreshReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	validRefreshReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshApi.MakeHandler(), validRefreshReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	rToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &rToken)
	refreshToken, err := jwt.Parse(rToken.Token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Errorf("Received refreshed token with wrong signature", err)
	}

	if refreshToken.Claims["id"].(string) != "admin" ||
		int64(refreshToken.Claims["orig_iat"].(float64)) != refreshableToken.Claims["orig_iat"].(int64) ||
		int64(refreshToken.Claims["exp"].(float64)) < refreshableToken.Claims["exp"].(int64) {
		t.Errorf("Received refreshed token with wrong data")
	}
}
