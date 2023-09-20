package main

// imports
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// keypair struct
type Key struct {
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	fingerprint string
	expireTime  time.Time
}

// auth payload data
type Credentials struct {
	Password string //`json:"password"`
	Username string //`json:"username"`
}

// jwt claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// token payload data
type Token struct {
	Username string
	Exp      int
}

// returned when jwks hit
type JWKSentry struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var SigningKeys = make(map[string]*Key)
var ExpiredKeys = make(map[string]*Key)

// generate keypair
func generateKeypair(expired bool) *Key {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}

	// validate it
	err = privateKey.Validate()
	if err != nil {
		return nil
	}

	// set expiry
	var expiry time.Time
	if expired {
		expiry = time.Now().Add(-time.Hour * 24)
	} else {
		expiry = time.Now().Add(time.Minute * 10)
	}

	// generate public key and fingerprint
	publicKey := generatePublicKey(privateKey)
	fingerprint := generateKeyFingerprint(privateKey)

	// store in a struct
	key := Key{
		privateKey:  privateKey,
		publicKey:   publicKey,
		fingerprint: fingerprint,
		expireTime:  expiry,
	}

	// return pointer to struct
	return &key
}

// encode public key to pem (readable)
func encodePublicPEM(privateKey *rsa.PrivateKey) *pem.Block {
	publicKey := &privateKey.PublicKey
	publicPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	return publicPEM
}

// generate public key from private key
func generatePublicKey(privateKey *rsa.PrivateKey) *rsa.PublicKey {
	publicKey := &privateKey.PublicKey
	return publicKey
}

// generate sha256 hash of public key for id
func generateKeyFingerprint(privateKey *rsa.PrivateKey) string {
	keyID := sha256.Sum256(encodePublicPEM(privateKey).Bytes)
	fingerprint := hex.EncodeToString(keyID[:])

	return fingerprint
}

func auth(w http.ResponseWriter, req *http.Request) {
	// verify method
	method := req.Method

	switch method {
	case http.MethodPost:
		// check if expired
		requestingExpiredJWT := req.URL.Query().Get("expired")
		if requestingExpiredJWT == "true" {
			generateExpiredJWT(w, req)
		} else {
			generateUnexpiredJWT(w, req)
		}
	// not allowed
	default:
		http.Error(w, "Unsupported HTTP method", http.StatusMethodNotAllowed)
		return
	}
}

func jwks(w http.ResponseWriter, req *http.Request) {
	method := req.Method

	// verify proper method
	switch method {
	case http.MethodGet:
		// json crap
		var jwksMap = make(map[string][1]*JWKSentry)
		var ShareableKeys [1]*JWKSentry
		// has to be an array so that the brackets parse out as []
		// package all valid keys
		for fp, key := range SigningKeys {
			ShareableKeys[0] = &JWKSentry{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: fp,
				N:   b64.URLEncoding.EncodeToString(key.publicKey.N.Bytes()),
				E:   b64.URLEncoding.EncodeToString(big.NewInt(int64(key.publicKey.E)).Bytes()),
			}
		}
		// package all
		jwksMap["keys"] = ShareableKeys
		jsonKeys, err := json.Marshal(jwksMap)
		// stop if failed
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// send keys
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonKeys)
	// not allowed
	default:
		http.Error(w, "Unsupported HTTP method", http.StatusMethodNotAllowed)
		return
	}
}

func generateUnexpiredJWT(w http.ResponseWriter, req *http.Request) {
	var creds Credentials

	// challenge: bad request because runner was not sending payload as this is a prject and I was assuming that it would be sending payload all the time.
	err := json.NewDecoder(req.Body).Decode(&creds)
	if err != nil {
		creds.Username = "VeryCoolUserTotallyNotInsecureToHaveThisButItIsOkayBecauseThisIsASchoolAssignment"
	}

	// generate valid jwt
	expirationTime := time.Now().Add(time.Minute * 5)
	// package claims
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// generate token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// this is unsafe and WILL NOT WORK WITH MORE THAN 1 SIGNING KEY but lol idk how to select the first entry
	for fingerprint := range SigningKeys {
		// add kid
		token.Header["kid"] = fingerprint
		// sign token
		tokenString, err := token.SignedString(SigningKeys[fingerprint].privateKey)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// send token
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(tokenString))
	}
}

func generateExpiredJWT(w http.ResponseWriter, req *http.Request) {
	var creds Credentials

	// encode payload
	err := json.NewDecoder(req.Body).Decode(&creds)
	if err != nil {
		// challenge: bad request because runner was not sending payload as this is a prject and I was assuming that it would be sending payload all the time.
		creds.Username = "VeryCoolUserTotallyNotInsecureToHaveThisButItIsOkayBecauseThisIsASchoolAssignment"
	}

	// generate expired jwt
	expirationTime := time.Now().Add(-time.Minute * 5)
	// package claims
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// generate token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// this is unsafe and WILL NOT WORK WITH MORE THAN 1 SIGNING KEY but lol idk how to select the first entry
	for fingerprint := range ExpiredKeys {
		// add kid
		token.Header["kid"] = fingerprint
		// sign token
		tokenString, err := token.SignedString(ExpiredKeys[fingerprint].privateKey)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// send token
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(tokenString))
	}
}

// shut up go compiler
func UNUSED(x ...interface{}) {}

// generate variable amount of valid and expired keys
func preGame() {
	var key *Key
	for i := range [1]int{} {
		UNUSED(i)
		key = generateKeypair(false)
		SigningKeys[key.fingerprint] = key
	}
	for i := range [1]int{} {
		UNUSED(i)
		key = generateKeypair(true)
		ExpiredKeys[key.fingerprint] = key
	}
}

func main() {
	// moved out of main to allow testing
	preGame()

	http.HandleFunc("/auth", auth)

	http.HandleFunc("/.well-known/jwks.json", jwks)

	http.ListenAndServe(":8080", nil)
}
