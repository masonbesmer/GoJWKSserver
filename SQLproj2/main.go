package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	pregame()
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

var (
	db *sql.DB
)

// done
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("Failed to init DB: %s", err)
	}
	// drop the "keys" table and recreate
	_, err = db.Exec(`DROP TABLE keys`)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}
}

// done
func genKeys() {
	// generate good key
	goodPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	privKeyData := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(goodPrivKey),
	}

	goodExpiry := time.Now().Add(time.Hour) // expiration time
	_, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", privKeyData.Bytes, goodExpiry.Unix())
	if err != nil {
		log.Fatal(err)
	}

	// Generate an expired key pair
	expiredPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	expKeyData := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(expiredPrivKey),
	}

	expExpiry := time.Now().Add(-time.Hour)
	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", expKeyData.Bytes, expExpiry.Unix())
	if err != nil {
		log.Fatal(err)
	}
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var (
		signingKey *rsa.PrivateKey
		keyID      string
		exp        int64
	)
	goodKeys, err := retrieveKeysFromDatabase(false)
	if err != nil {
		log.Fatal(err)
	}
	badKeys, err := retrieveKeysFromDatabase(true)
	if err != nil {
		log.Fatal(err)
	}
	// Default to the good key
	signingKey = goodKeys[0].Key
	keyID = strconv.Itoa(goodKeys[0].Kid)
	exp = goodKeys[0].Expiry.Unix()

	// If the expired query parameter is set, use the expired key
	if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
		signingKey = badKeys[0].Key
		keyID = strconv.Itoa(badKeys[0].Kid)
		exp = badKeys[0].Expiry.Unix()
	}

	// Create the token with the expiry
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": exp,
	})
	// Set the key ID header
	token.Header["kid"] = keyID
	// Sign the token with the private key
	signedToken, _ := token.SignedString(signingKey)

	_, _ = w.Write([]byte(signedToken))
}

type (
	JWKS struct {
		Keys []JWK `json:"keys"`
	}
	JWK struct {
		KID       string `json:"kid"`
		Algorithm string `json:"alg"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
)

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	goodKeys, err := retrieveKeysFromDatabase(false)
	if err != nil {
		log.Fatal(err)
	}
	base64URLEncode := func(b *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(b.Bytes())
	}
	publicKey := goodKeys[0]
	resp := JWKS{
		Keys: []JWK{
			{
				KID:       strconv.Itoa(publicKey.Kid),
				Algorithm: "RS256",
				KeyType:   "RSA",
				Use:       "sig",
				N:         base64URLEncode(publicKey.Key.PublicKey.N),
				E:         base64URLEncode(big.NewInt(int64(publicKey.Key.PublicKey.E))),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func retrieveKeysFromDatabase(expired bool) ([]struct {
	Kid    int
	Key    *rsa.PrivateKey
	Expiry time.Time
}, error) {
	var rows *sql.Rows
	var err error
	if expired {
		rows, err = db.Query("SELECT kid, key, exp FROM keys WHERE exp < ?", time.Now().Unix())
	} else {
		rows, err = db.Query("SELECT kid, key, exp FROM keys WHERE exp > ?", time.Now().Unix())
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []struct {
		Kid    int
		Key    *rsa.PrivateKey
		Expiry time.Time
	}

	for rows.Next() {
		var kid int
		var keyBytes []byte
		var expiry int64

		if err := rows.Scan(&kid, &keyBytes, &expiry); err != nil {
			return nil, err
		}

		// Parse the key data
		key, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}

		expiryTime := time.Unix(expiry, 0)

		keys = append(keys, struct {
			Kid    int
			Key    *rsa.PrivateKey
			Expiry time.Time
		}{Kid: kid, Key: key, Expiry: expiryTime})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func pregame() {
	initDB()
	genKeys()
}
