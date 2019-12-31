package agentjwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"math/big"
	"net"
	"os"
	"reflect"
	"time"
)

// MAX_TOKEN_DURATION is the maximum duration allowed on a signed token.
const MAX_TOKEN_DURATION = 300

// SigningMethodRSAAgent is a JWT Signing method that produces RS256 signatures from a running ssh-agent.
type SigningMethodRSAAgent struct {
	Name string
	Hash crypto.Hash
}

// Alg returns the name of the name of the algorithm used by the signing method
func (m *SigningMethodRSAAgent) Alg() string {
	return m.Name
}

// Verify verifies the signature on the JWT Token in the normal JWT RS256 fashion
func (m *SigningMethodRSAAgent) Verify(signingString, signature string, key interface{}) (err error) {
	var sig []byte
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		err = errors.Wrap(err, "failed to decode signature")
		return err
	}

	var rsaKey rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(rsa.PublicKey); !ok {
		return jwt.ErrInvalidKeyType
	}

	// Create hasher
	if !m.Hash.Available() {
		err = errors.Wrap(err, "failed checking hash availability")
		return jwt.ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Verify the signature
	err = rsa.VerifyPKCS1v15(&rsaKey, m.Hash, hasher.Sum(nil), sig)
	if err != nil {
		err = errors.Wrap(err, "authentication failed")
		return err
	}

	return err
}

// Sign sends a request to the running ssh-agent to sign the header and claims of the JWT.  This is pretty much the normal RS256 mechanism, but it doesn't require the private key in order to sign.  The private key is held by the ssh-agent.
func (m *SigningMethodRSAAgent) Sign(signingString string, key interface{}) (sig string, err error) {
	var pubKey ssh.PublicKey
	var ok bool

	if pubKey, ok = key.(ssh.PublicKey); !ok {
		err = errors.New(fmt.Sprintf("Invalid key type: %s", reflect.TypeOf(key).String()))
		return sig, err
	}

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		err = errors.New("No SSH_AUTH_SOCK in env")
		return sig, err
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		err = errors.Wrap(err, "failed to connect to SSH_AUTH_SOCK")
		return sig, err
	}

	a := agent.NewClient(conn)

	if a != nil {
		signature, err := a.SignWithFlags(pubKey, []byte(signingString), agent.SignatureFlagRsaSha256)
		if err != nil {
			err = errors.Wrap(err, "failed to sign with agent")
			return sig, err
		}

		sig = jwt.EncodeSegment(signature.Blob)
	}

	return sig, err
}

// ParsePubkeySignedToken takes a token string that has been signed by the ssh-agent (RS256)
// The Subject of the token (user authenticating) is part of the claims on the token.
// Subject in claim is used to retrieve the public key which is used to verify the signature of the token.
// The pubkeyFunc takes the subject, and produces a public key by some means.
// The subject is as trustworthy as your pubkeyFunc.
// If the subject (which came from the client) produces a different pubkey (as if the user set the wrong subject), validation will fail.
// If the claims are tampered with, the validation will fail
// Security of this method depends entirely on pubkeyFunc being able to produce a pubkey for the subject that corresponds to a private key held by the requestor.
func ParsePubkeySignedToken(tokenString string, pubkeyFunc func(subject string) (pubkey string, err error)) (subject string, token *jwt.Token, err error) {
	// Make a token object, part of which is acquiring the appropriate public key with which to verify said token.
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		subject = token.Claims.(jwt.MapClaims)["sub"].(string)
		log.Infof("Subject %s attempting to authenticate", subject)

		// Verify that we've been sent the right kind of token in the first place
		if _, ok := token.Method.(*SigningMethodRSAAgent); !ok {
			t := reflect.TypeOf(token.Method)
			err := errors.New(fmt.Sprintf("Unsupported signing method: %s", t.String()))
			return nil, err
		}

		pubkey, err := pubkeyFunc(subject)

		// need to convert from ssh.PublicKey to rsa.PublicKey  This is a mess.
		sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
		if err != nil {
			err = errors.Wrap(err, "failed to parse authorized key")
			return nil, err
		}

		// Only way to do this that I'm aware of is nastily via reflection.
		// field 0 "N" is modulus
		// filed 1 "E" is public exponent

		val := reflect.ValueOf(sshPubKey).Elem()

		modulus := val.Field(0).Interface().(*big.Int)
		exponent := val.Field(1).Interface().(int)

		var key rsa.PublicKey
		key.E = exponent
		key.N = modulus

		// It does, however, work, and that's what counts.
		return key, nil
	})

	if err != nil {
		err = errors.Wrapf(err, "failed to parse token")
		return "", nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		iss := claims["iss"]
		sub := claims["sub"]

		// The issuer must match the subject, or someone is doing something screwy
		if iss != sub {
			err = errors.New("Subject and Issuer of token do not match")
			return "", nil, err
		}

		// Unpack the standard claims and do some checking
		var exp int
		var iat int
		var nbf int

		if expInt, ok := claims["exp"]; ok {
			if expFloat, ok := expInt.(float64); ok {
				exp = int(expFloat)
			}
		}

		if iatInt, ok := claims["iat"]; ok {
			if iatFloat, ok := iatInt.(float64); ok {
				iat = int(iatFloat)
			}
		}

		if nbfInt, ok := claims["nbf"]; ok {
			if nbfFloat, ok := nbfInt.(float64); ok {
				nbf = int(nbfFloat)
			}
		}

		duration := exp - iat

		// Only allow tokens with an agreeably short duration (MAX_TOKEN_DURATION)
		if duration > MAX_TOKEN_DURATION {
			err = errors.New(fmt.Sprintf("Token duration too long (max %d seconds)", MAX_TOKEN_DURATION))
			return "", nil, err
		}

		// make sure it's not before when the token was created (paranoid much?)
		if int64(nbf) < time.Now().Unix() {
			err = errors.New("Token not yet valid")
			return "", nil, err
		}

		return subject, token, err
	} else {
		err = errors.New("Unparsable token claims")
		return "", nil, err
	}
}

// SignedJwtToken takes a subject, and a public key string (as provided by ssh-agent or ssh-keygen) and creates a signed JWT Token by asking the ssh-agent politely to sign the token claims.  The token is good for MAX_TOKEN_DURATION seconds.
func SignedJwtToken(subject string, pubkey string) (token string, err error) {
	now := time.Now()
	expiration := now.Add(time.Duration(MAX_TOKEN_DURATION) * time.Second)

	rBytes := make([]byte, 32)
	if _, err := rand.Read(rBytes); err != nil {
		err = errors.Wrapf(err, "failed generating random JWT id")
		return token, err
	}

	id := hex.EncodeToString(rBytes)

	claims := &jwt.StandardClaims{
		Id:        id,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: expiration.Unix(),
		Subject:   subject,
		Issuer:    subject, // Subject and issuer match, cos that's how this ssh-agent pubkey auth stuff works - you auth yourself.  It's up to the server to decide if it trusts you.
	}

	log.Infof("Issued: %d Expires: %d", now.Unix(), expiration.Unix())

	// set up the JWT Token
	SigningMethodRS256Agent := &SigningMethodRSAAgent{"RS256", crypto.SHA256}
	jwt.RegisterSigningMethod(SigningMethodRS256Agent.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS256Agent
	})

	t := jwt.NewWithClaims(SigningMethodRS256Agent, claims)

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
	if err != nil {
		err = errors.Wrap(err, "failed to parse public key")
		return token, err
	}

	token, err = t.SignedString(pubKey)
	if err != nil {
		err = errors.Wrap(err, "failed to sign token")
		return token, err
	}

	return token, err
}
