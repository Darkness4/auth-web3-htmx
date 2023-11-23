// Package auth defines the authentication layer of the application.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Darkness4/auth-web3-htmx/jwt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
)

const (
	tokenCookieKey = "session_token"
)

var (
	ErrAuthError = errors.New("authentication error")
)

type claimsContextKey struct{}

// Auth is a service that provides HTTP handlers and middlewares used for authentication.
//
// It uses a time-based nonce. The nonce is encrypted with the private key.
type Auth struct {
	JWTSecret jwt.Secret
	pk        *ecdsa.PrivateKey
	pub       *ecdsa.PublicKey
}

func NewAuth(jwtSecret jwt.Secret, pk *ecdsa.PrivateKey) *Auth {
	return &Auth{
		JWTSecret: jwtSecret,
		pk:        pk,
		pub:       &pk.PublicKey,
	}
}

type challengeMessage struct {
	Message    string `json:"message"`
	Nonce      int64  `json:"nonce"`
	ServerSigR string `json:"serverSigR"`
	ServerSigS string `json:"serverSigS"`
}

// Challenge returns a message with a nonce.
func (a *Auth) Challenge(message string) string {
	now := time.Now().Unix()
	nowS := strconv.FormatInt(now, 10)
	r, s, err := ecdsa.Sign(rand.Reader, a.pk, []byte(nowS))
	if err != nil {
		panic(err)
	}
	dat, err := json.Marshal(challengeMessage{
		Message:    message,
		Nonce:      now,
		ServerSigR: hex.EncodeToString(r.Bytes()),
		ServerSigS: hex.EncodeToString(s.Bytes()),
	})
	if err != nil {
		panic(err)
	}
	return string(dat)
}

// Verify checks the signature and nonce.
//
// This is a time-based nonce. In production, it is preferable to use a true nonce (random number) which is stored in a database.
func (a *Auth) Verify(address string, data []byte, sig []byte) error {
	var hash []byte
	if sig[ethcrypto.RecoveryIDOffset] > 1 {
		// Legacy Keccak256
		// Transform yellow paper V from 27/28 to 0/1
		sig[ethcrypto.RecoveryIDOffset] -= 27
	}
	hash = accounts.TextHash(data)

	// Verify signature
	sigPublicKey, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		log.Err(err).
			Str("hash", hexutil.Encode(hash)).
			Str("sig", hexutil.Encode(sig)).
			Msg("SigToPub failed")
		return err
	}
	sigAddr := ethcrypto.PubkeyToAddress(*sigPublicKey)

	// Verify public key
	if !strings.EqualFold(address, sigAddr.Hex()) {
		log.Error().
			Str("sig.Address", sigAddr.Hex()).
			Str("address", address).
			Str("sig", hexutil.Encode(sig)).
			Str("expected hash", hexutil.Encode(hash)).
			Msg("addresses are not equal")
		return ErrAuthError
	}

	// Verify message
	now := time.Now().Unix()
	var msg challengeMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Err(err).
			Str("data", string(data)).
			Msg("invalid msg")
		return ErrAuthError
	}
	r, err := hex.DecodeString(msg.ServerSigR)
	if err != nil {
		log.Err(err).
			Str("data", string(data)).
			Msg("failed to decode r")
		return err
	}
	s, err := hex.DecodeString(msg.ServerSigS)
	if err != nil {
		log.Err(err).
			Str("data", string(data)).
			Msg("failed to decode s")
		return err
	}
	nonceS := strconv.FormatInt(msg.Nonce, 10)
	if !ecdsa.Verify(a.pub, []byte(nonceS), new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)) {
		log.Error().
			Str("data", string(data)).
			Msg("nonce failed sig verification")
		return ErrAuthError
	}
	// Time-window 30s
	if !(msg.Nonce-now < 30 && msg.Nonce-now > -30) {
		log.Error().
			Str("data", string(data)).
			Msg("nonce expired")
		return ErrAuthError
	}

	return nil
}

type AuthResponse struct {
	Address string `json:"address"`
	Data    []byte `json:"data"`
	Sig     []byte `json:"sig"`
}

// Login is the handler called after login.
//
// It sends a challenge to the authenticator (Metamask).
func (a *Auth) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, a.Challenge("login"))
	}
}

// CallBack is the handler called after login.
//
// It:
//
//  1. Fetches the signed message
//  2. Validate and wrap the address in a JWT token
//  3. Store the JWT token in a cookie for the browser.
func (a *Auth) CallBack() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rep AuthResponse
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Err(err).Msg("failed to read body")
			http.Error(
				w,
				fmt.Sprintf("failed to read body: %s", err),
				http.StatusInternalServerError,
			)
			return
		}
		if err := json.Unmarshal(body, &rep); err != nil {
			log.Err(err).Str("body", string(body)).Msg("invalid body")
			http.Error(
				w,
				fmt.Sprintf("%s: %s", err, string(body)),
				http.StatusInternalServerError,
			)
			return
		}
		address := strings.ToLower(rep.Address)
		if err := a.Verify(address, rep.Data, rep.Sig); err != nil {
			log.Err(err).Msg("authentication failure")
			http.Error(
				w,
				fmt.Sprintf("authentication failure: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		token, err := a.JWTSecret.GenerateToken(address, address)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     tokenCookieKey,
			Value:    token,
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// Logout removes session cookies and redirect to home.
func (a *Auth) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(tokenCookieKey)
		if err != nil {
			// Ignore error. Cookie doesn't exists.
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		cookie.Value = ""
		cookie.Path = "/"
		cookie.Expires = time.Now().Add(-1 * time.Hour)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// Middleware is an authentication guard for HTTP servers.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the JWT token from the request header
		cookie, err := r.Cookie(tokenCookieKey)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Verify the JWT token
		claims, err := a.JWTSecret.VerifyToken(cookie.Value)
		if err != nil {
			log.Error().Err(err).Msg("token verification failed")
			next.ServeHTTP(w, r)
			return
		}

		// Store the claims in the request context for further use
		ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClaimsFromRequest is a helper function to fetch the JWT session token from an HTTP request.
func GetClaimsFromRequest(r *http.Request) (claims *jwt.Claims, ok bool) {
	claims, ok = r.Context().Value(claimsContextKey{}).(*jwt.Claims)
	return claims, ok
}
