/*
Auth Web3 HTMX is a simple demonstration of Web3 in combination with HTMX, written in Go.
*/
package main

import (
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"embed"

	"github.com/Darkness4/auth-web3-htmx/auth"
	"github.com/Darkness4/auth-web3-htmx/database"
	"github.com/Darkness4/auth-web3-htmx/database/counter"
	"github.com/Darkness4/auth-web3-htmx/handler"
	"github.com/Darkness4/auth-web3-htmx/jwt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

var (
	//go:embed pages/* components/* base.html base.htmx
	html       embed.FS
	version    = "dev"
	key        []byte
	jwtSecret  string
	privateKey *ecdsa.PrivateKey

	dbFile string
)

var app = &cli.App{
	Name:    "auth-web3-htmx",
	Version: version,
	Usage:   "Demo of Auth and HTMX.",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "csrf.secret",
			Usage: "A 32 bytes hex secret",
			Action: func(ctx *cli.Context, s string) error {
				data, err := hex.DecodeString(s)
				if err != nil {
					panic(err)
				}
				key = data
				return nil
			},
			EnvVars: []string{"CSRF_SECRET"},
		},
		&cli.StringFlag{
			Name:        "jwt.secret",
			Usage:       "A unique string secret",
			Destination: &jwtSecret,
			EnvVars:     []string{"JWT_SECRET"},
		},
		&cli.StringFlag{
			Name:        "private-key",
			Usage:       "A ecdsa private key in Hex.",
			Destination: &jwtSecret,
			Action: func(ctx *cli.Context, s string) error {
				pk, err := crypto.HexToECDSA(s)
				if err != nil {
					return err
				}
				privateKey = pk
				return nil
			},
			EnvVars: []string{"PRIVATE_KEY"},
		},
		&cli.StringFlag{
			Name:        "db.path",
			Value:       "./db.sqlite3",
			Destination: &dbFile,
			Usage:       "SQLite3 database file path.",
			EnvVars:     []string{"DB_PATH"},
		},
	},
	Suggest: true,
	Action: func(cCtx *cli.Context) error {
		log.Level(zerolog.DebugLevel)

		// Auth
		authService := auth.NewAuth(jwt.Secret(jwtSecret), privateKey)

		// Router
		r := chi.NewRouter()
		r.Use(hlog.NewHandler(log.Logger))
		r.Use(authService.Middleware)

		// Auth Guard
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, isAuth := auth.GetClaimsFromRequest(r)

				if !isAuth {
					switch r.URL.Path {
					case "/counter":
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
				}

				next.ServeHTTP(w, r)
			})
		})

		// DB
		d, err := sql.Open("sqlite", dbFile)
		if err != nil {
			log.Error().Err(err).Msg("db failed")
			return err
		}
		if err := database.InitialMigration(d); err != nil {
			log.Error().Err(err).Msg("db migration failed")
			return err
		}

		// Auth
		r.Route("/auth", func(r chi.Router) {
			r.Get("/login", authService.Login())
			r.Get("/logout", authService.Logout())
			r.Post("/callback", authService.CallBack())
		})

		// Backend
		cr := counter.NewRepository(d)
		r.Post("/count", handler.Count(cr))

		// Pages rendering
		var renderFn http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Clean(r.URL.Path)
			path = filepath.Clean(fmt.Sprintf("pages/%s/page.tmpl", path))

			var userName, userID string
			if claims, ok := auth.GetClaimsFromRequest(r); ok {
				userName = claims.UserName
				userID = claims.UserID
			}

			// Check if SSR
			var base string
			if r.Header.Get("Hx-Request") != "true" {
				// Initial Rendering
				base = "base.html"
			} else {
				// SSR
				base = "base.htmx"
			}
			t, err := template.ParseFS(html, base, path, "components/*")
			if err != nil {
				// The page doesn't exist
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if err := t.ExecuteTemplate(w, "base", struct {
				UserName  string
				UserID    string
				CSRFToken string
			}{
				UserName:  userName,
				UserID:    userID,
				CSRFToken: csrf.Token(r),
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
		r.Get("/*", renderFn)

		log.Info().Msg("listening")
		return http.ListenAndServe(":3000", csrf.Protect(key)(r))
	},
}

func main() {
	log.Logger = log.With().Caller().Logger()
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("app crashed")
	}
}
