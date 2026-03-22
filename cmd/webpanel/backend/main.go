// cmd/webpanel/backend/main.go
// DDoS Mitigation Platform - Web Panel Backend
// Serves the frontend static files and proxies API calls to the control plane.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/api"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/auth"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/models"
)

var (
	flagAddr        = flag.String("addr", ":3000", "Web panel listen address")
	flagCPURL       = flag.String("cp", "http://localhost:8080", "Control plane API URL")
	flagJWTSecret   = flag.String("jwt-secret", "", "JWT signing secret (random if empty)")
	flagFrontendDir = flag.String("frontend", "./cmd/webpanel/frontend", "Path to frontend static files")
	flagProd        = flag.Bool("prod", false, "Enable production mode (disables Gin debug logs)")
)

func main() {
	flag.Parse()

	if *flagProd {
		gin.SetMode(gin.ReleaseMode)
	}

	// ── Initialise dependencies ──
	authMgr := auth.NewManager(*flagJWTSecret)
	cpClient := api.NewControlPlaneClient(*flagCPURL)
	alertStore := models.NewAlertStore(500)
	handler := api.NewHandler(authMgr, cpClient, alertStore)

	// ── Gin engine ──
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(ginLogger())
	r.Use(corsMiddleware())

	// Register API routes
	handler.RegisterRoutes(r)

	// Serve frontend static files
	r.Static("/static", *flagFrontendDir)
	r.StaticFile("/", *flagFrontendDir+"/index.html")
	r.StaticFile("/app.js", *flagFrontendDir+"/app.js")
	r.StaticFile("/styles.css", *flagFrontendDir+"/styles.css")

	// Fallback: any unmatched route serves index.html (SPA support)
	r.NoRoute(func(c *gin.Context) {
		c.File(*flagFrontendDir + "/index.html")
	})

	srv := &http.Server{
		Addr:         *flagAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ── Signal handling ──
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Web panel listening on %s (control plane: %s)", *flagAddr, *flagCPURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("web panel server: %v", err)
		}
	}()

	<-sigCh
	log.Println("Web panel shutting down...")
}

// ginLogger is a minimal request logger.
func ginLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("%s %s %d %s",
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			time.Since(start),
		)
	}
}

// corsMiddleware adds permissive CORS headers for development.
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
