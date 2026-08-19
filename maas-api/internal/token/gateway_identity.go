package token

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/constant"
	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/logger"
)

// RequireGatewayIdentity rejects requests that did not pass through the gateway AuthPolicy.
// When gatewayIdentityToken is configured, callers must present a matching
// X-MaaS-Gateway-Auth header injected by Authorino after successful authentication.
// Direct pod access with forged X-MaaS-Username / X-MaaS-Group headers is blocked.
func RequireGatewayIdentity(log *logger.Logger, gatewayIdentityToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if gatewayIdentityToken == "" {
			log.Warn("GATEWAY_IDENTITY_TOKEN not configured; gateway identity verification disabled")
			c.Next()
			return
		}

		provided := strings.TrimSpace(c.GetHeader(constant.HeaderGatewayAuth))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(gatewayIdentityToken)) != 1 {
			log.Warn("Missing or invalid gateway identity token",
				"header", constant.HeaderGatewayAuth,
				"hasUsernameHeader", c.GetHeader(constant.HeaderUsername) != "",
				"hasGroupHeader", c.GetHeader(constant.HeaderGroup) != "",
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"type":    "authentication_error",
					"message": "Request must be authenticated via the MaaS gateway",
				},
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
