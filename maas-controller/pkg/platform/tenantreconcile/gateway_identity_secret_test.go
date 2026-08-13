package tenantreconcile

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	maasv1alpha1 "github.com/opendatahub-io/models-as-a-service/maas-controller/api/maas/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, maasv1alpha1.AddToScheme(s))
	return s
}

func TestEnsureGatewayIdentityToken_CreatesSecretWhenMissing(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	token, err := EnsureGatewayIdentityToken(ctx, c, "opendatahub", "")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	secret := &corev1.Secret{}
	require.NoError(t, c.Get(ctx, types.NamespacedName{
		Namespace: "opendatahub",
		Name:      MaaSGatewayIdentitySecretName,
	}, secret))
	assert.Equal(t, []byte(token), secret.Data[MaaSGatewayIdentitySecretKey])
	assert.Equal(t, "maas-controller", secret.Labels["app.kubernetes.io/managed-by"])
}

func TestEnsureGatewayIdentityToken_UsesConfiguredTokenOnCreate(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	token, err := EnsureGatewayIdentityToken(ctx, c, "opendatahub", "configured-token")
	require.NoError(t, err)
	assert.Equal(t, "configured-token", token)

	secret := &corev1.Secret{}
	require.NoError(t, c.Get(ctx, types.NamespacedName{
		Namespace: "opendatahub",
		Name:      MaaSGatewayIdentitySecretName,
	}, secret))
	assert.Equal(t, []byte("configured-token"), secret.Data[MaaSGatewayIdentitySecretKey])
}

func TestEnsureGatewayIdentityToken_ReturnsExistingSecret(t *testing.T) {
	ctx := context.Background()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      MaaSGatewayIdentitySecretName,
			Namespace: "opendatahub",
		},
		Data: map[string][]byte{
			MaaSGatewayIdentitySecretKey: []byte("existing-token"),
		},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(existing).Build()

	token, err := EnsureGatewayIdentityToken(ctx, c, "opendatahub", "configured-token")
	require.NoError(t, err)
	assert.Equal(t, "existing-token", token)
}

func TestGatewayAuthHeaderExpression_EscapesQuotes(t *testing.T) {
	assert.Equal(t, "'gateway-test-token'", GatewayAuthHeaderExpression("gateway-test-token"))
	assert.Equal(t, `'tok\'en'`, GatewayAuthHeaderExpression("tok'en"))
}
