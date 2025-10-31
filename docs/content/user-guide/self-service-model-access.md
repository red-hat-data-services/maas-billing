# Self-Service Model Access

This guide is for **end users** who want to use AI models through the MaaS platform.

## 🎯 What is MaaS?

The Model-as-a-Service (MaaS) platform provides access to AI models through a simple API. Your organization's administrator has set up the platform and configured access for your team.

## Getting Your Access Token

### Step 1: Get Your OpenShift Authentication Token

First, you need your OpenShift token to prove your identity to the maas-api.

```bash
# Log in to your OpenShift cluster if you haven't already
oc login ...

# Get your current OpenShift authentication token
OC_TOKEN=$(oc whoami -t)
```

### Step 2: Request an Access Token from the API

Next, use that OpenShift token to call the maas-api `/v1/tokens` endpoint. You can specify the desired expiration time; the default is 4 hours.

```bash
CLUSTER_DOMAIN=$(kubectl get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}')
MAAS_API_URL="https://maas.${CLUSTER_DOMAIN}"

TOKEN_RESPONSE=$(curl -sSk \
  -H "Authorization: Bearer ${OC_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"expiration": "15m"}' \
  "${MAAS_API_URL}/maas-api/v1/tokens")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r .token)

echo $ACCESS_TOKEN
```

### Token Lifecycle

- **Default lifetime**: 4 hours (configurable when requesting)
- **Maximum lifetime**: Determined by cluster configuration
- **Refresh**: Request a new token before expiration
- **Revocation**: Tokens can be revoked if compromised

## Discovering Models

### List Available Models

Get a list of models available to your tier:

```bash
MODELS=$(curl "${MAAS_API_URL}/v1/models" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

echo $MODELS | jq .
```

Example response:

```json
{
  "data": [
    {
      "id": "simulator",
      "name": "Simulator Model",
      "url": "https://gateway.your-domain.com/simulator/v1/chat/completions",
      "tier": "free"
    },
    {
      "id": "qwen3",
      "name": "Qwen3 Model",
      "url": "https://gateway.your-domain.com/qwen3/v1/chat/completions",
      "tier": "premium"
    }
  ]
}
```

### Get Model Details

Get detailed information about a specific model:

```bash
MODEL_ID="simulator"
MODEL_INFO=$(curl "${MAAS_API_URL}/v1/models" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" | \
    jq --arg model "$MODEL_ID" '.data[] | select(.id == $model)')

echo $MODEL_INFO | jq .
```

## Making Inference Requests

### Basic Chat Completion

Make a simple chat completion request:

```bash
# First, get the model URL from the models endpoint
MODELS=$(curl "${MAAS_API_URL}/v1/models" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")
MODEL_URL=$(echo $MODELS | jq -r '.data[0].url')
MODEL_NAME=$(echo $MODELS | jq -r '.data[0].id')

curl -sSk \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
        \"model\": \"${MODEL_NAME}\",
        \"messages\": [
          {
            \"role\": \"user\",
            \"content\": \"Hello, how are you?\"
          }
        ],
        \"max_tokens\": 100
      }" \
  "${MODEL_URL}/v1/chat/completions"
```

### Streaming Chat Completion

For streaming responses, add `"stream": true` to the request and use `--no-buffer` to process the response in real-time:

```bash
curl -sSk --no-buffer \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
        \"model\": \"${MODEL_NAME}\",
        \"messages\": [
          {
            \"role\": \"user\",
            \"content\": \"Hello, how are you?\"
          }
        ],
        \"max_tokens\": 100,
        \"stream\": true
      }" \
  "${MODEL_URL}/v1/chat/completions"
```

## Understanding Your Access Level

Your access is determined by your **tier**, which controls:

- **Available models** - Which AI models you can use
- **Request limits** - How many requests per minute
- **Token limits** - Maximum tokens per request
- **Features** - Advanced capabilities available

### Default Tiers

| Tier | Requests/min | Tokens/min |
|------|--------------|------------|
| Free | 5 | 100 |
| Premium | 20 | 50,000 |
| Enterprise | 50 | 100,000 |

## Error Handling

### Common Error Responses

**401 Unauthorized**

```json
{
  "error": {
    "message": "Invalid authentication token",
    "type": "invalid_request_error",
    "code": "invalid_api_key"
  }
}
```

**403 Forbidden**

```json
{
  "error": {
    "message": "Insufficient permissions for this model",
    "type": "permission_error",
    "code": "access_denied"
  }
}
```

**429 Too Many Requests**

```json
{
  "error": {
    "message": "Rate limit exceeded",
    "type": "rate_limit_error",
    "code": "rate_limit_exceeded"
  }
}
```

## Monitoring Usage

Check your current usage through response headers:

```bash
# Make a request and check headers
curl -I -sSk \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"model": "simulator", "messages": [{"role": "user", "content": "test"}]}' \
  "${MODEL_URL}/v1/chat/completions" | grep -i "x-ratelimit"
```

## ⚠️ Common Issues

### Authentication Errors

**Problem**: `401 Unauthorized`

**Solution**: Check your token and ensure it's correctly formatted:

```bash
# Correct format
-H "Authorization: Bearer YOUR_TOKEN"

# Wrong format
-H "Authorization: YOUR_TOKEN"
```

### Rate Limit Exceeded

**Problem**: `429 Too Many Requests`

**Solution**: Wait before making more requests, or contact your administrator to upgrade your tier.

### Model Not Available

**Problem**: `404 Model Not Found`

**Solution**: Check which models are available in your tier:

```bash
curl -X GET "${MAAS_API_URL}/v1/models" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```
