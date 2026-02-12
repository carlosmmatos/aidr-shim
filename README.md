# AIDR GCP ext_proc Shim

A gRPC service that integrates [CrowdStrike AIDR](https://www.crowdstrike.com/) (AI Detection & Response) with Google Cloud Load Balancer's [external processing](https://cloud.google.com/load-balancing/docs/https/ext-proc-overview) (ext_proc) extension.

## Overview

This shim enables real-time protection for AI workloads by:

- **Detecting prompt injection attacks** before they reach your AI systems
- **Preventing data leakage** by identifying PII and sensitive data in requests/responses
- **Enforcing security policies** defined in CrowdStrike Falcon

```text
User → Google Load Balancer → ext_proc (this shim) → AIDR API
                ↓                                        ↓
         Your AI App ←────────── Allow/Block/Transform ──┘
```

## Quick Start

### Prerequisites

- GCP project with billing enabled
- CrowdStrike AIDR credentials (base URL and bearer token)
- [gcloud CLI](https://cloud.google.com/sdk/docs/install) or Google Cloud Shell

### Deploy in 2 Minutes

```bash
# 1. Clone the repository
git clone <repository-url>
cd gcp-shim

# 2. Set up prerequisites
./scripts/setup-prerequisites.sh

# 3. Deploy (interactive prompts for configuration)
./scripts/deploy.sh
```

The deployment script will:
1. Validate your GCP environment
2. Create secrets in Secret Manager
3. Deploy to Cloud Run
4. Output the service URL for Load Balancer configuration

### Non-Interactive Deployment

```bash
export PROJECT_ID="your-project-id"
export AIDR_BASE_URL="https://api.crowdstrike.com/aidr/aiguard"
export AIDR_TOKEN="your-bearer-token"

./scripts/deploy.sh
```

## Documentation

| Document | Description |
|----------|-------------|
| [User Guide](docs/USER_GUIDE.md) | Complete deployment and usage guide |
| [Configuration](docs/CONFIGURATION.md) | All configuration options |
| [Terraform](terraform/README.md) | Infrastructure-as-code deployment |

## Deployment Options

### Option 1: Shell Scripts (Quick Start)

Best for getting started quickly in Cloud Shell:

```bash
./scripts/deploy.sh
```

### Option 2: Terraform (Production)

Best for repeatable, auditable deployments:

```bash
cd terraform
terraform init
terraform apply
```

See [terraform/README.md](terraform/README.md) for details.

## Testing

Test your deployment with the included test client:

```bash
# Build test client
go build -o testclient ./test/client

# Test a payload
./testclient \
  --address=YOUR_SERVICE_URL:443 \
  --tls \
  --payload=test/testdata/clean_request.json

# Run all test payloads
./testclient \
  --address=YOUR_SERVICE_URL:443 \
  --tls \
  --batch \
  --testdata=test/testdata
```

## Project Structure

```
├── cmd/
│   ├── shim/           # Main service
│   └── testclient/     # Test client
├── pkg/
│   └── config/         # Configuration
├── internal/
│   └── server/         # gRPC server implementation
├── scripts/
│   ├── deploy.sh           # Production deployment
│   ├── deploy-debug.sh     # Debug deployment
│   └── setup-prerequisites.sh
├── terraform/          # Terraform module
├── test/
│   └── testdata/       # Test payloads
├── docs/               # Documentation
├── Dockerfile
└── README.md
```

## Configuration

Key environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `AIDR_BASE_URL` | Yes | AIDR API endpoint |
| `AIDR_TOKEN` | Yes | Bearer token for authentication |
| `LOG_LEVEL` | No | debug, info, warn, error (default: info) |
| `DEBUG_MODE` | No | Enable verbose logging (default: false) |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options.

## Next Steps After Deployment

1. **Configure Load Balancer**: Provide the service URL to Google for ext_proc configuration
2. **Set Up Policies**: Configure AIDR policies in CrowdStrike Falcon console
3. **Monitor**: View logs with `gcloud run services logs tail aidr-shim`

## License

Copyright CrowdStrike. See LICENSE for details.
