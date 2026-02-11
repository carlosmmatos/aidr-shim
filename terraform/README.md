# AIDR GCP ext_proc Shim - Terraform Module

This Terraform module deploys the AIDR GCP ext_proc shim to Google Cloud Run with Secret Manager integration.

## Prerequisites

1. **Terraform**: Version 1.0 or later
2. **GCP Project**: With billing enabled
3. **Authentication**: Configure one of:
   - `gcloud auth application-default login`
   - Service account key via `GOOGLE_APPLICATION_CREDENTIALS`
4. **Container Image**: Build and push the image first (see below)

## Building the Container Image

Before running Terraform, you need to build and push the container image:

```bash
# Option 1: Build and push using Cloud Build
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/aidr-shim:latest ..

# Option 2: Build locally and push
docker build -t gcr.io/YOUR_PROJECT_ID/aidr-shim:latest ..
docker push gcr.io/YOUR_PROJECT_ID/aidr-shim:latest
```

Alternatively, use `gcloud run deploy --source` which handles this automatically (see the shell scripts in `scripts/`).

## Usage

### Basic Usage

Create a `terraform.tfvars` file:

```hcl
project_id    = "your-gcp-project-id"
region        = "us-central1"
aidr_base_url = "https://api.crowdstrike.com/aidr/aiguard"
aidr_token    = "your-aidr-bearer-token"
container_image = "gcr.io/your-project-id/aidr-shim:latest"
```

Then run:

```bash
terraform init
terraform plan
terraform apply
```

### Using Environment Variables

```bash
export TF_VAR_project_id="your-gcp-project-id"
export TF_VAR_aidr_base_url="https://api.crowdstrike.com/aidr/aiguard"
export TF_VAR_aidr_token="your-aidr-bearer-token"
export TF_VAR_container_image="gcr.io/your-project-id/aidr-shim:latest"

terraform init
terraform plan
terraform apply
```

### Production Configuration

For production deployments, consider these settings:

```hcl
project_id    = "your-gcp-project-id"
region        = "us-central1"
service_name  = "aidr-shim"

# AIDR credentials
aidr_base_url = "https://api.crowdstrike.com/aidr/aiguard"
aidr_token    = "your-aidr-bearer-token"

# Container image
container_image = "gcr.io/your-project-id/aidr-shim:v1.0.0"

# Scaling
min_instances = 1    # Keep warm for low latency
max_instances = 100  # Scale for high traffic

# Resources
cpu    = "2"
memory = "1Gi"

# Logging
log_level  = "info"
debug_mode = false

# Optional instance identifier
collector_instance_id = "prod-us-central1"
```

## Input Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `project_id` | Yes | - | GCP project ID |
| `region` | No | `us-central1` | Cloud Run region |
| `service_name` | No | `aidr-shim` | Cloud Run service name |
| `aidr_base_url` | Yes | - | AIDR API base URL |
| `aidr_token` | Yes | - | AIDR bearer token |
| `container_image` | Yes | - | Container image to deploy |
| `min_instances` | No | `0` | Minimum instances |
| `max_instances` | No | `10` | Maximum instances |
| `cpu` | No | `1` | CPU allocation |
| `memory` | No | `512Mi` | Memory allocation |
| `log_level` | No | `info` | Log level |
| `debug_mode` | No | `false` | Enable debug logging |
| `collector_instance_id` | No | `""` | Instance identifier |

## Outputs

| Output | Description |
|--------|-------------|
| `service_url` | Cloud Run service URL for LB configuration |
| `service_name` | Deployed service name |
| `service_location` | Deployed service region |
| `project_id` | GCP project ID |
| `secret_ids` | Secret Manager secret IDs |

## Resources Created

- **Cloud Run Service**: The AIDR ext_proc shim
- **Secret Manager Secrets**: For AIDR credentials (base URL and token)
- **IAM Bindings**: For Cloud Run to access secrets
- **Project Services**: Enables required APIs

## State Management

For production, use remote state:

```hcl
terraform {
  backend "gcs" {
    bucket = "your-terraform-state-bucket"
    prefix = "aidr-shim"
  }
}
```

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Warning**: This will delete the Cloud Run service and secrets. Any traffic using this service will be disrupted.

## Troubleshooting

### "Permission denied" errors

Ensure your account has these roles:
- `roles/run.admin`
- `roles/secretmanager.admin`
- `roles/cloudbuild.builds.editor`
- `roles/artifactregistry.writer`

### "API not enabled" errors

The module automatically enables required APIs, but this may take a moment. Re-run `terraform apply` if you see API enablement errors.

### Secret access errors

The module creates IAM bindings for the Cloud Run service account to access secrets. If you see secret access errors, verify the bindings exist in the IAM console.
