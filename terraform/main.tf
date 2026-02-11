# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
  ])

  project = var.project_id
  service = each.key

  disable_on_destroy = false
}

# Cloud Run service for AIDR ext_proc shim
resource "google_cloud_run_v2_service" "aidr_shim" {
  name     = var.service_name
  location = var.region
  project  = var.project_id

  # Ensure APIs are enabled first
  depends_on = [google_project_service.required_apis]

  template {
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    containers {
      # If container_image is provided, use it; otherwise, this will fail
      # and you need to build/push the image first or use gcloud run deploy --source
      image = var.container_image != "" ? var.container_image : "gcr.io/${var.project_id}/${var.service_name}:latest"

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }

      ports {
        container_port = 8080
      }

      # Environment variables
      env {
        name  = "LOG_LEVEL"
        value = var.log_level
      }

      env {
        name  = "DEBUG_MODE"
        value = tostring(var.debug_mode)
      }

      dynamic "env" {
        for_each = var.collector_instance_id != "" ? [1] : []
        content {
          name  = "COLLECTOR_INSTANCE_ID"
          value = var.collector_instance_id
        }
      }

      # Secret references
      env {
        name = "AIDR_BASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.aidr_base_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "AIDR_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.aidr_token.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  # Allow unauthenticated access (the service will be behind Google's LB)
  ingress = "INGRESS_TRAFFIC_ALL"

  labels = {
    app = "aidr-shim"
  }
}

# IAM policy to allow unauthenticated access
resource "google_cloud_run_v2_service_iam_member" "allow_unauthenticated" {
  project  = google_cloud_run_v2_service.aidr_shim.project
  location = google_cloud_run_v2_service.aidr_shim.location
  name     = google_cloud_run_v2_service.aidr_shim.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
