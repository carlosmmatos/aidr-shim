# Secret Manager secrets for AIDR credentials

resource "google_secret_manager_secret" "aidr_base_url" {
  secret_id = "aidr-base-url"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    app = "aidr-shim"
  }
}

resource "google_secret_manager_secret_version" "aidr_base_url" {
  secret      = google_secret_manager_secret.aidr_base_url.id
  secret_data = var.aidr_base_url
}

resource "google_secret_manager_secret" "aidr_token" {
  secret_id = "aidr-token"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    app = "aidr-shim"
  }
}

resource "google_secret_manager_secret_version" "aidr_token" {
  secret      = google_secret_manager_secret.aidr_token.id
  secret_data = var.aidr_token
}

# IAM binding for Cloud Run service account to access secrets
resource "google_secret_manager_secret_iam_member" "aidr_base_url_access" {
  secret_id = google_secret_manager_secret.aidr_base_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_cloud_run_v2_service.aidr_shim.template[0].service_account}"

  depends_on = [google_cloud_run_v2_service.aidr_shim]
}

resource "google_secret_manager_secret_iam_member" "aidr_token_access" {
  secret_id = google_secret_manager_secret.aidr_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_cloud_run_v2_service.aidr_shim.template[0].service_account}"

  depends_on = [google_cloud_run_v2_service.aidr_shim]
}
