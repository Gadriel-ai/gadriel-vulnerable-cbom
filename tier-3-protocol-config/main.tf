# Deliberately vulnerable-by-design A3 (Terraform/IaC) fixture --
# AWS ELB TLS policy, AWS/GCP/Azure KMS key specs, and a CloudFront
# viewer-certificate minimum version, covering every branch
# protocol_scan.rs's scan_terraform recognises.

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"

  # Weak: a TLS-1.0-era predefined policy.
  ssl_policy = "ELBSecurityPolicy-2016-08"
}

resource "aws_lb_listener" "https_strong" {
  load_balancer_arn = aws_lb.app.arn
  port              = 8443
  protocol          = "HTTPS"

  ssl_policy = "ELBSecurityPolicy-TLS13-1-3-2021-06"
}

resource "aws_kms_key" "legacy_signing_key" {
  description              = "Business-critical signing key, deliberately RSA for this fixture"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "symmetric_data_key" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
}

resource "google_kms_crypto_key" "example" {
  name     = "example-key"
  key_ring = google_kms_key_ring.example.id

  version_template {
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
  }
}

resource "azurerm_key_vault_key" "example" {
  name         = "generated-cert"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
}

resource "aws_cloudfront_distribution" "app" {
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.app.arn
    ssl_support_method       = "sni-only"
    # Weak: pre-2018 minimum policy.
    minimum_protocol_version = "TLSv1_2016"
  }
}

resource "aws_cloudfront_distribution" "future_unrecognised" {
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.app.arn
    # Deliberately not in protocol_scan.rs's cloudfront_min_version
    # table -- recorded as Unresolved, never dropped.
    minimum_protocol_version = "TLSv1.4_2099"
  }
}
