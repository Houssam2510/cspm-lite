# Bucket volontairement expose : declenche S3-001 a S3-006.

resource "aws_s3_bucket" "public" {
  bucket        = "${var.prefix}-public-${random_id.suffix.hex}"
  force_destroy = true # labo : on veut pouvoir detruire meme non vide
}

# Sans ce bloc, AWS active Block Public Access par defaut depuis avril 2023.
# On le desactive explicitement pour reproduire la mauvaise configuration.
resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "public" {
  bucket = aws_s3_bucket.public.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Policy ouverte a tout Internet : declenche S3-002.
resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.public.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public.arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.public]
}

# Bucket de reference, correctement configure : sert de temoin (doit passer).
resource "aws_s3_bucket" "sain" {
  bucket        = "${var.prefix}-sain-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "sain" {
  bucket                  = aws_s3_bucket.sain.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "sain" {
  bucket = aws_s3_bucket.sain.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sain" {
  bucket = aws_s3_bucket.sain.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "sain_tls" {
  bucket = aws_s3_bucket.sain.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.sain.arn,
        "${aws_s3_bucket.sain.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
