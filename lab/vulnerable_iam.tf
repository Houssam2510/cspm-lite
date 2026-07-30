# Utilisateur sur-privilegie et policy trop large : declenche IAM-007 et IAM-008.

resource "aws_iam_user" "deployer" {
  name          = "${var.prefix}-deployer"
  force_destroy = true
}

# Anti-pattern volontaire : permissions attachees directement a un utilisateur.
resource "aws_iam_user_policy_attachment" "admin" {
  user       = aws_iam_user.deployer.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Policy client "*" sur "*" : le classique de l'escalade de privileges.
resource "aws_iam_policy" "wildcard" {
  name        = "${var.prefix}-legacy-full-access"
  description = "Policy volontairement trop large pour le labo cspm-lite"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "wildcard" {
  user       = aws_iam_user.deployer.name
  policy_arn = aws_iam_policy.wildcard.arn
}

# Role de lecture destine a cspm-lite lui-meme : moindre privilege applique.
# C'est ce role qu'on assume pour scanner, jamais un utilisateur administrateur.
resource "aws_iam_role" "scanner" {
  name = "${var.prefix}-scanner"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_caller_identity.current.account_id }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "sts:ExternalId" = "cspm-lite-lab" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "scanner" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
