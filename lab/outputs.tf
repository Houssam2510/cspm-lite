output "bucket_public" {
  description = "Bucket volontairement expose"
  value       = aws_s3_bucket.public.bucket
}

output "bucket_sain" {
  description = "Bucket temoin correctement configure"
  value       = aws_s3_bucket.sain.bucket
}

output "security_group_expose" {
  description = "Security group ouvert sur Internet"
  value       = aws_security_group.expose.id
}

output "role_scanner_arn" {
  description = "Role a assumer pour lancer cspm-lite en lecture seule"
  value       = aws_iam_role.scanner.arn
}

output "commande_de_scan" {
  description = "Commande prete a l'emploi"
  value = join(" ", [
    "cspm-lite scan",
    "--role-arn ${aws_iam_role.scanner.arn}",
    "--external-id cspm-lite-lab",
    "--region ${var.region}",
    "--format html -o rapport.html",
  ])
}
