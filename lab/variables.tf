variable "region" {
  description = "Region AWS du labo"
  type        = string
  default     = "eu-west-3"
}

variable "prefix" {
  description = "Prefixe de nommage des ressources"
  type        = string
  default     = "cspm-lab"
}

variable "owner" {
  description = "Identifiant du proprietaire, pour les tags et la tracabilite"
  type        = string
}

variable "enable_compute" {
  description = "Creer une instance EC2 (facturee). Laisser a false par defaut."
  type        = bool
  default     = false
}
