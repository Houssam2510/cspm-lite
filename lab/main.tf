# Labo AWS volontairement vulnerable.
#
# AVERTISSEMENT : ce code cree des ressources reellement non securisees (bucket
# public, utilisateur sur-privilegie, ports ouverts sur Internet).
#
#   - utiliser un compte AWS DEDIE, sans aucune donnee reelle ;
#   - poser un budget avec alerte AVANT le premier apply ;
#   - lancer `terraform destroy` a la fin de chaque session.
#
# Objectif : verifier que cspm-lite leve bien les findings attendus. Un outil de
# securite qu'on n'a jamais vu detecter quelque chose n'est pas un outil, c'est une
# hypothese.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.region

  # Tags appliques a toutes les ressources : indispensable pour retrouver et
  # supprimer ce qui a ete cree, et pour attribuer les couts.
  default_tags {
    tags = {
      Project    = "cspm-lite-lab"
      Owner      = var.owner
      AutoDelete = "true"
      Warning    = "ressources-volontairement-vulnerables"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

data "aws_caller_identity" "current" {}
