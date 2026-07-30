# Security group ouvert sur Internet : declenche NET-001 et NET-002.

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "expose" {
  name        = "${var.prefix}-expose"
  description = "Volontairement ouvert sur Internet - labo cspm-lite"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_ingress_rule" "ssh_v4" {
  security_group_id = aws_security_group.expose.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH ouvert au monde (volontaire)"
}

# IPv6 : le piege que la plupart des scanners amateurs oublient.
resource "aws_vpc_security_group_ingress_rule" "ssh_v6" {
  security_group_id = aws_security_group.expose.id
  cidr_ipv6         = "::/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH ouvert au monde en IPv6 (volontaire)"
}

resource "aws_vpc_security_group_ingress_rule" "mysql" {
  security_group_id = aws_security_group.expose.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3306
  to_port           = 3306
  ip_protocol       = "tcp"
  description       = "Base de donnees exposee (volontaire)"
}

# Instance EC2 avec IMDSv1 autorise : declenche NET-006.
# Facturee : desactivee par defaut.
data "aws_ami" "al2023" {
  count       = var.enable_compute ? 1 : 0
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "imdsv1" {
  count                  = var.enable_compute ? 1 : 0
  ami                    = data.aws_ami.al2023[0].id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.expose.id]

  metadata_options {
    http_tokens = "optional" # IMDSv1 autorise : le vecteur de la breche Capital One
  }

  root_block_device {
    encrypted = false # declenche NET-005
  }

  tags = { Name = "${var.prefix}-imdsv1" }
}
