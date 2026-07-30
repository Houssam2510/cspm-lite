"""Vocabulaire partage des types de ressources.

Les collecteurs produisent ces types, les checks les consomment. Les centraliser ici
evite qu'une faute de frappe dans une chaine ne fasse silencieusement passer un check
sur une liste vide - la panne la plus insidieuse d'un outil de securite.

La convention de nommage suit celle de CloudFormation et d'ASFF.
"""

S3_BUCKET = "AWS::S3::Bucket"

IAM_USER = "AWS::IAM::User"
IAM_POLICY = "AWS::IAM::Policy"
IAM_PASSWORD_POLICY = "AWS::IAM::PasswordPolicy"

EC2_SECURITY_GROUP = "AWS::EC2::SecurityGroup"
EC2_INSTANCE = "AWS::EC2::Instance"
EC2_VOLUME = "AWS::EC2::Volume"
EC2_VPC = "AWS::EC2::VPC"

CLOUDTRAIL_TRAIL = "AWS::CloudTrail::Trail"

ACCOUNT = "AWS::Account"
