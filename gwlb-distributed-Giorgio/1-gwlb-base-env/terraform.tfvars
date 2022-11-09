# Set in this file your deployment variables
#region          = "us-east-1"
region          = "eu-west-1"
#aws-access-key  = "xxxxxxxxxxxx"
#aws-secret-key  = "xxxxxxxxxxxx"

linux-keypair   = "cgns-key-eu" # cgns-keypair
dns-zone        = "chkpscott.com"

spoke-env       = {
        0 = ["spoke-dev","10.10.0.0/22","10.10.0.0/24","10.10.1.0/24","10.10.2.0/24"]
        1 = ["spoke-prod","10.20.0.0/22","10.20.0.0/24","10.20.1.0/24","10.20.2.0/24"]
      # 2 = ["spoke-name","vpc-net/cidr","net-gwlbe/cidr","net-untrust/cidr","net-trust/cidr"]
    }

gateway-connection = "private" # Determines if the gateways are provisioned using their private or public address
gateway-name       = "gwlb-ckpgateway"
gateway-size       = "c5.xlarge"
gateway-version    = "R80.40-BYOL"
gateway-sic        = "chkp1SICchkp"
ckpgw-keypair      = "cgns-key-eu" # cgns-keypair
admin-pwd-hash     = "$6$gstjQ/1WxWAWIymB$2MH0yqmvGvuIO99FHXlbJdxOYOxd.2u1.eBsZ39fqE0m5GP4DgSvszPe6OsYfVk.vXYPgeLV5rkMAgtJ2QGqA1"

mgmt-name          = "ckpmgmt"
mgmt-size          = "m5.xlarge"
#mgmt-version       = "R80.40-BYOL"
mgmt-version       = "R81.10-BYOL"
iam-role-mgmt      = "Create with read-write permissions"
#    AllowedValues:
#      - None (configure later)
#      - Use existing (specify an existing IAM role name)
#      - Create with assume role permissions (specify an STS role ARN)
#      - Create with read permissions
#      - Create with read-write permissions

vpc-checkpoint     = "sec-mgmt"
vpc-checkpoint-cidr = "10.60.0.0/22"
policy-pkg-gwlb    = "pkg-gwlb-ingress"
cme-provision-tag  = "ckpgwlb"

team               = "team-scott"
