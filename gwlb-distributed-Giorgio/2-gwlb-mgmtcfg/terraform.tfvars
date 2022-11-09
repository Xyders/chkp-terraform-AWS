# Set your deployment variables
region              = "eu-west-1"
api-username        = "admin"
api-password        = "P>JE3&Hp&r}F{5R?"
provider-context    = "web_api"

aws-dc-name         = "aws-dc"
gateway-sic         = "chkp1SICchkp"
new-policy-pkg      = "pkg-gwlb-ingress"

ckp-mgmt-name       = "ckpmgmt"
ckp-mgmt-ip         = "34.243.168.120"
ckp-mgmt-template   = "ckpgwlb-template"
ckp-mgmt-controller = "gwlb-controller"

gwlb-subnets-range  = "{<10.60.0.0,10.60.0.255>, <10.60.1.0,10.60.1.255>}"
#last-jhf            = "Check_Point_R80_40_JUMBO_HF_Bundle_T94_sk165456_FULL.tgz"
last-jhf            = "Check_Point_R81_10_JUMBO_HF_MAIN_Bundle_T78_FULL.tar"


# this should not be needed
accesskeyid         = "xxx"
secretaccesskey     = "xxx"
