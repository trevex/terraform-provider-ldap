module github.com/trevex/terraform-provider-ldap

go 1.15

require (
	github.com/go-ldap/ldap/v3 v3.2.4
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.0.4
)

replace google.golang.org/api v0.28.0 => github.com/googleapis/google-api-go-client v0.28.0
