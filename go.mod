module github.com/trevex/terraform-provider-ldap

go 1.15

require (
	github.com/go-ldap/ldap/v3 v3.2.4
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.5.0
	github.com/pkg/errors v0.8.1
	golang.org/x/text v0.3.3
)

replace google.golang.org/api v0.28.0 => github.com/googleapis/google-api-go-client v0.28.0
