// Heavily based on https://github.com/Pryz/terraform-provider-ldap, see LICENSE

package provider

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

var SEARCH_DEPTHS = map[int][]string{
	ldap.ScopeWholeSubtree: {
		"sub",
		"subtree",
		"wholeSubtree",
	},
	ldap.ScopeBaseObject: {
		"base",
		"baseObject",
	},
	ldap.ScopeSingleLevel: {
		"one",
		"singleLevel",
	},
}

// searchDepthLookup normalizes the name of a search depth
func normalizeSearchDepth(search string) int {
	lowerSearch := strings.ToLower(search)
	for val, alternates := range SEARCH_DEPTHS {
		for _, a := range alternates {
			if strings.ToLower(a) == lowerSearch {
				return val
			}
		}
	}
	return -1
}

func depthHelpString() string {
	out := []string{}
	for _, alternates := range SEARCH_DEPTHS {
		out = append(out, fmt.Sprintf("%s (or %s)", alternates[0], strings.Join(alternates[1:], ", ")))
	}

	return strings.Join(out, ", ")
}

func dataLDAPObject() *schema.Resource {
	return &schema.Resource{
		Read: dataLDAPObjectRead,

		Schema: map[string]*schema.Schema{
			"base_dn": {
				Type:        schema.TypeString,
				Description: "Base DN to search from",
				Required:    true,
			},
			"depth": {
				Type: schema.TypeString,
				// Search depth can be any of the keys or values in SEARCH_DEPTHS
				Description: "Search depth kind: " + depthHelpString(),
				Default:     "subtree",
				Optional:    true,
			},
			"search_values": {
				Type:        schema.TypeMap,
				Description: "A dict of values to search by, will be AND'd together",
				Required:    true,
				Elem: &schema.Schema{
					Type:        schema.TypeString,
					Description: "The value to search for on this attribute",
				},
			},
			"dn": {
				Type:        schema.TypeString,
				Description: "DN Of the object",
				Computed:    true,
			},
			"attributes": {
				Type:        schema.TypeSet,
				Description: "The map of attributes of this object; each attribute can be multi-valued.",
				Set:         attributeHash,
				MinItems:    0,
				Computed:    true,

				Elem: &schema.Schema{
					Type:        schema.TypeMap,
					Description: "The list of values for a given attribute.",
					MinItems:    1,
					MaxItems:    1,
					Elem: &schema.Schema{
						Type:        schema.TypeString,
						Description: "The individual value for the given attribute.",
					},
				},
			},
			"attributes_json": {
				Computed:    true,
				Type:        schema.TypeMap,
				Description: "A map of json encoded attribute values. Each entry is a JSON encoded string list",
				Elem: &schema.Schema{
					Type:        schema.TypeString,
					Description: "A json-encoded array of strings",
				},
			},
			"skip_attributes": {
				Type:        schema.TypeSet,
				Description: "A list of attributes which will not be tracked by the provider",
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				Optional:    true,
			},
			"select_attributes": {
				Type:        schema.TypeSet,
				Description: "Only attributes in this list will be modified by the provider",
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				Optional:    true,
			},
		},
	}
}

func dataLDAPObjectRead(d *schema.ResourceData, meta interface{}) error {
	return searchLDAPObject(d, meta)
}

func searchLDAPObject(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	baseDN := d.Get("base_dn").(string)
	searchDepthInput := d.Get("depth").(string)
	searchDepth := normalizeSearchDepth(searchDepthInput)

	if searchDepth < 0 {
		return fmt.Errorf("Search depth of '%s' not a valid option", searchDepthInput)
	}

	searchFilters := []string{}
	if requestedSearch, ok := d.GetOk("search_values"); ok {
		for key, val := range requestedSearch.(map[string]interface{}) {
			searchFilters = append(searchFilters, fmt.Sprintf("(%s=%s)", key, val.(string)))
		}
	}
	searchFilter := fmt.Sprintf("(&%s)", strings.Join(searchFilters, ""))

	debugLog("data.ldap_object::read - looking in %q for %q", baseDN, searchFilter)
	// when searching by DN, you don't need t specify the base DN a search
	// filter a "subtree" scope: just put the DN (i.e. the primary key) as the
	// base DN with a "base object" scope, and the returned object will be the
	// entry, if it exists
	request := ldap.NewSearchRequest(
		baseDN,
		searchDepth,
		ldap.NeverDerefAliases, // deref Aliases
		0,                      // sizeLimit
		0,                      // timeLimit
		false,                  // typesOnly
		searchFilter,           // filter
		[]string{"*"},          // attributes
		nil,                    // controls
	)

	searchResult, err := client.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 { // no such object
				warnLog("data.ldap_object::read - object not found with filter: %s", searchFilter)
				return fmt.Errorf("Object not found with filter: %s", searchFilter)
			}
		}
		debugLog("data.ldap_object::read - search %q returned an error %v", searchFilter, err)
		return err
	}

	if len(searchResult.Entries) > 1 {
		err := fmt.Errorf("There were more than one objects foudn with search %q", searchFilter)
		errorLog(err.Error())
		return err
	} else if len(searchResult.Entries) < 1 {
		err := fmt.Errorf("There were no objects found against %q", searchFilter)
		errorLog(err.Error())
		return err
	}

	foundObject := searchResult.Entries[0]

	dn := foundObject.DN
	
	if dn == "" {
		for _, key := range []string{"dn", "DN", "distinguished_name", "distinguishedName"} {
			dn = foundObject.GetAttributeValue(key)
			if dn != "" {
				traceLog("Found Distinguished Name for object: %s = %q", key, dn)
				break
			}
		}
	}

	if dn == "" {
		err := fmt.Errorf("Failed to find DN for object %+v", foundObject)
		errorLog(err.Error())
		return err
	}

	traceLog("data.ldap_object::read - found %q : %+v", dn, foundObject)
	d.Set("dn", dn)
	d.SetId("-")

	// now deal with attributes
	set := &schema.Set{
		F: attributeHash,
	}

	// retrieve attributes to skip from HCL
	attributesToSkip := []string{}
	for _, attr := range (d.Get("skip_attributes").(*schema.Set)).List() {
		debugLog("data.ldap_object::create - object %q set to skip: %q", dn, attr.(string))
		attributesToSkip = append(attributesToSkip, attr.(string))
	}

	// retrieve attributes to skip from HCL
	attributesToSet := []string{}
	for _, attr := range (d.Get("select_attributes").(*schema.Set)).List() {
		debugLog("data.ldap_object::create - object %q set to only modify: %q", dn, attr.(string))
		attributesToSet = append(attributesToSet, attr.(string))
	}

	jsonAttributes := make(map[string]string)

	for _, attribute := range searchResult.Entries[0].Attributes {
		if shouldSkipAttribute(attribute.Name, attributesToSkip, attributesToSet) {
			debugLog("data.ldap_object::read - skipping attribute %q for %q", attribute.Name, dn)
			continue
		}
		debugLog("data.ldap_object::read - adding attribute %q to %q (%d values)", attribute.Name, dn, len(attribute.Values))
		// now add each value as an individual entry into the object, because
		// we do not handle name => []values, and we have a set of maps each
		// holding a single entry name => value; multiple maps may share the
		// same key.
		for _, value := range attribute.Values {
			traceLog("data.ldap_object::read - for %q, setting %q => %q", dn, attribute.Name, value)
			set.Add(map[string]interface{}{
				attribute.Name: value,
			})
		}
		jsonBytes, err := json.Marshal(attribute.Values)
		if err != nil {
			err = errors.Wrapf(err, "Marshalling attribute %s values", attribute.Name)
			errorLog(err.Error())
			return err
		}
		jsonAttributes[attribute.Name] = string(jsonBytes)
	}

	if err := d.Set("attributes", set); err != nil {
		warnLog("data.ldap_object::read - error setting attributes for %q : %v", dn, err)
		return err
	}

	if err := d.Set("attributes_json", jsonAttributes); err != nil {
		warnLog("data.ldap_object::read - error setting attributes_json for %q : %v", dn, err)
		return err
	}

	return nil
}
