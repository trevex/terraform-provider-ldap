// Heavily based on https://github.com/Pryz/terraform-provider-ldap, see LICENSE

package provider

import (
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"log"
	"strings"

	"github.com/pkg/errors"
	"github.com/trevex/terraform-provider-ldap/util"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/text/encoding/unicode"
)

func resourceLDAPObject() *schema.Resource {
	return &schema.Resource{
		Create: resourceLDAPObjectCreate,
		Read:   resourceLDAPObjectRead,
		Update: resourceLDAPObjectUpdate,
		Delete: resourceLDAPObjectDelete,
		Exists: resourceLDAPObjectExists,

		Importer: &schema.ResourceImporter{
			StateContext: resourceLDAPObjectImport,
		},

		Schema: map[string]*schema.Schema{
			"dn": {
				Type:        schema.TypeString,
				Description: "The Distinguished Name (DN) of the object, as the concatenation of its RDN (unique among siblings) and its parent's DN.",
				Required:    true,
				ForceNew:    true,
			},
			"object_classes": {
				Type:        schema.TypeSet,
				Description: "The set of classes this object conforms to (e.g. organizationalUnit, inetOrgPerson).",
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				Required:    true,
			},
			"attributes": {
				Type:        schema.TypeSet,
				Description: "The map of attributes of this object; each attribute can be multi-valued.",
				Set:         attributeHash,
				MinItems:    0,

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
				Optional: true,
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

func resourceLDAPObjectImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	dn := d.Id()
	debugLog("Goign to import dn %q", dn)
	d.Set("dn", dn)
	err := resourceLDAPObjectRead(d, meta)
	return []*schema.ResourceData{d}, errors.Wrap(err, "Reading ldap object")
}

func resourceLDAPObjectExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	l := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("[DEBUG] ldap_object::exists - checking if %q exists", dn)

	// search by primary key (that is, set the DN as base DN and use a "base
	// object" scope); no attributes are retrieved since we are onòy checking
	// for existence; all objects have an "objectClass" attribute, so the filter
	// is a "match all"
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	)

	_, err := l.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 { // no such object
				warnLog("ldap_object::exists - lookup for %q returned no value: deleted on server?", dn)
				return false, nil
			}
		}
		debugLog("ldap_object::exists - lookup for %q returned an error %v", dn, err)
		return false, err
	}

	debugLog("ldap_object::exists - object %q exists", dn)
	return true, nil
}

func resourceLDAPObjectCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("ldap_object::create - creating a new object under %q", dn)

	request := ldap.NewAddRequest(dn, []ldap.Control{})

	// retrieve classe from HCL
	objectClasses := []string{}
	for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
		debugLog("ldap_object::create - object %q has class: %q", dn, oc.(string))
		objectClasses = append(objectClasses, oc.(string))
	}
	request.Attribute("objectClass", objectClasses)

	// retrieve attributes to skip from HCL
	attributesToSkip := []string{"objectClass"}
	for _, attr := range (d.Get("skip_attributes").(*schema.Set)).List() {
		debugLog("ldap_object::create - object %q set to skip: %q", dn, attr.(string))
		attributesToSkip = append(attributesToSkip, attr.(string))
	}

	// retrieve attributes to skip from HCL
	attributesToSet := []string{}
	for _, attr := range (d.Get("select_attributes").(*schema.Set)).List() {
		debugLog("ldap_object::create - object %q set to only modify: %q", dn, attr.(string))
		attributesToSet = append(attributesToSet, attr.(string))
	}

	// if there is a non empty list of attributes, loop though it and
	// create a new map collecting attribute names and its value(s); we need to
	// do this because we could not model the attributes as a map[string][]string
	// due to an appareent limitation in HCL; we have a []map[string]string, so
	// we loop through the list and accumulate values when they share the same
	// key, then we use these as attributes in the LDAP client.
	if v, ok := d.GetOk("attributes"); ok {
		attributes := v.(*schema.Set).List()
		if len(attributes) > 0 {
			debugLog("ldap_object::create - object %q has %d attributes", dn, len(attributes))
			m := make(map[string][]string)
			for _, attribute := range attributes {
				debugLog("ldap_object::create - %q has attribute of type %T", dn, attribute)
				// each map should only have one entry (see resource declaration)
				for name, value := range attribute.(map[string]interface{}) {
					if stringSliceContains(attributesToSkip, name) {
						continue
					}
					if len(attributesToSet) > 0 && !stringSliceContains(attributesToSet, name) {
						debugLog("ldap_object::create - %q skipping unselected attribute", dn, name)
						continue
					}
					debugLog("ldap_object::create - %q has attribute[%v] => %v (%T)", dn, name, value, value)
					v := toAttributeValue(name, value.(string))
					m[name] = append(m[name], v)
				}
			}
			// now loop through the map and add attributes with theys value(s)
			for name, values := range m {
				request.Attribute(name, values)
			}
		}
	}

	err := client.Add(request)
	if err != nil {
		return err
	}

	debugLog("ldap_object::create - object %q added to LDAP server", dn)

	d.SetId(dn)
	return resourceLDAPObjectRead(d, meta)
}

func stringSliceContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if needle == h {
			return true
		}
	}
	return false
}

func resourceLDAPObjectRead(d *schema.ResourceData, meta interface{}) error {
	return readLDAPObject(d, meta, true)
}

func resourceLDAPObjectUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)

	dn := d.Id()
	debugLog("ldap_object::update - performing update on %q", dn)

	// retrieve attributes to skip from HCL
	attributesToSkip := []string{"objectClass"}
	for _, attr := range (d.Get("skip_attributes").(*schema.Set)).List() {
		debugLog("ldap_object::create - object %q set to skip: %q", dn, attr.(string))
		attributesToSkip = append(attributesToSkip, attr.(string))
	}

	// retrieve attributes to skip from HCL
	attributesToSet := []string{}
	for _, attr := range (d.Get("select_attributes").(*schema.Set)).List() {
		debugLog("ldap_object::create - object %q set to only modify: %q", dn, attr.(string))
		attributesToSet = append(attributesToSet, attr.(string))
	}

	modify := ldap.NewModifyRequest(dn, []ldap.Control{})

	// handle objectClasses
	if d.HasChange("object_classes") {
		classes := []string{}
		for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
			classes = append(classes, oc.(string))
		}
		debugLog("ldap_object::update - updating classes of %q, new value: %v", d.Id(), classes)
		modify.Replace("objectClass", classes)
	}

	if d.HasChange("attributes") {
		o, n := d.GetChange("attributes")
		debugLog("ldap_object::update - \n%s", printAttributes("old attributes map", o))
		debugLog("ldap_object::update - \n%s", printAttributes("new attributes map", n))

		err := computeAndAddDeltas(modify, o.(*schema.Set), n.(*schema.Set), attributesToSkip, attributesToSet)
		if err != nil {
			return err
		}
	}

	if len(modify.Changes) > 0 {
		err := client.Modify(modify)
		if err != nil {
			errorLog("ldap_object::update - error modifying LDAP object %q with values %v", d.Id(), err)
			return err
		}
	} else {
		warnLog("ldap_boject::update - didn't actually make changes to %q because there were no changes requested", dn)
	}
	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("ldap_object::delete - removing %q", dn)

	request := ldap.NewDelRequest(dn, nil)

	err := client.Del(request)
	if err != nil {
		errorLog("ldap_object::delete - error removing %q: %v", dn, err)
		return err
	}
	debugLog("ldap_object::delete - %q removed", dn)
	return nil
}

func readLDAPObject(d *schema.ResourceData, meta interface{}, updateState bool) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("ldap_object::read - looking for object %q", dn)

	// when searching by DN, you don't need t specify the base DN a search
	// filter a "subtree" scope: just put the DN (i.e. the primary key) as the
	// base DN with a "base object" scope, and the returned object will be the
	// entry, if it exists
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectclass=*)",
		[]string{"*"},
		nil,
	)

	sr, err := client.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 && updateState { // no such object
				warnLog("ldap_object::read - object not found, removing %q from state because it no longer exists in LDAP", dn)
				d.SetId("")
				return nil
			}
		}
		debugLog("ldap_object::read - lookup for %q returned an error %v", dn, err)
		return err
	}

	debugLog("ldap_object::read - query for %q returned %v", dn, sr)

	d.SetId(dn)
	d.Set("object_classes", sr.Entries[0].GetAttributeValues("objectClass"))

	// retrieve attributes to skip from HCL
	attributesToSkip := []string{"objectClass"}
	for _, attr := range (d.Get("skip_attributes").(*schema.Set)).List() {
		debugLog("ldap_object::create - object %q set to skip: %q", dn, attr.(string))
		attributesToSkip = append(attributesToSkip, attr.(string))
	}

	// retrieve attributes to set from HCL
	attributesToSet := []string{}
	for _, attr := range (d.Get("select_attributes").(*schema.Set)).List() {
		debugLog("ldap_object::create - object %q set to only modify: %q", dn, attr.(string))
		attributesToSet = append(attributesToSet, attr.(string))
	}

	// now deal with attributes
	set := &schema.Set{
		F: attributeHash,
	}

	for _, attribute := range sr.Entries[0].Attributes {
		debugLog("ldap_object::read - treating attribute %q of %q (%d values: %v)", attribute.Name, dn, len(attribute.Values), attribute.Values)
		if stringSliceContains(attributesToSkip, attribute.Name) {
			// skip: we don't treat object classes as ordinary attributes
			debugLog("ldap_object::read - skipping attribute %q of %q", attribute.Name, dn)
			continue
		}
		if len(attributesToSet) > 0 && !stringSliceContains(attributesToSet, attribute.Name) {
			debugLog("ldap_object::read - skipping unselected attribute %q of %q", attribute.Name, dn)
			continue
		}
		if len(attribute.Values) == 1 {
			// we don't treat the RDN as an ordinary attribute
			a := fmt.Sprintf("%s=%s", attribute.Name, attribute.Values[0])
			if strings.HasPrefix(dn, a) {
				debugLog("ldap_object::read - skipping RDN %q of %q", a, dn)
				continue
			}
		}
		debugLog("ldap_object::read - adding attribute %q to %q (%d values)", attribute.Name, dn, len(attribute.Values))
		// now add each value as an individual entry into the object, because
		// we do not handle name => []values, and we have a set of maps each
		// holding a single entry name => value; multiple maps may share the
		// same key.
		for _, value := range attribute.Values {
			debugLog("ldap_object::read - for %q, setting %q => %q", dn, attribute.Name, value)
			set.Add(map[string]interface{}{
				attribute.Name: value,
			})
		}
	}

	if err := d.Set("attributes", set); err != nil {
		warnLog("ldap_object::read - error setting LDAP attributes for %q : %v", dn, err)
		return err
	}
	return nil
}

// computes the hash of the map representing an attribute in the attributes set
func attributeHash(v interface{}) int {
	m := v.(map[string]interface{})
	var buffer bytes.Buffer
	buffer.WriteString("map {")
	for k, v := range m {
		buffer.WriteString(fmt.Sprintf("%q := %q;", k, v.(string)))
	}
	buffer.WriteRune('}')
	h := int(crc32.ChecksumIEEE([]byte(buffer.String())))
	if h >= 0 {
		return h
	}
	if -h >= 0 {
		return -h
	}
	return 0
}

func printAttributes(prefix string, attributes interface{}) string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("%s: {\n", prefix))
	if attributes, ok := attributes.(*schema.Set); ok {
		for _, attribute := range attributes.List() {
			for k, v := range attribute.(map[string]interface{}) {
				buffer.WriteString(fmt.Sprintf("    %q: %q\n", k, v.(string)))
			}
		}
		buffer.WriteRune('}')
	}
	return buffer.String()
}

func computeAndAddDeltas(modify *ldap.ModifyRequest, os, ns *schema.Set, attributesToSkip, attributesToSet []string) error {
	shouldSkipAttribute := func(k string) bool {
		if len(attributesToSet) > 0 && !stringSliceContains(attributesToSet, k) {
			return true
		}
		if len(attributesToSkip) > 0 && stringSliceContains(attributesToSkip, k) {
			return true
		}
		debugLog("Not going to skip attribute %q", k)
		return false
	}

	rk := util.NewSet() // names of removed attributes
	for _, v := range os.Difference(ns).List() {
		for k := range v.(map[string]interface{}) {
			rk.Add(k)
		}
	}

	ak := util.NewSet() // names of added attributes
	for _, v := range ns.Difference(os).List() {
		for k := range v.(map[string]interface{}) {
			ak.Add(k)
		}
	}

	kk := util.NewSet() // names of kept attributes
	for _, v := range ns.Intersection(os).List() {
		for k := range v.(map[string]interface{}) {
			kk.Add(k)
		}
	}

	ck := util.NewSet() // names of changed attributes

	// loop over remove attributes' names
	for _, k := range rk.List() {
		if shouldSkipAttribute(k) {
			continue
		}
		if !ak.Contains(k) && !kk.Contains(k) {
			// one value under this name has been removed, no other value has
			// been added back, and there is no further value under the same
			// name among those that were untouched; this means that it has
			// been dropped and must go among the RemovedAttributes
			log.Printf("[DEBUG} ldap_object::deltas - dropping attribute %q", k)
			modify.Delete(k, []string{})
		} else {
			ck.Add(k)
		}
	}

	for _, k := range ak.List() {
		if shouldSkipAttribute(k) {
			continue
		}
		if !rk.Contains(k) && !kk.Contains(k) {
			// this is the first value under this name: no value is being
			// removed and no value is being kept; so we're adding this new
			// attribute to the LDAP object (AddedAttributes), getting all
			// the values under this name from the new set
			values := []string{}
			for _, m := range ns.List() {
				for mk, mv := range m.(map[string]interface{}) {
					if k == mk {
						v := toAttributeValue(k, mv.(string))
						values = append(values, v)
					}
				}
			}
			modify.Add(k, values)
			log.Printf("[DEBUG} ldap_object::deltas - adding new attribute %q with values %v", k, values)
		} else {
			ck.Add(k)
		}
	}

	// now loop over changed attributes and
	for _, k := range ck.List() {
		if shouldSkipAttribute(k) {
			continue
		}
		// the attributes in this set have been changed, in that a new value has
		// been added or removed and it was not the last/first one; so we're
		// adding this new attribute to the LDAP object (ModifiedAttributes),
		// getting all the values under this name from the new set
		values := []string{}
		for _, m := range ns.List() {
			for mk, mv := range m.(map[string]interface{}) {
				if k == mk {
					v := toAttributeValue(k, mv.(string))
					values = append(values, v)
				}
			}
		}
		modify.Replace(k, values)
		log.Printf("[DEBUG} ldap_object::deltas - changing attribute %q with values %v", k, values)
	}
	return nil
}

func toAttributeValue(name, value string) string {
	if name == "unicodePwd" {
		utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
		pwdEncoded, _ := utf16.NewEncoder().String("\"" + value + "\"")
		return pwdEncoded
	}
	return value
}
