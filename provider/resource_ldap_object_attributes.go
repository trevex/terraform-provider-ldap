package provider

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceLDAPObjectAttributes() *schema.Resource {
	return &schema.Resource{
		Create: resourceLDAPObjectAttributesCreate,
		Read:   resourceLDAPObjectAttributesRead,
		Update: resourceLDAPObjectAttributesUpdate,
		Delete: resourceLDAPObjectAttributesDelete,

		Schema: map[string]*schema.Schema{
			"dn": {
				Type:        schema.TypeString,
				Description: "The Distinguished Name (DN) of the object, as the concatenation of its RDN (unique among siblings) and its parent's DN. The referenced object should exist to be able to add attributes.",
				Required:    true,
				ForceNew:    true,
			},
			"attributes": {
				Type:        schema.TypeSet,
				Description: "The map of attributes to add to the referenced object; each attribute can be multi-valued.",
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
		},
	}
}

func resourceLDAPObjectAttributesCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("ldap_object_attributes::create - adding attributes to object %q", dn)

	request := ldap.NewModifyRequest(dn, []ldap.Control{})

	// if there is a non empty list of attributes, loop though it and
	// create a new map collecting attribute names and its value(s); we need to
	// do this because we could not model the attributes as a map[string][]string
	// due to an appareent limitation in HCL; we have a []map[string]string, so
	// we loop through the list and accumulate values when they share the same
	// key, then we use these as attributes in the LDAP client.
	if v, ok := d.GetOk("attributes"); ok {
		attributes := v.(*schema.Set).List()
		if len(attributes) > 0 {
			debugLog("ldap_object_attributes::create - object %q updated with %d additional attributes", dn, len(attributes))
			m := make(map[string][]string)
			for _, attribute := range attributes {
				debugLog("ldap_object_attributes::create - %q has attribute of type %T", dn, attribute)
				// each map should only have one entry (see resource declaration)
				for name, value := range attribute.(map[string]interface{}) {
					debugLog("ldap_object_attributes::create - %q has attribute[%v] => %v (%T)", dn, name, value, value)
					v := toAttributeValue(name, value.(string))
					m[name] = append(m[name], v)
				}
			}
			// now loop through the map and add attributes with theys value(s)
			for name, values := range m {
				request.Add(name, values)
			}
		}
	}

	err := client.Modify(request)
	if err != nil {
		return err
	}

	debugLog("ldap_object_attributes::create - object %q updated with additional attributes", dn)

	d.SetId(dn)
	return nil
}

func resourceLDAPObjectAttributesRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("ldap_object_attributes::read - looking for object %q", dn)

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
			if err.ResultCode == 32 { // no such object
				warnLog("ldap_object_attributes::read - object not found, removing %q from state because it no longer exists in LDAP", dn)
				d.SetId("")
			}
		}
		debugLog("ldap_object_attributes::read - lookup for %q returned an error %v", dn, err)
		return err
	}

	debugLog("ldap_object_attributes::read - query for %q returned %v", dn, sr)

	// Let's transform the attributes from LDAP into a set that we can intersect
	// with our resources sets.
	ldapSet := &schema.Set{
		F: attributeHash,
	}
	for _, attribute := range sr.Entries[0].Attributes {
		debugLog("ldap_object_attributes::read - adding attribute %q to %q (%d values)", attribute.Name, dn, len(attribute.Values))
		// now add each value as an individual entry into the object, because
		// we do not handle name => []values, and we have a set of maps each
		// holding a single entry name => value; multiple maps may share the
		// same key.
		for _, value := range attribute.Values {
			debugLog("ldap_object_attributes::read - for %q from ldap, setting %q => %q", dn, attribute.Name, value)
			ldapSet.Add(map[string]interface{}{
				attribute.Name: value,
			})
		}
	}

	// We are both interested in the attributes before and after changes, so
	// depending on what is available, let's compute the union
	var (
		prevSet  *schema.Set
		nextSet  *schema.Set
		unionSet *schema.Set
	)
	if d.HasChange("attributes") {
		prev, next := d.GetChange("attributes")
		prevSet = prev.(*schema.Set)
		nextSet = next.(*schema.Set)
	} else {
		nextSet = d.Get("attributes").(*schema.Set)
	}
	if prevSet != nil {
		unionSet = prevSet.Union(nextSet)
	} else {
		unionSet = nextSet
	}

	// Now that we both have union of relevant terraform states and ldap, let's
	// get the intersection and set it.
	set := unionSet.Intersection(unionSet)

	// If the set is empty the attributes do not exist, yet.
	if set.Len() == 0 {
		d.SetId("")
		return nil
	}

	// The set contains values, let's set them and indicate that the object
	// exists by setting the id as well.
	if err := d.Set("attributes", set); err != nil {
		warnLog("ldap_object_attributes::read - error setting attributes for %q : %v", dn, err)
		return err
	}
	d.SetId(dn)
	return nil
}

func resourceLDAPObjectAttributesUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("ldap_object_attributes::update - performing update on %q", dn)

	modify := ldap.NewModifyRequest(dn, []ldap.Control{})

	if d.HasChange("attributes") {
		o, n := d.GetChange("attributes")
		debugLog("ldap_object_attributes::update - \n%s", printAttributes("old attributes map", o))
		debugLog("ldap_object_attributes::update - \n%s", printAttributes("new attributes map", n))

		err := computeAndAddDeltas(modify, o.(*schema.Set), n.(*schema.Set), []string{}, []string{})
		if err != nil {
			return err
		}
	}

	if len(modify.Changes) > 0 {
		err := client.Modify(modify)
		if err != nil {
			errorLog("ldap_object_attributes::update - error modifying LDAP object %q with values %v", d.Id(), err)
			return err
		}
	} else {
		warnLog("ldap_object_attributes::update - didn't actually make changes to %q because there were no changes requested", dn)
	}
	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectAttributesDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	debugLog("ldap_object_attributes::delete - removing attributes from %q", dn)

	modify := ldap.NewModifyRequest(dn, []ldap.Control{})

	err := computeAndAddDeltas(modify, d.Get("attributes").(*schema.Set), &schema.Set{
		F: attributeHash,
	}, []string{}, []string{})
	if err != nil {
		return err
	}

	if len(modify.Changes) > 0 {
		err := client.Modify(modify)
		if err != nil {
			errorLog("ldap_object_attributes::delete - error modifying LDAP object %q with values %v", d.Id(), err)
			return err
		}
	} else {
		warnLog("ldap_object_attributes::delete - didn't actually make changes to %q because there were no changes requested", dn)
	}

	debugLog("ldap_object::delete - %q removed", dn)
	return nil
}
