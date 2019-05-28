package chef

import (
	"encoding/json"
	"strings"

	chefcrypto "github.com/bhoriuchi/go-chef-crypto"
	chefc "github.com/go-chef/chef"
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceDataBagItem() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceDataBagItemRead,
		Schema: map[string]*schema.Schema{
			"item_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"data_bag_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"content_json": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("CHEF_SECRET_KEY", ""),
			},
		},
	}
}

func dataSourceDataBagItemRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*chefc.Client)

	// The Chef API provides no API to read a data bag's metadata,
	// but we can try to read its items and use that as a proxy for
	// whether it still exists.
	var id string
	itemId := d.Get("item_id")

	if itemId == nil {
		// nil item_id means the resource is calling this func, get the id
		id = d.Id()
	} else {
		// non-nil item_id means data source is calling this func, set the id
		id = itemId.(string)
		d.SetId(id)
	}

	dataBagName := d.Get("data_bag_name").(string)
	secretKey := strings.TrimSpace(d.Get("secret_key").(string))
	value, err := client.DataBags.GetItem(dataBagName, id)
	if err != nil {
		if errRes, ok := err.(*chefc.ErrorResponse); ok {
			if errRes.Response.StatusCode == 404 {
				d.SetId("")
				return nil
			}
		} else {
			return err
		}
	}

	// if secret key was set, decrypt the data bag
	if secretKey != "" && value != nil {
		dataBag := value.(map[string]interface{})
		for key, val := range dataBag {
			// do not decrypt the id, it will never be encrypted
			if key == "id" {
				continue
			}

			var decryptedItem interface{}
			itemJSON, err := json.Marshal(val)
			if err != nil {
				return err
			}

			// attempt to decrypt the data bag item
			err = chefcrypto.Decrypt([]byte(secretKey), itemJSON, &decryptedItem)

			// check if the item was not an encrypted data bag item
			// if so, dont update it. otherwise throw any other errors
			if err == chefcrypto.ErrItemNotValid {
				continue
			} else if err != nil {
				return err
			}

			// set the dataBag key to the decrypted item
			dataBag[key] = decryptedItem
		}
		value = dataBag
	}

	jsonContent, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if err := d.Set("content_json", string(jsonContent)); err != nil {
		return err
	}

	return nil
}
