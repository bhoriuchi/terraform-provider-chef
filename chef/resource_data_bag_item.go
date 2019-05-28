package chef

import (
	"encoding/json"
	"fmt"
	"strings"

	chefcrypto "github.com/bhoriuchi/go-chef-crypto"
	"github.com/hashicorp/terraform/helper/schema"

	chefc "github.com/go-chef/chef"
)

func resourceChefDataBagItem() *schema.Resource {
	return &schema.Resource{
		Create: CreateDataBagItem,
		Read:   ReadDataBagItem,
		Delete: DeleteDataBagItem,

		Schema: map[string]*schema.Schema{
			"data_bag_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"content_json": {
				Type:      schema.TypeString,
				Required:  true,
				ForceNew:  true,
				StateFunc: jsonStateFunc,
			},
			"secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				DefaultFunc: schema.EnvDefaultFunc("CHEF_SECRET_KEY", ""),
			},
			"encryption_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				DefaultFunc: schema.EnvDefaultFunc("CHEF_ENCRYPTION_VERSION", chefcrypto.VersionLatest),
			},
		},
	}
}

func CreateDataBagItem(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*chefc.Client)

	dataBagName := d.Get("data_bag_name").(string)
	itemId, itemContent, err := prepareDataBagItemContent(
		d.Get("content_json").(string),
		strings.TrimSpace(d.Get("secret_key").(string)),
		d.Get("encryption_version").(int),
	)

	err = client.DataBags.CreateItem(dataBagName, itemContent)
	if err != nil {
		return err
	}

	d.SetId(itemId)
	d.Set("id", itemId)
	return nil
}

func ReadDataBagItem(d *schema.ResourceData, meta interface{}) error {
	return dataSourceDataBagItemRead(d, meta)
}

func DeleteDataBagItem(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*chefc.Client)

	itemId := d.Id()
	dataBagName := d.Get("data_bag_name").(string)

	err := client.DataBags.DeleteItem(dataBagName, itemId)
	if err == nil {
		d.SetId("")
		d.Set("id", "")
	}
	return err
}

func prepareDataBagItemContent(contentJson, secretKey string, encryptionVersion int) (string, interface{}, error) {
	var value map[string]interface{}
	err := json.Unmarshal([]byte(contentJson), &value)
	if err != nil {
		return "", nil, err
	}

	var itemId string
	if itemIdI, ok := value["id"]; ok {
		itemId, _ = itemIdI.(string)
	}

	if itemId == "" {
		return "", nil, fmt.Errorf("content_json must have id attribute, set to a string")
	}

	// if a secretKey was passed, encrypt the data bag item data
	for key, val := range value {
		// do not encrypt the id, it should never be encrypted
		if key == "id" {
			continue
		}

		// marshal the value to a json string
		jsonData, err := json.Marshal(val)
		if err != nil {
			return "", nil, err
		}

		// encrypt the value and set it on the map
		encryptedItem, err := chefcrypto.Encrypt([]byte(secretKey), []byte(jsonData), encryptionVersion)
		if err != nil {
			return "", nil, err
		}
		value[key] = encryptedItem
	}

	return itemId, value, nil
}
