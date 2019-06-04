---
layout: "chef"
page_title: "Chef: chef_data_bag_item"
sidebar_current: "docs-chef-data-source-data-bag-item"
description: |-
  Provides a Chef data bag item data source. This can be used to get the JSON content
  of a data bag item.
---

# chef\_data\_bag\_item

The `chef_data_bag_item` data source can be used to fetch JSON encoded data
from a Chef server. The data source supports decrypting encrypted data bags
when a `secret_key` is specified.

## Example Usage

```hcl
data "chef_data_bag_item" "secret" {
  data_bag_name = "foo"
  item_id = "bar"
  secret_key = "${file("baz.key")}"
}
```

## Argument Reference

The following arguments are supported:

* `item_id` - (Required) The data bag item ID.
* `data_bag_name` - (Required) The name of the data bag the item belongs to.
* `secret_key` - (Optional) A secret key string that can be used to decrypt the data bag item.

## Attribute Reference

Currently, the only exported attribute from this data source is `content_json`, which contains
the JSON encoded content of the data bag item.