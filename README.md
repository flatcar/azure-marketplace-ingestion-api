### azure-marketplace-ingestion-api

This is a POC project to test the [Azure Product Ingestion API](https://learn.microsoft.com/en-us/partner-center/marketplace/product-ingestion-api). The POC is built keeping the Flatcar Container Linux release process in mind, but tried to make it as generic as possible. If you have a more customized usecase, feel free to file a PR.

The current supported APIs are for Azure Marketplace Virtual Machine offers, and Azure Marketplace Core Virtual Machine offers.


#### Usage

Use the config file as per your requirements, "az_storage", "offer_metadata", and "plan_metdata" are the required section. The test sections are when you run the script in test mode.

- `az_storage` is required to build the SAS url.
- `offer_metadata` is section for mapping offer to arch.
- `plan_metadata` is section for mapping plan to the list of offer it is in.

```
[az_storage]
account_name = "flatcar"
container_name = "publish"
blob_name_format = "flatcar-linux-{version}-{plan}-{arch}.vhd"

[offer_metadata]
flatcar-container-linux-corevm = "arm64"
flatcar-container-linux-corevm-amd64 = "amd64"
flatcar-container-linux-free = "amd64"
flatcar-container-linux = "amd64"
flatcar_pro = "amd64"

[plan_metadata]
alpha = ["flatcar-container-linux-corevm", "flatcar-container-linux-corevm-amd64", "flatcar-container-linux-free", "flatcar-container-linux"]
beta = ["flatcar-container-linux-corevm", "flatcar-container-linux-corevm-amd64", "flatcar-container-linux-free", "flatcar-container-linux", "flatcar_pro"]
stable = ["flatcar-container-linux-corevm", "flatcar-container-linux-corevm-amd64", "flatcar-container-linux-free", "flatcar-container-linux", "flatcar_pro"]
lts-2022 = ["flatcar-container-linux-free", "flatcar_pro"]

[test_offer_metadata]
test-release-automation-corevm = "amd64"
test-release-automation = "amd64"

[test_plan_metadata]
release-test-automation = ["test-release-automation-corevm", "test-release-automation"]
```

To run the script:
```
AZ_STORAGE_KEY=<randoms_az_storage_key> AZ_TENANT_ID=<az_tenant_id> AZ_SECRET_VALUE=<az_secret_value> AZ_CLIENT_ID=<az_client_id> python vm_azure_publish.py -p release-test-automation -v 3717.0.0 --test-mode --test-plan alpha
```

