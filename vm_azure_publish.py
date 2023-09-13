#!/usr/bin/python3
import os
import copy
import json
import argparse
import requests
import logging

from azure.storage.blob import BlobClient, generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta

logging.basicConfig(level=logging.DEBUG)

PLANS_METADATA = {
    "flatcar-container-linux-corevm": "arm64",
    "flatcar-container-linux-corevm-amd64": "amd64",
    "flatcar-container-linux-free": "amd64",
    "flatcar-container-linux": "amd64",
    "flatcar_pro": "amd64",
}

CHANNELS_METADATA = {
    "alpha": [
        "flatcar-container-linux-corevm",
        "flatcar-container-linux-corevm-amd64" "flatcar-container-linux-free",
        "flatcar-container-linux",
    ],
    "beta": [
        "flatcar-container-linux-corevm",
        "flatcar-container-linux-corevm-amd64" "flatcar-container-linux-free",
        "flatcar-container-linux",
        "flatcar_pro",
    ],
    "stable": [
        "flatcar-container-linux-corevm",
        "flatcar-container-linux-corevm-amd64" "flatcar-container-linux-free",
        "flatcar-container-linux",
        "flatcar_pro",
    ],
    "lts-2022": ["flatcar-container-linux-free", "flatcar_pro"],
}

TEST_PLANS_METADATA = {
    "test-release-automation-corevm": "amd64",
    "test-release-automation": "amd64",
}

TEST_CHANNEL_METADATA = {
    "release-test-automation": [
        "test-release-automation-corevm",
        "test-release-automation",
    ]
}


def generate_partner_center_token(tenant_id, client_id, secret_value):
    data = f"grant_type=client_credentials&client_id={client_id}&client_secret={secret_value}&resource=https://graph.microsoft.com"
    resp = requests.post(
        url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
    )
    access_token = resp.json().get("access_token")
    return access_token


def generate_az_sas_url(channel, version, arch, **kwargs):
    az_storage_key = os.environ.get("AZ_STORAGE_KEY")
    if az_storage_key is None:
        logging.error("missing env: AZ_STORAGE_KEY")
        return

    account_name = "flatcar"
    container_name = "publish"

    if kwargs.get("test_channel"):
        channel = kwargs.get("test_channel")

    blob_name = f"flatcar-linux-{version}-{channel}-{arch}.vhd"
    sas_query_params = generate_blob_sas(
        account_name=account_name,
        container_name=container_name,
        blob_name=blob_name,
        account_key=az_storage_key,
        permission="rl",
        start=datetime.utcnow() - timedelta(days=1),
        expiry=datetime.utcnow() + timedelta(weeks=4),
    )

    if sas_query_params is not None:
        return f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_query_params}"
    else:
        return None


def get_product_durable_id(access_token, plan):
    resp = requests.get(
        url=f"https://graph.microsoft.com/rp/product-ingestion/product?externalId={plan}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    return resp.json().get("value", [])[0].get("id")


def get_channel_durable_id(access_token, product_durable_id, channel):
    resp = requests.get(
        url=f"https://graph.microsoft.com/rp/product-ingestion/plan?product={product_durable_id}&externalId={channel}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    return resp.json().get("value", [])[0].get("id")


def get_image_versions(
    access_token, product_durable_id, channel_durable_id, corevm=False
):
    endpoint = "virtual-machine-plan-technical-configuration"
    if corevm:
        endpoint = "core-virtual-machine-plan-technical-configuration"

    resp = requests.get(
        url=f"https://graph.microsoft.com/rp/product-ingestion/{endpoint}/{product_durable_id}/{channel_durable_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    return resp.json().get("vmImageVersions")


def draft_new_image_versions(
    access_token,
    channel,
    plan,
    version,
    az_sas_url,
    image_versions,
    image_type_arch,
    corevm=False,
):
    new_vm_image = {
        "versionNumber": version,
        "vmImages": [
            {
                "imageType": f"{image_type_arch}Gen2",
                "source": {
                    "sourceType": "sasUri",
                    "osDisk": {"uri": az_sas_url},
                    "dataDisks": [],
                },
            },
        ],
    }

    if image_type_arch != "arm64":
        new_vm_image["vmImages"].append(
            {
                "imageType": f"{image_type_arch}Gen1",
                "source": {
                    "sourceType": "sasUri",
                    "osDisk": {"uri": az_sas_url},
                    "dataDisks": [],
                },
            }
        )

    image_versions.append(new_vm_image)

    schema_url = "https://product-ingestion.azureedge.net/schema/virtual-machine-plan-technical-configuration/2022-03-01-preview3"
    if corevm:
        schema_url = "https://product-ingestion.azureedge.net/schema/core-virtual-machine-plan-technical-configuration/2022-03-01-preview5"

    payload = {
        "$schema": "https://product-ingestion.azureedge.net/schema/configure/2022-03-01-preview2",
        "resources": [
            {
                "$schema": schema_url,
                "product": {"externalId": f"{plan}"},
                "plan": {"externalId": f"{channel}"},
                "operatingSystem": {"family": "linux", "type": "other"},
                "skus": [
                    {"imageType": f"{image_type_arch}Gen2", "skuId": f"{channel}-gen2"},
                ],
                "vmImageVersions": image_versions,
            }
        ],
    }

    if image_type_arch != "arm64":
        payload["resources"][0]["skus"].append(
            {"imageType": f"{image_type_arch}Gen1", "skuId": f"{channel}"}
        )

    if corevm:
        payload["resources"][0]["softwareType"] = "operatingSystem"

    resp = requests.post(
        url=f"https://graph.microsoft.com/rp/product-ingestion/configure",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        data=json.dumps(payload),
    )


def main():
    parser = argparse.ArgumentParser(
        prog="flatcar_azure_publisher",
        description="Program to publish the Azure Marketplace Images",
    )
    parser.add_argument("-c", "--channel")
    parser.add_argument("-v", "--version")
    parser.add_argument("-s", "--az-sas-url")
    parser.add_argument("-t", "--test-mode", action="store_true")
    parser.add_argument("-z", "--test-channel")
    args = parser.parse_args()

    if not all((args.channel, args.version)):
        logging.error("Both version and channel is required")
        return

    channel = args.channel
    if not args.test_mode and channel not in ("alpha", "beta", "stable", "lts-2022"):
        logging.error("channel value should be either alpha, beta, stable or lts-2022")
        return

    if args.test_mode:
        test_channel = args.test_channel

    version = args.version
    az_sas_url = args.az_sas_url

    ## secrets, and other confidential variables
    tenant_id = os.environ.get("AZ_TENANT_ID")
    client_id = os.environ.get("AZ_CLIENT_ID")
    secret_value = os.environ.get("AZ_SECRET_VALUE")

    if not all((tenant_id, client_id, secret_value)):
        logging.error("Required: AZ_TENANT_ID, AZ_CLIENT_ID, AZ_SECRET_VALUE")
        return

    access_token = generate_partner_center_token(tenant_id, client_id, secret_value)

    if args.test_mode:
        CHANNELS_METADATA = copy.deepcopy(TEST_CHANNEL_METADATA)
        PLANS_METADATA = copy.deepcopy(TEST_PLANS_METADATA)

    for plan in CHANNELS_METADATA.get(channel, []):
        corevm = False
        if "corevm" in plan:
            corevm = True

        arch = PLANS_METADATA.get(plan)
        if arch is None:
            continue

        if az_sas_url is None:
            if test_channel:
                kwargs = {"test_channel": test_channel}
            az_sas_url = generate_az_sas_url(channel, version, arch, **kwargs)
            if az_sas_url is None:
                logging.error(
                    f"generate_az_sas_url returned None for {channel}, {version}, {arch}"
                )
                continue

        product_durable_id = get_product_durable_id(access_token, plan)
        channel_durable_id = get_channel_durable_id(
            access_token, product_durable_id, channel
        )

        product_durable_id = product_durable_id.split("/")[1]
        channel_durable_id = channel_durable_id.split("/")[2]

        image_versions = get_image_versions(
            access_token, product_durable_id, channel_durable_id, corevm=corevm
        )

        image_type_arch = "x64"
        if PLANS_METADATA[plan] == "arm64":
            image_type_arch = "arm64"

        draft_new_image_versions(
            access_token,
            channel,
            plan,
            version,
            az_sas_url,
            image_versions,
            image_type_arch,
            corevm=corevm,
        )


if __name__ == "__main__":
    main()