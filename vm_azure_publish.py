#!/usr/bin/python3
import os
import copy
import json
import argparse
import requests
import logging
import tomllib

from azure.storage.blob import BlobClient, generate_container_sas, BlobSasPermissions
from datetime import datetime, timedelta

logging.basicConfig(level=logging.DEBUG)

with open("config.toml", 'rb') as fobj:
    toml_data = tomllib.load(fobj)


def generate_partner_center_token(tenant_id, client_id, secret_value):
    data = f"grant_type=client_credentials&client_id={client_id}&client_secret={secret_value}&resource=https://graph.microsoft.com"
    resp = requests.post(
        url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
    )
    access_token = resp.json().get("access_token")
    return access_token


def generate_az_sas_url(plan, version, arch, **kwargs):
    az_storage_key = os.environ.get("AZ_STORAGE_KEY")
    if az_storage_key is None:
        logging.error("missing env: AZ_STORAGE_KEY")
        return

    az_storage = toml_data.get("az_storage")
    if not az_storage:
        logging.error("Missing `az_storage` section in config.toml")

    account_name = az_storage.get("account_name")
    if not account_name:
        logging.error("Missing `account_name` section in config.toml")

    container_name = az_storage.get("container_name")
    if not container_name:
        logging.error("Missing `container_name` section in config.toml")

    if kwargs.get("test_plan"):
        plan = kwargs.get("test_plan")

    blob_name_format = az_storage.get("blob_name_format")
    if not blob_name_format:
        logging.error("Missing `container_name` section in config.toml")

    blob_name = blob_name_format.format(version=version, plan=plan, arch=arch)

    sas_query_params = generate_container_sas(
        account_name=account_name,
        account_key=az_storage_key,
        container_name=container_name,
        permission="rl",
        start=datetime.utcnow() - timedelta(days=1),
        expiry=datetime.utcnow() + timedelta(weeks=4),
    )

    if sas_query_params is not None:
        return f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_query_params}"
    else:
        return None


def get_product_durable_id(access_token, offer):
    resp = requests.get(
        url=f"https://graph.microsoft.com/rp/product-ingestion/product?externalId={offer}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    return resp.json().get("value", [])[0].get("id")


def get_plan_durable_id(access_token, product_durable_id, plan):
    resp = requests.get(
        url=f"https://graph.microsoft.com/rp/product-ingestion/plan?product={product_durable_id}&externalId={plan}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    return resp.json().get("value", [])[0].get("id")


def get_image_versions(access_token, product_durable_id, plan_durable_id, corevm=False):
    endpoint = "virtual-machine-plan-technical-configuration"
    if corevm:
        endpoint = "core-virtual-machine-plan-technical-configuration"

    resp = requests.get(
        url=f"https://graph.microsoft.com/rp/product-ingestion/{endpoint}/{product_durable_id}/{plan_durable_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    return resp.json().get("vmImageVersions")


def draft_new_image_versions(
    access_token,
    plan,
    offer,
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

    sku_id = f"{plan}-gen2"
    if image_type_arch == "arm64":
        sku_id = f"{plan}"

    payload = {
        "$schema": "https://product-ingestion.azureedge.net/schema/configure/2022-03-01-preview2",
        "resources": [
            {
                "$schema": schema_url,
                "product": {"externalId": f"{offer}"},
                "plan": {"externalId": f"{plan}"},
                "operatingSystem": {"family": "linux", "type": "other"},
                "skus": [
                    {"imageType": f"{image_type_arch}Gen2", "skuId": sku_id},
                ],
                "vmImageVersions": image_versions,
                "vmProperties": {
                    "supportsSriov": True,
                    "supportsNVMe": True,
                    "requiresCustomArmTemplate": True
                }
            }
        ],
    }

    if image_type_arch != "arm64":
        payload["resources"][0]["skus"].append(
            {"imageType": f"{image_type_arch}Gen1", "skuId": f"{plan}"}
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
        prog="azure-marketlace-ingestion-api",
        description="Program to publish the Azure Marketplace Images",
    )
    parser.add_argument("-p", "--plan")
    parser.add_argument("-v", "--version")
    parser.add_argument("-s", "--az-sas-url")
    parser.add_argument("-t", "--test-mode", action="store_true")
    parser.add_argument("-z", "--test-plan")
    args = parser.parse_args()

    if not all((args.plan, args.version)):
        logging.error("Both version and plan is required")
        return

    plan = args.plan
    if not args.test_mode and plan not in ("alpha", "beta", "stable", "lts-2022", "lts-2023"):
        logging.error("plan value should be either alpha, beta, stable, lts-2023 or lts-2022")
        return

    test_plan = None
    if args.test_mode:
        test_plan = args.test_plan

    version = args.version

    ## secrets, and other confidential variables
    tenant_id = os.environ.get("AZ_TENANT_ID")
    client_id = os.environ.get("AZ_CLIENT_ID")
    secret_value = os.environ.get("AZ_SECRET_VALUE")

    if not all((tenant_id, client_id, secret_value)):
        logging.error("Required: AZ_TENANT_ID, AZ_CLIENT_ID, AZ_SECRET_VALUE")
        return

    access_token = generate_partner_center_token(tenant_id, client_id, secret_value)

    if args.test_mode:
        OFFER_METADATA = toml_data.get("test_offer_metadata")
        if not OFFER_METADATA:
            logging.error(
                "test_mode: Missing `test_offer_metadata` section in config.toml"
            )
            return

        PLAN_METADATA = toml_data.get("test_plan_metadata")
        if not PLAN_METADATA:
            logging.error(
                "test_mode: Missing `test_plan_metadata` section in config.toml"
            )
            return
    else:
        OFFER_METADATA = toml_data.get("offer_metadata")
        if not OFFER_METADATA:
            logging.error("Missing `offer_metadata` section in config.toml")

        PLAN_METADATA = toml_data.get("plan_metadata")
        if not PLAN_METADATA:
            logging.error("Missing `plan_metadata` section in config.toml")

    for offer in PLAN_METADATA.get(plan, []):
        az_sas_url = None
        if args.az_sas_url is not None:
            az_sas_url = args.az_sas_url

        corevm = False
        if "corevm" in offer:
            corevm = True

        arch = OFFER_METADATA.get(offer)
        if arch is None:
            continue

        if az_sas_url is None:
            kwargs = {}
            if test_plan:
                kwargs = {"test_plan": test_plan}
            az_sas_url = generate_az_sas_url(plan, version, arch, **kwargs)
            if az_sas_url is None:
                logging.error(
                    f"generate_az_sas_url returned None for {plan}, {version}, {arch}"
                )
                continue

        product_durable_id = get_product_durable_id(access_token, offer)
        plan_durable_id = get_plan_durable_id(access_token, product_durable_id, plan)

        product_durable_id = product_durable_id.split("/")[1]
        plan_durable_id = plan_durable_id.split("/")[2]

        image_versions = get_image_versions(
            access_token, product_durable_id, plan_durable_id, corevm=corevm
        )

        image_type_arch = "x64"
        if OFFER_METADATA[offer] == "arm64":
            image_type_arch = "arm64"

        draft_new_image_versions(
            access_token,
            plan,
            offer,
            version,
            az_sas_url,
            image_versions,
            image_type_arch,
            corevm=corevm,
        )


if __name__ == "__main__":
    main()
