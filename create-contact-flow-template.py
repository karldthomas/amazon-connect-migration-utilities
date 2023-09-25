# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Known Issues:
#   Contact flows and modules can not have an apostrophe -- ie GetUserInput and PlayPrompt.
#   describe_contact_flow and describe_contact_flow_module will error both in boto3 and from the CLI
#
#   Lex V2 references must be manually attached to the Connect instance

import boto3
import re
import os
import sys
import json
from functools import reduce
import pydash as _

# initialize id -> CF resource name mappings
contact_flows = {}
contact_flow_modules = {}
hours_of_operations = {}
quick_connects = {}
queues = {}
phone_number_parameters = []


def get_current_region():
    easy_checks = [
        # check if set through ENV vars
        os.environ.get('AWS_REGION'),
        os.environ.get('AWS_DEFAULT_REGION'),
        boto3.DEFAULT_SESSION.region_name if boto3.DEFAULT_SESSION else None,
        boto3.Session().region_name,
    ]
    for region in easy_checks:
        if region:
            return region


# Uses the Connect APIs to retrieve contact flows from the Connect instance
# the format of the exported contact flows is not the same as what are exported from
def export_contact_flow(name, resource_type):
    print("Retrieving contact flows...")
    pageNumber = 0
    contact_flow_number = 0

    # we only want to retrieve contact flows specified in the config file
    for contact_flow in contact_flow_list:
        contact_flow_number += 1
        if (name not in contact_flow["Name"]):
            continue
        try:
            print(
                f"Calling describe_contact flow for {contact_flow['Name']}")
            properties = client.describe_contact_flow(
                InstanceId=config["Input"]["ConnectInstanceId"],
                ContactFlowId=contact_flow["Id"]
            )["ContactFlow"]
        except client.exceptions.ContactFlowNotPublishedException:
            print(
                f"Warning: {contact_flow['Name']} is not published, Unable to export.")
            continue
        properties["InstanceArn"] = {"Fn::Sub": connect_arn}

        # Make sure the CloudFormation logical resource name is valid
        resource_name = re.sub(r'[\W_]+', '', contact_flow["Name"])
        contact_flows[contact_flow["Id"]] = resource_name
        template["Resources"].update(
            {resource_name: {
                "Type": resource_type,
                "Properties": {
                }
            }})
        print(f"Creating resource {resource_name}")
        # Some properties  that are returned by the API call should not be included in the output template
        excluded_properties = [
            "Id", "Arn", "ResponseMetadata", "InstanceId", "Tags", "Description"]
        keys_to_add = list(properties.keys() - set(excluded_properties))
        properties_to_add = list(
            map(lambda x: {x: properties[x]}, keys_to_add))

        # add the contact flow to the the CF template
        template["Resources"][resource_name]["Properties"].update(
            reduce(lambda a, b: dict(a, **b), properties_to_add))
        content = template["Resources"][resource_name]["Properties"]["Content"]

        print("Processing contact flow content")
        # Replace the hard coded partition, region, account number and Connect Instance ID with parameters
        content = replace_pseudo_parms(content)

        # Associate any Lambdas found to the Connect instance
        attach_lambdas(content)

        # some resource types are created by default when you create a Connect instance
        # the identifiers will be different between accounts.  Map the source identifiers to the destination
        content = replace_with_mappings(content)

        # Add the resource to the template
        print("Adding the resource {resource_name} to the template")
        template["Resources"][resource_name]["Properties"]["Content"] = {
            "Fn::Sub": content}


def get_phone_number_by_id(phone_number_id):
    # Create a Boto3 Amazon Connect client
    print(f"Retrieving phone number for {phone_number_id}")
    connect_client = boto3.client('connect', region_name=region)

    # Describe the phone number using its ID
    response = connect_client.describe_phone_number(
        PhoneNumberId=phone_number_id
    )

    # Extract and return the phone number
    description = response['ClaimedPhoneNumberSummary']['PhoneNumberDescription']
    return description


def get_hours_of_operation_by_id(instance_id, hours_of_operation_id):
    # Initialize the AWS Connect client
    connect = boto3.client('connect', region_name=region)

    try:
        # Describe the hours of operation for the given instance and ID
        response = connect.describe_hours_of_operation(
            InstanceId=instance_id,
            HoursOfOperationId=hours_of_operation_id
        )

        # Extract the name of the hours of operation
        hours_of_operation = response['HoursOfOperation']
        name = hours_of_operation['Name']

        return name

    except Exception as e:
        print(f"Error: {str(e)}")
        return None


def get_contact_flow_name(contact_flow_id):
    return next((flow for flow in contact_flow_list if flow['Id'] == contact_flow_id), None)


def get_contact_flows(instance_id):
    paginator = connect_client.get_paginator('list_contact_flows')
    response_iterator = paginator.paginate(
        InstanceId=instance_id,
        ContactFlowTypes=['CONTACT_FLOW',
                          'CUSTOMER_QUEUE',
                          'CUSTOMER_HOLD',
                          'CUSTOMER_WHISPER',
                          'AGENT_HOLD',
                          'AGENT_WHISPER',
                          'OUTBOUND_WHISPER',
                          'AGENT_TRANSFER',
                          'QUEUE_TRANSFER'],

    )

    contact_flows = []

    for page in response_iterator:
        contact_flows.extend(page['ContactFlowSummaryList'])

    return contact_flows

# Uses the Connect APIs to retrieve contact flow modules from the Connect instance
# the format of the exported contact flows is not the same as what are exported from Connect


def export_contact_flow_modules(name, resource_type):
    paginator = client.get_paginator('list_contact_flow_modules')
    print("Retrieving contact flow modules...")
    for page in paginator.paginate(InstanceId=config["Input"]["ConnectInstanceId"],
                                   ContactFlowModuleState="active",
                                   PaginationConfig={
        "MaxItems": 50,
        "PageSize": 50,
    }):

        for contact_flow_module in page["ContactFlowModulesSummaryList"]:
            if (name not in contact_flow_module["Name"]):
                continue

            print(
                f"Calling describe_contact_flow_module for {contact_flow_module['Name']}")
            properties = client.describe_contact_flow_module(
                InstanceId=config["Input"]["ConnectInstanceId"],
                ContactFlowModuleId=contact_flow_module["Id"].split("/")[-1]
            )

            properties = properties["ContactFlowModule"]
            properties["InstanceArn"] = {"Fn::Sub": connect_arn}

            # CF ResourceNames should only contain letters and a '-'
            resource_name = re.sub(
                r'[\W_]+', '', contact_flow_module["Name"])+"Module"
            contact_flow_modules[contact_flow_module["Id"]] = resource_name
            print(f"Creating resource {resource_name}")

            template["Resources"].update(
                {resource_name: {
                    "Type": resource_type,
                    "Properties": {
                    }
                }})

            # Map API response to CF properties and exclude properties that are not supported.
            excluded_properties = [
                "Id", "Arn", "ResponseMetadata", "InstanceId", "Status", "Tags", "Description"]
            keys_to_add = list(properties.keys() - set(excluded_properties))
            properties_to_add = list(
                map(lambda x: {x: properties[x]}, keys_to_add))

            template["Resources"][resource_name]["Properties"].update(
                reduce(lambda a, b: dict(a, **b), properties_to_add))

            content = template["Resources"][resource_name]["Properties"]["Content"]
            print("Processing contact flow content")
            # Replace the hard coded partition, region, account number and Connect Instance ID with parameters
            content = replace_pseudo_parms(content)

            # Attach any Lambdas found to the Connect instance
            attach_lambdas(content)

            # some resource types are created by default when you create a Connect instance
            # the identifiers will be different between accounts.  Map the source identifiers to the destination
            content = replace_with_mappings(content)
            template["Resources"][resource_name]["Properties"]["Content"] = {
                "Fn::Sub": content}

            # Map the phone number from the destination Connect instance to the source connect instance
            for source_phone, target_phone in phone_number_mappings.items():
                content = content.replace(source_phone, target_phone)
            template["Resources"][resource_name]["Properties"]["Content"] = {
                "Fn::Sub": content}

            # The API returns the state as lowercase.  CF requires it to be uppercase.
            state = template["Resources"][resource_name]["Properties"]["State"].upper(
            )
            print("Adding the resource {resource_name} to the template")

            template["Resources"][resource_name]["Properties"]["State"] = state


# Uses the Connect APIs to retrieve hours of operations from the Connect instance
# the format of the exported contact flows is not the same as what are exported from
def export_hours_of_operation(resource_type):
    print("Processing hours of operation")
    paginator = client.get_paginator('list_hours_of_operations')
    for page in paginator.paginate(InstanceId=config["Input"]["ConnectInstanceId"],
                                   PaginationConfig={
        "MaxItems": 50,
        "PageSize": 50,
    }):

        for hours_of_operation in page["HoursOfOperationSummaryList"]:
            if (hours_of_operation["Name"] == "Basic Hours"):
                continue

            print(
                f"Calling describe_hours_of_operation for {hours_of_operation['Name']}")
            properties = client.describe_hours_of_operation(
                InstanceId=config["Input"]["ConnectInstanceId"],
                HoursOfOperationId=hours_of_operation["Id"].split("/")[-1]
            )["HoursOfOperation"]

            properties["InstanceArn"] = {"Fn::Sub": connect_arn}

            # CF ResourceNames should only contain letters and a '-'
            resource_name = re.sub(
                r'[\W_]+', '', hours_of_operation["Name"])+"HoursOfOperation"
            hours_of_operations[hours_of_operation["Id"]] = resource_name
            template["Resources"].update(
                {resource_name: {
                    "Type": resource_type,
                    "Properties": {
                    }
                }})
            print(f"Creating resource {resource_name}")
            # Map API response to CF properties and exclude properties that are not supported.
            excluded_properties = [
                "Id",
                "Arn",
                "ResponseMetadata",
                "InstanceId",
                "HoursOfOperationId",
                "HoursOfOperationArn",
                "Tags",
                "Description"
            ]
            keys_to_add = list(properties.keys() - set(excluded_properties))

            properties_to_add = list(
                map(lambda x: {x: properties[x]}, keys_to_add))
            template["Resources"][resource_name]["Properties"].update(
                reduce(lambda a, b: dict(a, **b), properties_to_add))


def export_queues(name, resource_type):
    print("Processing queues")
    paginator = client.get_paginator('list_queues')
    for page in paginator.paginate(InstanceId=config["Input"]["ConnectInstanceId"],
                                   QueueTypes=["STANDARD"],
                                   PaginationConfig={
                                       "MaxItems": 50,
                                       "PageSize": 50,
    }):

        for queue in page["QueueSummaryList"]:
            print(queue)
            if (name not in queue["Name"]):
                continue

            print(f"Calling describe_queue for {queue['Name']}")
            properties = client.describe_queue(
                InstanceId=config["Input"]["ConnectInstanceId"],
                QueueId=queue["Id"].split("/")[-1]
            )["Queue"]

            properties["InstanceArn"] = {"Fn::Sub": connect_arn}

            # CF ResourceNames should only contain letters and a '-'
            resource_name = re.sub(
                r'[\W_]+', '', queue["Name"]) + "Queue"
            queues[queue["Id"]] = resource_name
            template["Resources"].update(
                {resource_name: {
                    "Type": resource_type,
                    "Properties": {
                    }
                }})
            print(f"Creating resource {resource_name}")

            # Map API response to CF properties and exclude properties that are not supported.
            excluded_properties = [
                "Id",
                "Arn",
                "ResponseMetadata",
                "InstanceId",
                "QueueId",
                "QueueArn",
                "Tags"
            ]
            keys_to_add = list(properties.keys() - set(excluded_properties))

            properties_to_add = list(
                map(lambda x: {x: properties[x]}, keys_to_add))
            template["Resources"][resource_name]["Properties"].update(
                reduce(lambda a, b: dict(a, **b), properties_to_add))


def attach_lambdas(content):
    content = json.loads(content)
    lambda_attachments = list(
        filter(lambda t: t["Type"] == "InvokeLambdaFunction", content["Actions"]))

    for attachment in lambda_attachments:
        lambda_arn = _.get(attachment, "Parameters.LambdaFunctionARN")
        lambda_name = lambda_arn.split(":")[-1]
        resource_name = re.sub(r'[\W_]+', '', lambda_name)+"LambdaPermission"

        print(f"Creating an AttachLambda resource for {lambda_name}")
        template["Resources"].update(
            {
                resource_name: {
                    "Type": "Custom::ConnectAssociateLambda",
                    "Properties": {
                        "InstanceId": {"Ref": "ConnectInstanceID"},
                        "FunctionArn": {"Fn::Sub": lambda_arn},
                        "ServiceToken": {"Fn::ImportValue": "CFNConnectAssociateLambda"}
                    }
                }
            })


def get_lexbot_details(lex_id):
    lex_client = boto3.client('lexv2-models', region_name=get_current_region())
    lex_bot_details = lex_client.describe_bot(botId=lex_id.split("/")[1])
    lex_alias_details = lex_client.describe_bot_alias(
        botAliasId=lex_id.split("/")[2], botId=lex_id.split("/")[1])

    dest_bot = _.get(
        output_arns, ["LexBotSummaries", lex_bot_details["botName"]])
    dstBotAliasId = list(filter(lambda alias: alias["botAliasName"] == lex_alias_details["botAliasName"],
                         dest_bot["botAliases"]))[0]

    return {
        "alias": lex_alias_details["botAliasName"],
        "name": lex_bot_details["botName"],
        "botId": lex_bot_details["botId"],
        "botAliasId": lex_alias_details["botAliasId"],
        "botAliasName": lex_alias_details["botAliasName"],
        "dstBotId": dest_bot["botId"],
        "dtsBotAliasId": dstBotAliasId
    }


def create_lexV2_attachment_resource(content, lex_details):
    content = json.loads(content)
    lex_attachments = list(filter(
        lambda t: t["Type"] == "ConnectParticipantWithLexBot", content["Actions"]))

    for attachment in lex_attachments:
        lex_arn = _.get(attachment, "Parameters.LexV2Bot.AliasArn")
        resource_name = re.sub(
            r'[\W_]+', '', lex_details["name"])+"LexPermission"
        print(f"Creating an AttachLex resource for {lex_details['name']}")
        return {
            resource_name: {
                "Type": "Custom::ConnectAssociateLex",
                "Properties": {
                        "InstanceId": {"Ref": "ConnectInstanceID"},
                        "AliasArn": {"Fn::Sub": lex_arn},
                        "ServiceToken": {"Fn::ImportValue": "CFNConnectAssociateLexV2Bot"}
                }
            }
        }


# Uses the Connect APIs to retrieve quick connects from the Connect instance
# the format of the exported contact flows is not the same as what are exported from
def export_quick_connects(name, resource_type):
    paginator = client.get_paginator('list_quick_connects')
    for page in paginator.paginate(InstanceId=config["Input"]["ConnectInstanceId"],
                                   QuickConnectTypes=[
                                       "USER", "QUEUE", "PHONE_NUMBER"],
                                   PaginationConfig={
        "MaxItems": 50,
        "PageSize": 50,
    }):

        for quick_connect in page["QuickConnectSummaryList"]:
            if (name not in quick_connect["Name"]):
                continue

            properties = client.describe_quick_connect(
                InstanceId=config["Input"]["ConnectInstanceId"],
                QuickConnectId=quick_connect["Id"].split("/")[-1]
            )["QuickConnect"]

            properties["InstanceArn"] = {"Fn::Sub": connect_arn}
            resource_name = re.sub(
                r'[\W_]+', '', quick_connect["Name"])+"QuickConnect"
            quick_connects[quick_connect["Id"]] = resource_name
            template["Resources"].update(
                {resource_name: {
                    "Type": resource_type,
                    "Properties": {
                    }
                }})
            excluded_properties = ["Id",
                                   "Arn",
                                   "ResponseMetadata",
                                   "InstanceId",
                                   "QuickConnectId",
                                   "QuickConnectARN",
                                   "Tags",
                                   "Description"]
            keys_to_add = list(properties.keys() - set(excluded_properties))

            properties_to_add = list(
                map(lambda x: {x: properties[x]}, keys_to_add))
            template["Resources"][resource_name]["Properties"].update(
                reduce(lambda a, b: dict(a, **b), properties_to_add))


# By the time this method is called, the original arn that is contained in the exported contact flow
# has been converted from this:
#
# arn:aws:connect:us-east-1:987654321:instance/aaaaaa-bbbb-cc1c-dddd-123456789abc/flowid/a1a2a3-dddd-a1b1-dddd-123456789abc
#
# to this
#
# arn:${AWS::Partition}:connect:${AWS::Region}:${AWS::AccountId}:flowid/instance/${ConnectInstandId}/flowid/a1a2a3-dddd-a1b1-dddd-123456789abc
#
# Now we need to replace the resource identifier GUIDs with the contact flow ARNs of the newly created resources
# using the CloudFormation !Ref and !GetAtt intrinsic functions
#
# arn:${AWS::Partition}:connect:${AWS::Region}:${AWS::AccountId}:flowid/instance/${ConnectInstandId}/flowid/${SampleFlow.ContactFlowArn}
#
# the CloudFormation resource names to identifiers mapping was created while the ContactFlows were being
# exported.
def replace_contact_flowids():
    for resource in template["Resources"]:
        if "Content" not in template["Resources"][resource]["Properties"]:
            continue
        content = json.loads(
            template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"])

        # Transfer to agent actions can reference contact flows
        transfers = list(
            filter(lambda t: t["Type"] == "TransferToFlow", content["Actions"]))
        for transfer in transfers:
            contact_flow_arn = transfer["Parameters"]["ContactFlowId"]
            contact_flow_id = transfer["Parameters"]["ContactFlowId"].split(
                "/")[-1]

            if contact_flow_id not in contact_flows:
                raise Exception(
                    f"The Contact Flow {get_contact_flow_name(contact_flow_id)['Name']} was referenced.  But not exported")
            new_arn = contact_flow_arn.replace(
                contact_flow_id, "${" + contact_flows[contact_flow_id] + ".ContactFlowArn}")
            print(
                f"Replaced contact flow reference with {new_arn} in a TransferToFlow action")
            arn_replaced_content = \
                template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"].replace(
                    contact_flow_arn, new_arn)
            template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"] = arn_replaced_content

        # As can UpdateContactEventHooks...
        modules = list(
            filter(lambda t: t["Type"] == "UpdateContactEventHooks", content["Actions"]))
        for module in modules:
            customer_queue = _.get(
                module, "Parameters.EventHooks.CustomerQueue")
            if (customer_queue is None):
                continue
            contact_flow_id = customer_queue.split("/")[-1]
            contact_flow_arn = customer_queue
            if contact_flow_id not in contact_flows:
                raise Exception(
                    f"The Contact Flow {get_contact_flow_name(contact_flow_id)['Name']} was referenced.  But not exported")
            new_arn = "${" + \
                contact_flows[contact_flow_id] + ".ContactFlowArn}"
            print(
                f"Replaced a contact flow reference with {new_arn} in a UpdateContactEventHooks action")

            template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"] = \
                template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"].replace(
                    contact_flow_arn, new_arn)


# Returns the contact flow identifier in the destination instance based on the manifest file
# by the identifier referenced in the source contact flow
#
# This allows contact flows to reference pre-existing contact flows in the destination Connect instance
# that are not being exported
def get_dest_contact_flow_module(contact_flow_id):
    # first look in the current Connect instance
    contact_flow = client.describe_contact_flow_module(
        InstanceId=config["Input"]["ConnectInstanceId"],
        ContactFlowModuleId=contact_flow_id
    )
    contact_flow_name = contact_flow["ContactFlowModule"]["Name"]
    id = _.get(output_arns, [
               "ContactFlowModulesSummaryList", contact_flow_name, "Id"])
    return {
        "name": contact_flow_name,
        "id": id
    }


# This is the same concept as replace_contact_flowids() for contact flow modules
def replace_contact_module_flowids():
    for resource in template["Resources"]:
        if "Content" not in template["Resources"][resource]["Properties"]:
            continue
        content = json.loads(
            template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"])
        content_string = template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"]
        modules = list(
            filter(lambda t: t["Type"] == "InvokeFlowModule", content["Actions"]))
        cf_vars = {}
        for module in modules:
            contact_flow_id = module["Parameters"]["FlowModuleId"]
            dest_module = get_dest_contact_flow_module(contact_flow_id)
            if (contact_flow_id not in contact_flow_modules):
                if (dest_module["id"] is None):
                    raise Exception(
                        f"The referenced module ${dest_module['name']} " +
                        f"in the contact flow ${resource} was not exported and not found in " +
                        "in the destination Connect instance")
                new_arn = dest_module["id"]
            else:

                new_arn = "${" + contact_flow_modules[contact_flow_id] + "}"

            print(
                f"Replaced a contact flow module reference with {new_arn} in a InvokeFlowModule action")
            content_string = content_string.replace(contact_flow_id, new_arn)
        template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"] = [
            content_string, cf_vars]


def get_dest_lex_bot(alias_arn, lex_details):
    dest_id = alias_arn.split(":")[-1]
    bot_id = dest_id.split("/")[1]
    alias_id = dest_id.split("/")[2]

    dest_bot = _.get(output_arns, ["LexBotSummaries", lex_details["name"]])
    dest_alias = list(filter(
        lambda alias: alias["botAliasName"] == lex_details["botAliasName"], dest_bot["botAliases"]))[0]
    dest_arn = alias_arn.replace(bot_id, dest_bot["botId"]).replace(
        alias_id, dest_alias["botAliasId"])
    return dest_arn


def replace_lexbot_ids():
    attachment_resources = []
    for resource in template["Resources"]:
        if "Content" not in template["Resources"][resource]["Properties"]:
            continue
        contact_flow = template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"][0]
        content = json.loads(contact_flow)
        lex_actions = list(filter(
            lambda t: t["Type"] == "ConnectParticipantWithLexBot", content["Actions"]))
        cf_vars = template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"][1]
        for lex_action in lex_actions:
            alias_arn = _.get(lex_action, "Parameters.LexV2Bot.AliasArn")
            lex_id = alias_arn.split(":")[-1]
            lex_details = get_lexbot_details(lex_id)
            dest_arn = get_dest_lex_bot(alias_arn, lex_details)

#            print(f"Replaced a contact flow module reference with {new_arn} in a InvokeFlowModule action")
            contact_flow = contact_flow.replace(alias_arn, dest_arn)
            attachment_resources.append(
                create_lexV2_attachment_resource(contact_flow, lex_details))

        template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"] = [
            contact_flow, cf_vars]

    # add resources to add Lex permissions to the Connect instance
    # This can't be done inline while iterating through the template["Resources"]
    for attachment in attachment_resources:
        template["Resources"].update(attachment)


# This is the same concept as replace_contact_flowids() for contact flow modules
def replace_hours_of_operation():
    for resource in template["Resources"]:
        if "Content" not in template["Resources"][resource]["Properties"]:
            continue
        content = json.loads(
            template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"][0])
        check_hours = list(
            filter(lambda t: t["Type"] == "CheckHoursOfOperation", content["Actions"]))
        for hours in check_hours:
            # Hours is optional in CheckHoursOfOperations.
            # If it is not specified. Hours attached to the current queue are checked.
            if "Hours" not in hours["Parameters"]:
                continue

            hours_arn = hours["Parameters"]["Hours"]
            hours_id = hours_arn.split("/")[-1]
            new_arn =\
                "arn:${AWS::Partition}:connect:${AWS::Region}:" +\
                "${AWS::AccountId}:instance/${ConnectInstanceID}/operating-hours/${" + \
                hours_of_operations[hours_id]+".HoursOfOperationArn}"

            print(
                f"Replaced an hours of opertation reference with {new_arn} in a InvokeFlowModule action")
            template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"][0] =\
                template["Resources"][resource]["Properties"]["Content"]["Fn::Sub"][0].replace(
                    hours_arn, new_arn)


def replace_properties_in_queues():
    for resource_name in template["Resources"]:
        resource = template["Resources"][resource_name]
        if resource["Type"] == "AWS::Connect::Queue":
            id = resource["Properties"]["HoursOfOperationId"]
            if id not in hours_of_operations:
                hours_of_operations_name = get_hours_of_operation_by_id(
                    connect_instance_id, id)
                raise Exception(
                    f"Hours of operation {hours_of_operations_name} referenced in resource_name but was not exported.")
            resource["Properties"]["HoursOfOperationArn"] = {
                "Fn::GetAtt": [hours_of_operations[id], "HoursOfOperationArn"]}
            print(resource)
            del resource["Properties"]["HoursOfOperationId"]

            phone_number_id = resource["Properties"]["OutboundCallerConfig"]["OutboundCallerIdNumberId"]
            del resource["Properties"]["OutboundCallerConfig"]["OutboundCallerIdNumberId"]
            existing_param_index = None
            for idx, param in enumerate(phone_number_parameters):
                if param.get("Description") == description:
                    existing_param_index = idx
                    break

            if existing_param_index is not None:
                phone_number_param_name = "PhoneNumber" + \
                    str(existing_param_index + 1)
            else:
                phone_number_param_name = "PhoneNumber" + \
                    str(len(phone_number_parameters) + 1)

            parameter = {}
            source_phone_number = get_phone_number_by_id(phone_number_id)
            description = "Enter the phone number that corresponds to the phone number for " + \
                source_phone_number + " on the source instance."
            parameter[phone_number_param_name] = {
                "Type": "String",
                "AllowedPattern": "^\+1\d{10}$",
                "ConstraintDescription": "This must be a valid US phone number with the country code",
                "Description": description
            }

            if existing_param_index is None:
                phone_number_parameters.append(parameter)
            else:
                phone_number_parameters[existing_param_index] = parameter

            outbound_flow_id = resource["Properties"]["OutboundCallerConfig"]["OutboundFlowId"]
            del resource["Properties"]["OutboundCallerConfig"]["OutboundFlowId"]
            if outbound_flow_id not in contact_flows:
                raise Exception(
                    f"The Contact Flow {get_contact_flow_name(outbound_flow_id)['Name']} was referenced.  But not exported")
            resource["Properties"]["OutboundCallerConfig"]["OutboundFlowArn"] = {
                "Fn::GetAtt": [contact_flows[outbound_flow_id], "ContactFlowArn"]
            }

    print(phone_number_parameters)


# There are default audio prompts and queues that come with a Connect instance
# map the identifiers to the destination Connect instance
def replace_with_mappings(content):
    content = replace_with_config_mappings(content)
    contact_flow = json.loads(content)
    metadata = _.get(contact_flow, "Metadata.ActionMetadata", {})
    for flow_command in metadata:
        action = metadata[flow_command]
        content = replace_with_mappings_audio_prompt(content, action)
        content = replace_with_mappings_queue(content, action)
    return content


def replace_with_config_mappings(content):
    for source_phone, target_phone in phone_number_mappings.items():
        content = content.replace(source_phone, target_phone)
    return content


def replace_with_mappings_audio_prompt(content, action):
    print("Remapping audio prompts based on the manifest file...")
    if "audio" in action:
        for audio in action["audio"]:
            if (_.get(audio, "type") == "Prompt"):
                text = _.get(audio, "text")
                source_id = _.get(audio, "id").split("/")[-1]
                dest_id = _.get(output_arns, ["PromptSummaryList", text, "Id"])
                content = content.replace(source_id, dest_id)

    return content


def replace_with_mappings_queue(content, action):
    print("Remapping queue identifiers based on the manifest file...")
    if "queue" in action:
        text = _.get(action, "queue.text")
        queue_id = _.get(action, "queue.id")
        if (queue_id is not None):
            source_id = queue_id.split("/")[-1]
            dest_id = _.get(output_arns, ["QueueSummaryList", text, "Id"])
            if dest_id is not None:
                content = content.replace(source_id, dest_id)

    return content


def replace_pseudo_parms(content):
    content = content.replace(account_number, "${AWS::AccountId}")
    content = content.replace(partition, "${AWS::Partition}")
    content = content.replace(region, "${AWS::Region}")
    content = content.replace(
        config["Input"]["ConnectInstanceId"], "${ConnectInstanceID}")
    return content


# config.json contains the configuration information needed by the rest of the script

print("Reading configuration from config.json file")
with open(os.path.join(sys.path[0], 'config.json'), "r") as file:
    config = json.load(file)

# The manifest file contains mappings of resources and their identifiers from the source
# Amazon Connect instance.  This file is created by the create-source-manifest-file.py script
print("Reading the manifest file to obtain identifiers from destination Connect instance")
with open(os.path.join(sys.path[0], config["Output"]["ManifestFileName"]), "r") as file:
    output_arns = json.load(file)

template = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": config["Output"]["TemplateDescription"],
    "Resources": {}
}

# contains mappings to tell the script how to replace phone numbers found in the destination instance with
# phone numbers found in the source instance.
phone_number_mappings = config["Input"]["PhoneNumberMappings"] if "PhoneNumberMappings" in config["Input"] else {}

client = boto3.client('connect', region_name=get_current_region())

# The ARNs for Connect resources contain account specific information. ie:
# arn:aws:connect:us-east-1:987654321:contact_flow/...
#
# The script replaces the account specific parts with their CloudFormation psuedo parameter equivalents.
# arn:${AWS::Partition}:connect:${AWS::Region}:${AWS::AccountId}:contact_flow/...

# Get the current account number
print("Retrieving information from current account.")
sts_client = boto3.client("sts")
identity = sts_client.get_caller_identity()
account_number = identity["Account"]

print(f"Current AWS Account {account_number}")

# Get the current region
region = get_current_region()

connect_client = boto3.client('connect', region_name=region)

print(f"Current region: {region}")
connect_instance_id = config["Input"]["ConnectInstanceId"]
print(f"Retrieving resource from connect instance:{connect_instance_id}")
connect_arn = connect_client.describe_instance(
    InstanceId=connect_instance_id)["Instance"]["Arn"]


# Parse the current partition
# For standard AWS Regions, the partition is aws.
# For resources in other partitions, the partition is aws-partitionname.
# For example, the partition for resources in the China (Beijing and Ningxia) Region is aws-cn
# and the partition for resources in the AWS GovCloud (US-West) region is aws-us-gov.

partition = connect_arn.split(":")[1]
print("Current partition {partition}")


contact_flow_list = get_contact_flows(config["Input"]["ConnectInstanceId"])


# Currently, the script exporting:
#   - hours of operation
#   - contact flow
#   - contact flow modules


connect_arn = replace_pseudo_parms(connect_arn)

for name in config["ResourceFilters"]["ContactFlows"]:
    print(f"Retrieving contact flows containing {name}...")
    # export_quick_connects(name,"AWS::Connect::QuickConnect")
    export_queues(name, "AWS::Connect::Queue")
    export_contact_flow(name, "AWS::Connect::ContactFlow")
    export_contact_flow_modules(name, "AWS::Connect::ContactFlowModule")


export_hours_of_operation("AWS::Connect::HoursOfOperation")


replace_contact_flowids()
replace_contact_module_flowids()
replace_lexbot_ids()
replace_hours_of_operation()
replace_properties_in_queues()

# Add the parameters section to the CloudFormation template
template["Parameters"] = {
    "ConnectInstanceID": {
        "Type": "String",
        "AllowedPattern": ".+",
        "ConstraintDescription": "ConnectInstanceID is required"
    }
}

resource_index = 0
resource = {}


# Create a set to keep track of unique descriptions
unique_descriptions = set()

# Create a new list to store dictionaries with unique descriptions
filtered_data = []

# Iterate through the original data
for item in phone_number_parameters:
    description = item[list(item.keys())[0]]['Description']

    # Check if the description is unique
    if description not in unique_descriptions:
        filtered_data.append(item)
        unique_descriptions.add(description)


for parameter in filtered_data:
    resource_index += 1
    template["Parameters"].update(parameter)
    resource["CFNGetPhoneNumber"+str(resource_index)] = {
        "Type": "Custom::GetPhoneNumberAttribute",
        "Properties": {
            "ServiceToken": {"Fn::ImportValue": "CFNGetPhoneNumberAttributes"},
            "PhoneNumber": {"Ref": "PhoneNumber"+str(resource_index)}

        }
    }
    template["Resources"].update(resource)

with open(os.path.join(sys.path[0], config["Output"]["Filename"]), 'w') as f:
    json.dump(template, f, indent=4, default=str)
