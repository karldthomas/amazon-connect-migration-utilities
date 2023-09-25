import boto3
import cfnresponse as cfnresponse
import json

client = boto3.client('connect')


def get_phone_number_details(phone_number):
    response = client.list_phone_numbers_v2()
    print(json.dumps(response, indent=2))

    for phone in response['ListPhoneNumbersSummaryList']:
        if phone['PhoneNumber'] == phone_number:
            return {
                "PhoneNumberId": phone['PhoneNumberId'],
                "PhoneNumber": phone['PhoneNumber'],
                "PhoneNumberType": phone['PhoneNumberType'],
                "PhoneNumberCountryCode": phone['PhoneNumberCountryCode'],
                "PhoneNumberArn": phone['PhoneNumberArn'],
            }

    return None


def handler(event, context):
    try:
        if event["RequestType"] == "Delete":
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
            return
        cfnresponse.validate_resource_properties(event["ResourceProperties"], [
                                                 "PhoneNumber"])
        phone_number = event['ResourceProperties']['PhoneNumber']

        phone_number_details = get_phone_number_details(phone_number)

        if not phone_number_details:
            raise Exception(
                f"No phone number found with number {phone_number} for instance {instance_id}")

        print(phone_number_details)
        cfnresponse.send(event, context, cfnresponse.SUCCESS,
                         phone_number_details)

    except Exception as e:
        print(str(e))
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, reason=str(e))
