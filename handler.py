import json
import logging
import boto3

log = logging.getLogger()
log.setLevel(logging.DEBUG)

sns_arn = "arn:aws:sns:us-east-1:670533574044:github-file-to-copy"

def githubWebhook(event, context):
    log.debug("Received event {}".format(json.dumps(event)))
    message = {"foo": "bar"}
    client = boto3.client('sns')
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "input": event
    }
    sns_response = client.publish(
                        TargetArn=sns_arn,
                        Message=json.dumps({'default': json.dumps(message)}),
                        MessageStructure='json'
                    )

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response

def githubFileCopy(event, context):
    log.debug("Received event {}".format(json.dumps(event)))
    return {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "event": event
    }
