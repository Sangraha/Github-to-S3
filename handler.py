''''
acknowledgements
     https://github.com/serverless/examples/blob/master/aws-node-github-webhook-listener/handler.js
     https://github.com/carlos-jenkins/python-github-webhooks/blob/master/webhooks.py
     https://github.com/nytlabs/github-s3-deploy/blob/master/index.js
     https://aws.amazon.com/blogs/compute/sharing-secrets-with-aws-lambda-using-aws-systems-manager-parameter-store/
'''

import json
import logging
import boto3
from botocore.exceptions import ClientError
import base64
import datetime
import hmac , hashlib
import os
import sys

here = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(here, "library"))
from github import Github, GithubException

log = logging.getLogger()
log.setLevel(logging.DEBUG)

#  all required configurations
g_sns_arn = "arn:aws:sns:us-east-1:670533574044:github-file-to-copy"
g_secret_name = "/prod/githubCopy/appConfig"
g_endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"
g_region_name = "us-east-1"
g_myGithubConfig = None


def load_github_config():
    global g_myGithubConfig
    if g_myGithubConfig is None:
        log.debug("Loading config and creating new MyApp...")
        config = get_secret()
        g_myGithubConfig = GithubConfig(config)

class BreakoutException(Exception):
   """Base class for other exceptions"""
   pass


class GithubConfig:
    def __init__(self, config):
        """
        Construct new GithubConfig with configuration
        :param config: application configuration
        """
        self.config = config

    def get_config(self):
        return self.config


def get_secret():
    secret_name = g_secret_name
    endpoint_url = g_endpoint_url
    region_name =  g_region_name
    secret = {}

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        log.error ("got error while reading secret")
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            log.error("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            log.error("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            log.error("The request had invalid params:", e)
        else:
            log.error (e)
    else:
        log.debug ("Getting secret")
        # Decrypted secret using the associated KMS CMK
        # Depending on whether the secret was a string or binary, one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']
            log.debug("binary secret is not being handled here")
            # Your code goes here.
    log.debug("SECRECT : {}".format(secret))
    return json.loads(secret)

def send_message(client,repname, githubFile, s3bucket, s3basedir, s3path):
    message = {"repositoryName": repname,
               "githubFile" : githubFile,
               "s3bucket" : s3bucket,
               "s3basedir": s3basedir,
               "s3path" : s3path
               }

    sns_response = client.publish(
        TargetArn=g_sns_arn,
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure='json'
    )
    log.debug("send message response :".format( sns_response))

def queue_files_to_download(repository, sha, server_path, bucket, basedir, repname, sns_client):
    contents = repository.get_dir_contents(server_path, ref=sha)
    for content in contents:
        if content.type == 'dir':
            queue_files_to_download(repository, sha, content.path, bucket, basedir+"/"+content.path,repname, sns_client)
        else :
            try:
                path = content.path
                #file_content = repository.get_contents(path, ref=sha)
                #file_data = base64.b64decode(file_content.content)
                #s3.Object(bucket, basedir + "/" +content.name).put(Body=file_data)
                send_message(sns_client, repname, path, bucket,basedir,content.name)
                log.debug( "queing file = {}".format( path) + " to s3 path = {}".format( basedir) + "/".format( content.name))
            except (GithubException, IOError) as exc:
                log.error('Error processing %s: %s', content.path, exc)


def download_file(repository, path,sha,bucket,content, basedir):
    s3 = boto3.resource('s3')
    file_content = repository.get_contents(path, ref=sha)
    file_data = base64.b64decode(file_content.content)
    s3.Object(bucket, basedir + "/" + content.name).put(Body=file_data)
    log.debug("writing file = ", content.name, " to s3 path = ", basedir + "/" + content.name)


def githubWebhook(event, context):
    log.debug("event : ", event)
    headers = event["headers"]
    sig = headers['X-Hub-Signature']
    githubEvent = headers['X-GitHub-Event']
    id = headers['X-GitHub-Delivery']
    responseHeaders = {
        'content-type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
        "isBase64Encoded": 'false'
    };
    plain_ret = {
        'statusCode': 401,
        'headers': responseHeaders,
        'body': {"msg": "",
                 "timestamp": datetime.datetime.utcnow().isoformat()
                 }
    }

    try:

        if g_myGithubConfig is None:
            load_github_config()

        secret = g_myGithubConfig.get_config()
        log.debug ("secret = {}".format(secret))
        if secret is None:
            plain_ret['body']['msg'] = 'Internal Configuration Problems'
            plain_ret['statusCode'] = 500
            raise BreakoutException

        if sig is None:
            plain_ret['body']['msg'] = 'No X-Hub-Signature found on request'
            raise BreakoutException

        if githubEvent is None:
            plain_ret['body']['msg'] = 'No X-Github-Event found on request'
            plain_ret['statusCode'] = 422
            raise BreakoutException

        if id is None:
            plain_ret['body']['msg'] = 'No X-Github-Delivery found on request'
            raise BreakoutException

        if secret:
            # Only SHA1 is supported
            header_signature = headers['X-Hub-Signature']
            if header_signature is None:
                plain_ret['body']['msg'] = 'No X-Hub-Signature found on request'
                plain_ret['statusCode'] = 403
                raise BreakoutException

            sha_name, signature = header_signature.split('=')
            log.info ("header_signature = {}".format(header_signature))
            log.debug ("sha_name = {}".format( sha_name))
            log.debug ("signature = {} ".format( signature))
            sha_name = sha_name.strip()
            if sha_name != 'sha1':
                plain_ret['body']['msg'] = 'Only sha1 is supported'
                plain_ret['statusCode'] = 501
                raise BreakoutException

        #validate signature
        log.debug("event body = {}".format(event['body']))
        body = json.loads(event['body'])
        repository = body['repository']['name']
        log.debug("event detected for repository=" + repository)
        node = secret[repository]
        secretAsbytearray = bytearray()
        secretAsbytearray.extend(map(ord, node['githubWebhookSecret']))
        bodyAsbytearray = bytearray()
        bodyAsbytearray.extend(map(ord, str(event["body"])))
        mac = hmac.new(secretAsbytearray, msg=bodyAsbytearray, digestmod=hashlib.sha1)
        log.info("calculated mac={}".format( mac.hexdigest()))
        if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
            log.error ("signature mismatch ")
            plain_ret['body']['msg']  = 'Invalid signature'
            plain_ret['statusCode'] = 403
            raise BreakoutException

        # implement ping
        githubEvent = githubEvent.strip()
        if githubEvent == 'ping':
            plain_ret['body']['msg'] = 'pong'
            plain_ret['statusCode'] = 200
            raise BreakoutException

        plain_ret['body']['msg'] = 'No processing done as event was not relevant'
        if githubEvent == 'push':
            try:
                g = Github(node['githubAPIKey'])
                r = g.get_user().get_repo(repository)
                f_c = r.get_branches()
                matched_branches = [match for match in f_c if match.name == "master"]
                sns_client = boto3.client('sns')
                queue_files_to_download(r, matched_branches[0].commit.sha, "/", node['bucket'], node['bucketDir'],repository, sns_client )
                log.debug("Queued files for Download")
                plain_ret['body']['msg'] = "Push event processed"
                plain_ret['statusCode'] = 200
            except KeyError as e:
                plain_ret['body']['msg'] = 'push event not processed for this repository'

        plain_ret['statusCode'] = 200

    except BreakoutException:
        pass

    plain_ret['body'] = json.dumps(plain_ret['body'])
    return plain_ret


def githubFileCopy(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    try:

        if g_myGithubConfig is None:
            load_github_config()

    except BreakoutException:
        pass

    return {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "event": event
    }



