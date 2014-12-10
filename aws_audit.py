#!/usr/bin/env python

import sys
import boto.ec2
import boto.iam
import getopt
import json
import requests
import datetime
import pytz

def main(argv=sys.argv):
  try:
    opts, args = getopt.getopt(argv, "a:s:r:t:h", ["aws_access_key=", "aws_secret_key=", "regions=", "tags=", "help"])
  except getopt.GetoptError:
    usage()
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
        usage()
        sys.exit()
    elif opt in ("-a", "--aws_access_key"):
        aws_access_key = arg
    elif opt in ("-s", "--aws_secret_key"):
        aws_secret_key = arg
    elif opt in ("-r", "--regions"):
        regions = arg.split(",")
    elif opt in ("-t", "--tags"):
        tags = arg.split(",")

  route_audit = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/aws_tag_audit/"
  route_violator = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/aws_tag_violator/"

  # IAM for all regions is the same...
  iam = boto.iam.connect_to_region("us-west-2",
      aws_access_key_id=aws_access_key,
      aws_secret_access_key=aws_secret_key)

  alias = iam.get_account_alias()['list_account_aliases_response']['list_account_aliases_result']['account_aliases'][0]

  violators = []

  for region in regions:
    violators.append(get_violators(aws_access_key, aws_secret_key, region, tags))

  violators = [y for x in violators for y in x]

  time = datetime.datetime.now(pytz.utc)
  time_formatted = str(time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + time.strftime("%z"))

  audit_document = {
    "@timestamp": time_formatted,
    "account": alias,
    "tag_scheme": tags,
    "violator_count": len(violators),
    "violators": violators
  }

  requests.post(route_audit, data=json.dumps(audit_document))

  for v in violators:
    v_document = dict(list({"@timestamp": time_formatted, "account": alias}.items()) + list(v.items()))
    requests.post(route_violator, data=json.dumps(v_document))


def get_violators(access, secret, region, tags):
  conn = boto.ec2.connect_to_region(region,
      aws_access_key_id=access,
      aws_secret_access_key=secret)

  instance_list = []

  not_terminated = { "instance-state-name":["running", "shutting-down", "stopping", "stopped"] }

  try:
    reservations = conn.get_all_reservations(filters=not_terminated)
  except AttributeError:
    return instance_list

  for res in reservations:
    for instance in res.instances:
      present = []
      def check(i):
        if i in map(lambda x: x.lower(), instance.tags.keys()):
          return True
        else:
          return False
      present = [check(i) for i in tags]
      if False in present:
        instance_list.append({'id': instance.id, 'tags': [x+"="+instance.tags[x] for x in instance.tags], 'state': instance.state, 'region': region})

  return instance_list

if __name__ == "__main__":
  main(sys.argv[1:])