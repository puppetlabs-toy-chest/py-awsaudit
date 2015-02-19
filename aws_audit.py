#!/usr/bin/env python

import sys
import boto.ec2
import boto.iam
import getopt
import json
import requests
import datetime
import time
import pytz

def main(argv=sys.argv):

  # Setting default script options before reading in given command line.
  grace = 5
  terminate = False

  try:
    opts, args = getopt.getopt(argv, "a:s:r:t:g:kh", ["aws_access_key=", "aws_secret_key=", "regions=", "tags=", "grace=", "terminate",  "help"])
  except getopt.GetoptError:
    usage()
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
        usage()
        sys.exit()
    elif opt in ("-k", "--terminate"):
        terminate = True
    elif opt in ("-a", "--aws_access_key"):
        aws_access_key = arg
    elif opt in ("-s", "--aws_secret_key"):
        aws_secret_key = arg
    elif opt in ("-r", "--regions"):
        regions = arg.split(",")
    elif opt in ("-t", "--tags"):
        tags = arg.split(",")
    elif opt in ("-g", "--grace"):
        grace = float(arg)

  # ElasticSearch route for posting documents.  One for a combined rollup and
  # one for each violator found.
  route_audit = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/aws_tag_audit/"
  route_violator = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/aws_tag_violator/"

  # AWS console does not require this but API does, it seams or maybe it is
  # just boto but IAM for all regions is the same so we only do this once...I
  # randomly picked us-west-2 because I am from Oregon and run this script most
  # likely from Oregon.
  iam = boto.iam.connect_to_region("us-west-2",
      aws_access_key_id=aws_access_key,
      aws_secret_access_key=aws_secret_key)

  alias = iam.get_account_alias()['list_account_aliases_response']['list_account_aliases_result']['account_aliases'][0]

  # Wow! Do I ever hate dealing with time.
  current_time = datetime.datetime.now(pytz.utc)
  time_formatted = str(current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + current_time.strftime("%z"))

  violators = []

  for region in regions:
    violators.append(get_violators(aws_access_key, aws_secret_key, region, tags, current_time, grace, terminate))

  # List comprehensions are awesome, replaced all my usual uses of map or
  # blocks in ruby.
  violators = [y for x in violators for y in x]

  audit_document = {
    "@timestamp": time_formatted,
    "account": alias,
    "tag_scheme": tags,
    "violator_count": len(violators),
    "violators": violators
  }

  # Posting the rollup to ES, which is the document defined just above.
  requests.post(route_audit, data=json.dumps(audit_document))

  # Posting every violator entry individually.  Probably a better way to do
  # this, like sending them all at once...
  for v in violators:
    v_document = dict(list({"@timestamp": time_formatted, "account": alias}.items()) + list(v.items()))
    requests.post(route_violator, data=json.dumps(v_document))


def get_violators(access, secret, region, tags, current_time, grace=5, terminate=False):
  conn = boto.ec2.connect_to_region(region,
      aws_access_key_id=access,
      aws_secret_access_key=secret)

  instance_list = []

  # Terminating things that are pending is undesirable because instances are
  # likely untagged in this state and it is pretty pointless to try and termiate
  # things taht are already terminating.
  not_terminated = { "instance-state-name":["running", "stopped"] }

  # Else we'll throw a backtrace if they region is empty
  try:
    reservations = conn.get_all_reservations(filters=not_terminated)
  except AttributeError:
    return instance_list

  # A single reservation object can contain multiple instances
  for res in reservations:
    for instance in res.instances:
      present = []
      # Probably bad form
      def check(i):
        if i in [x.lower() for x in instance.tags.keys()]:
          return True
        else:
          return False
      present = [check(i) for i in tags]
      if False in present:
        # Only kill things of a certain age to give people time to tag and
        # account for clock drift between local and EC2.
        age = (time.mktime(datetime.datetime.now(pytz.utc).timetuple()) - time.mktime(time.strptime(instance.launch_time, '%Y-%m-%dT%H:%M:%S.%fZ'))) / 60
        if age > grace:
          instance_list.append({'id': instance.id, 'tags': [x+"="+instance.tags[x] for x in instance.tags], 'state': instance.state, 'region': region, 'age': age })

  # After we obtain violators for region we'll terminate them if requested.
  if terminate:
    protected = ([i['id'] for i in instance_list if conn.get_instance_attribute(i['id'], 'disableApiTermination')['disableApiTermination'] == True ])
    for i in protected:
      conn.modify_instance_attribute(i, 'disableApiTermination', False)
    vset = ([i['id'] for i in instance_list])
    if len(vset) != 0:
      conn.terminate_instances(instance_ids=vset)

  # Return our list of violators, even if we terminated them for reporting.
  return instance_list

if __name__ == "__main__":
  main(sys.argv[1:])
