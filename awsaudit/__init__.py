import sys
import boto.ec2
import boto.iam
import json
import requests
import datetime
import time
import pytz

class AwsAudit:

  current_time = datetime.datetime.now(pytz.utc)
  time_formatted =  str(current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + current_time.strftime("%z"))


  def __init__(self, **kwargs):
    # Dynamically define class variables for all passed command line options.
    for option in kwargs:
      setattr(AwsAudit, option, kwargs[option])

    # AWS console does not require this but API does, it seams or maybe it is
    # just boto but IAM for all regions is the same so we only do this once...I
    # randomly picked us-west-2 because I am from Oregon and run this script most
    # likely from Oregon.
    self.iam = boto.iam.connect_to_region("us-west-2", aws_access_key_id=kwargs['aws_access_key'], aws_secret_access_key=kwargs['aws_secret_key'])


  def audit(self):
    account = self.alias()
    violators = []
    u = self.users()

    for r in self.regions:
      region = AwsAuditRegion(r, u)
      region.canary()
      regions_violators = region.violators()
      if self.terminate and regions_violators:
        region.terminate([i['id'] for i in regions_violators])

      violators.append(regions_violators)

    # List comprehensions are awesome, replaced all my usual uses of map or
    # blocks in ruby.  Simple usage to replace my use of Ruby's flatten method.
    violators = [y for x in violators for y in x]

    self.send(violators, account)


  def alias(self):
    alias = self.iam.get_account_alias()['list_account_aliases_response']['list_account_aliases_result']['account_aliases'][0]

    return alias


  def users(self):
    raw = self.iam.get_all_users()
    users = ([x['user_name'] for x in raw['list_users_response']['list_users_result']['users']])

    while raw['list_users_response']['list_users_result']['is_truncated'] == 'true':
      raw = iam.get_all_users(marker=raw['list_users_response']['list_users_result']['marker'])
      users += ([x['user_name'] for x in raw['list_users_response']['list_users_result']['users']])

    return users


  def send(self, violators, account):

    # ElasticSearch route for posting documents.  One for a combined rollup and
    # one for each violator found.
    route_audit = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/aws_tag_audit/"
    route_violator = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/aws_tag_violator/"

    audit_document = {
      "@timestamp": self.time_formatted,
      "account": account,
      "tag_scheme": self.tags,
      "violator_count": len(violators),
      "violators": violators
    }

    # Posting the rollup to ES, which is the document defined just above.
    requests.post(route_audit, data=json.dumps(audit_document))

    # Posting every violator entry individually.  Probably a better way to do
    # this, like sending them all at once...
    for v in violators:
      v_document = dict(list({"@timestamp": self.time_formatted, "account": account}.items()) + list(v.items()))
      requests.post(route_violator, data=json.dumps(v_document))


class AwsAuditRegion(AwsAudit):

  def __init__(self, region, users):
    self.region = region
    self.users = users
    self.connection = boto.ec2.connect_to_region(region, aws_access_key_id=self.aws_access_key, aws_secret_access_key=self.aws_secret_key)


  def canary(self):
    # We only care about a single instance, the one I created as a canary for which I know the tags of.
    canary = self.connection.get_all_instances(filters={
        'tag:created_by':'cody',
        'tag:project':'API canary',
        'tag:department':'sysops',
        'tag:Name':'api-canary-' + self.region,
        'instance-state-name':['stopped', 'stopping'],
      }
    )

    # If we don't find our canary we exit immediately.
    if len(canary) == 0:
      sys.exit("Unable to validate canary from region: " + self.region)

    # Update the canary's timestamp so we can track down region failures.
    i = canary[0].instances[0].id
    self.connection.create_tags(i, { 'canary_timestamp':self.current_time })


  def violators(self):

    instance_list = []

    # Terminating things that are pending is undesirable because instances are
    # likely untagged in this state and it is pretty pointless to try and termiate
    # things taht are already terminating.
    not_terminated = { "instance-state-name":["running", "stopped"] }

    # Else we'll throw a backtrace if they region is empty
    try:
      reservations = self.connection.get_all_reservations(filters=not_terminated)
    except AttributeError:
      return instance_list

    # A single reservation object can contain multiple instances
    for res in reservations:
      for instance in res.instances:
        present = []

        for i in self.tags:
          if i in [x.lower() for x in instance.tags.keys()]:
            present.append(True)
          else:
            present.append(False)

        # This kinda feels like a hacky shortcut...inject False into present if created_by
        # isn't a valid IAM user name so that the code that builds our violators list is
        # triggered.
        if self.cbv:
          if 'created_by' in [x.lower() for x in instance.tags.keys()]:
            tagname = [x for x in instance.tags.keys() if x.lower() == 'created_by']
            if instance.tags[tagname[0]] not in self.users:
              present.append(False)

        if False in present:
          # Only kill things of a certain age to give people time to tag and
          # account for clock drift between local and EC2.
          now = time.mktime(self.current_time.utctimetuple())
          launched = time.mktime(datetime.datetime.strptime(instance.launch_time, '%Y-%m-%dT%H:%M:%S.%fZ').utctimetuple())
          age = (now - launched) / 60
          if age > self.grace:
            instance_list.append({'id': instance.id, 'tags': [x+"="+instance.tags[x] for x in instance.tags], 'state': instance.state, 'region': self.region, 'age': age })

    return instance_list


  def terminate(self, instances):

    protected = ([i for i in instances if self.connection.get_instance_attribute(i, 'disableApiTermination')['disableApiTermination'] == True ])
    for i in protected:
      self.connection.modify_instance_attribute(i, 'disableApiTermination', False)

    self.connection.terminate_instances(instance_ids=instances)
