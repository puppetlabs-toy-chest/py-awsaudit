#!/usr/bin/env python

import sys
import getopt
import json
import requests
import datetime
import pytz
import time
import sendgrid

def main(argv=sys.argv):

  # Setting default script option parameters before reading command line
  # options give.  Didn't find a better documented way.
  email = False

  try:
    opts, args = getopt.getopt(argv, "u:p:f:t:mh", ["user=", "password=", "from=", "to=", "mail", "help"])
  except getopt.GetoptError:
    usage()
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
        usage()
        sys.exit()
    elif opt in ("-u", "--user"):
        sg_user = arg
    elif opt in ("-p", "--password"):
        sg_password = arg
    elif opt in ("-t", "--to"):
        email_to = arg
    elif opt in ("-f", "--from"):
        email_from = arg
    elif opt in ("-m", "--mail"):
        email = True

  # So much for time.
  current_time = datetime.datetime.now(pytz.utc)
  yesterday_time = current_time - datetime.timedelta(days=1)
  current_formatted = str(current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + current_time.strftime("%z"))
  yesterday_formatted = str(yesterday_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + yesterday_time.strftime("%z"))
  current_index = str(current_time.strftime("%Y.%m.%d"))
  yesterday_index = str(yesterday_time.strftime("%Y.%m.%d"))
  yesterday_email = str(yesterday_time.strftime("%Y-%m-%d"))

  # To help infer the owner of an instance we check the last two days of
  # logstash indexes for cloudtrail tracked AWS API calls.
  user_search = "http://elasticsearch.ops.puppetlabs.net:9200/logstash-" + current_index + ",logstash-" + yesterday_index + "/_search"

  # We'll be searching through our aws-audit index for violators
  route_search = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/_search"

  # A bunch of mostly static data that makes up an ElasticSearch search query.
  # You might notice that size is set to 0.  This is because we query the index
  # twice, once to get the number of matches and then again to retrieve all the
  # matches.  This is to avoid having to deal with paging since we are not
  # querying a terribly large index.
  hits_request = {
    "query": {
      "filtered": {
        "query": {
          "bool": {
            "should": [
              {
                "query_string": {
                  "query": "_type:aws_tag_violator"
                }
              }
            ]
          }
        },
        "filter": {
          "bool": {
            "must": [
              {
                "range": {
                  "@timestamp": {
                    "from": yesterday_formatted,
                    "to": current_formatted
                  }
                }
              }
            ]
          }
        }
      }
    },
    "size": 0,
    "sort": [
      {
        "_score": {
          "order": "desc",
          "ignore_unmapped": True
        }
      }
    ]
  }

  # Get the number of hits to our query
  hits = requests.get(route_search, data=json.dumps(hits_request)).json()

  # Modify size key of hits_request dictionary to match the number of query
  # hits from previous require.
  hits_request["size"] = hits["hits"]["total"]

  # Get all the hits as json
  data = requests.get(route_search, data=json.dumps(hits_request)).json()

  # The pattern I just explained, you'll see it again but this time for getting
  # data from logstash indexes of type cloudtrail for API calls that create or
  # boot stopped instances.
  user_request = {
    "query": {
      "filtered": {
        "query": {
          "bool": {
            "should": [
              {
                "query_string": {
                  "query": "type:cloudtrail"
                }
              }
            ]
          }
        },
        "filter": {
          "bool": {
            "must": [
              {
                "range": {
                  "@timestamp": {
                    "from": yesterday_formatted,
                    "to": current_formatted
                  }
                }
              }
            ],
            "should": [
              {
                "fquery": {
                  "query": {
                    "query_string": {
                      "query": "eventName:(\"RunInstances\")"
                    }
                  },
                  "_cache": True
                }
              },
              {
                "fquery": {
                  "query": {
                    "query_string": {
                      "query": "eventName:(\"StartInstances\")"
                    }
                  },
                  "_cache": True
                }
              }
            ],
            "must_not": [
              {
                "fquery": {
                  "query": {
                    "query_string": {
                      "query": "errorCode:/.*/"
                    }
                  },
                  "_cache": True
                }
              }
            ]
          }
        }
      }
    },
    "size": 0,
    "sort": [
      {
        "@timestamp": {
          "order": "desc",
          "ignore_unmapped": True
        }
      }
    ]
  }

  user_hits = requests.get(user_search, data=json.dumps(user_request)).json()

  user_request["size"] = user_hits["hits"]["total"]

  user_data = requests.get(user_search, data=json.dumps(user_request)).json()

  # Now we start contructing the body of an email report to send
  grouped = dict()

  # Email header.
  doc = "This report is a list of all instances that will be terminated by the SysOps EC2 audit scripts in the last 24 hours for tag scheme violations come January XX, 2015.  To prevent interruption of work or loss of data you must tag instances to the documented scheme at https://confluence.puppetlabs.com/display/OPS/Tags+and+Tagging.\n\n"

  users = dict()
  user = str()

  # Reducing the cloudtail data obtained from logstash to a simple lookup table
  # of instanceId to username mappings.
  for u in user_data['hits']['hits']:
    users[u['_source']['responseElements']['instancesSet']['items'][0]['instanceId']] = u['_source']['userIdentity']['userName']

  # Iterate through all the data obtained from aws_audits and create a key for
  # each IAM alias, set to an empty set.
  for h in data["hits"]["hits"]:
    grouped[h["_source"]["account"]] = set([])

  # For each unique IAM alias iterate through aws_audits data, obtaining each
  # instanceId and looking that ID up in the users lookup table we created
  # earlier from the logstash data to identify possible owner of instance.
  # Construct a string of instanceId, inferred user, and any tags assigned to the
  # instance and added that to the set that corresponds to the IAM alias it was
  # associated with.
  for g in grouped:
    for h in data["hits"]["hits"]:
      if h['_source']['account'] == g:
        if h['_source']['id'] in users:
          user = users[h['_source']['id']]
        else:
          user = 'Unable to locate'

        grouped[g].add("ID: " + h['_source']['id'] + " USER: " + user + " TAGS: " + ",".join(h['_source']['tags']))

  # Add a section to our email body for each IAM alias
  for g in grouped:
    doc += (g + " IAM root account: TO BE TERMINATED" + "\n")
    for i in grouped[g]:
      doc += ("  " + i + "\n")
    doc += "\n"

  # Send the email via SendGrid
  if email == True:
    sg = sendgrid.SendGridClient(sg_user, sg_password)

    message = sendgrid.Mail()
    message.add_to(email_to)
    message.set_subject("EC2 Termination Report: " + yesterday_email)
    message.set_text(doc)
    message.set_from(email_from)
    status, msg = sg.send(message)
  else:
    print(doc)

if __name__ == "__main__":
  main(sys.argv[1:])
