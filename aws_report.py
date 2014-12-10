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

  current_time = datetime.datetime.now(pytz.utc)
  yesterday_time = current_time - datetime.timedelta(days=1)
  current_formatted = str(current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + current_time.strftime("%z"))
  yesterday_formatted = str(yesterday_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + yesterday_time.strftime("%z"))
  current_index = str(current_time.strftime("%Y.%m.%d"))
  yesterday_index = str(yesterday_time.strftime("%Y.%m.%d"))

  user_search = "http://elasticsearch.ops.puppetlabs.net:9200/logstash-" + current_index + ",logstash-" + yesterday_index + "/_search"
  route_search = "http://elasticsearch.ops.puppetlabs.net:9200/aws-audits/_search"
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

  hits = requests.get(route_search, data=json.dumps(hits_request)).json()

  hits_request["size"] = hits["hits"]["total"]

  data = requests.get(route_search, data=json.dumps(hits_request)).json()

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

  grouped = dict()
  doc = "This report is a list of all instances that will be terminated by the SysOps EC2 audit scripts in the last 24 hours for tag scheme violations come January 12, 2015.  To prevent interruption of work or loss of data you must tag instances to the documented scheme at https://confluence.puppetlabs.com/display/OPS/Cloud+Asset+Management+Standards.\n\n"

  users = dict()
  user = str()

  for u in user_data['hits']['hits']:
    users[u['_source']['responseElements']['instancesSet']['items'][0]['instanceId']] = u['_source']['userIdentity']['userName']

  for h in data["hits"]["hits"]:
    grouped[h["_source"]["account"]] = set([])

  for g in grouped:
    for h in data["hits"]["hits"]:
      if h['_source']['account'] == g:
        if h['_source']['id'] in users:
          user = users[h['_source']['id']]
        else:
          user = 'Unable to locate'

        grouped[g].add("ID: " + h['_source']['id'] + " USER: " + user + " TAGS: " + ",".join(h['_source']['tags']))

  for g in grouped:
    doc += (g + " IAM root account: TO BE TERMINATED" + "\n")
    for i in grouped[g]:
      doc += ("  " + i + "\n")
    doc += "\n"

  if email == True:
    sg = sendgrid.SendGridClient(sg_user, sg_password)

    message = sendgrid.Mail()
    message.add_to(email_to)
    message.set_subject("EC2 Termination Report: " + yesterday_formatted)
    message.set_text(doc)
    message.set_from(email_from)
    status, msg = sg.send(message)
  else:
    print(doc)

if __name__ == "__main__":
  main(sys.argv[1:])
