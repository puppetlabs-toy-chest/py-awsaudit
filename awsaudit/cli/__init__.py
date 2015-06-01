import sys
import getopt
from awsaudit import AwsAudit

def main(argv=sys.argv):

  options = {}

  # Setting default script options before reading in given command line.
  options['grace'] = 5
  options['terminate'] = False
  options['confirm'] = False

  try:
    opts, args = getopt.getopt(argv, "a:s:r:t:g:kch", ["aws_access_key=", "aws_secret_key=", "regions=", "tags=", "grace=", "terminate", "confirm", "help"])
  except getopt.GetoptError:
    usage()
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
        usage()
        sys.exit()
    elif opt in ("-k", "--terminate"):
        options['terminate'] = True
    elif opt in ("-c", "--confirm"):
        options['confirm'] = True
    elif opt in ("-a", "--aws_access_key"):
        options['aws_access_key'] = arg
    elif opt in ("-s", "--aws_secret_key"):
        options['aws_secret_key'] = arg
    elif opt in ("-r", "--regions"):
        options['regions'] = arg.split(",")
    elif opt in ("-t", "--tags"):
        options['tags'] = arg.split(",")
    elif opt in ("-g", "--grace"):
        options['grace'] = float(arg)

  AwsAudit(**options).audit()
