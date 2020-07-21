#!/usr/bin/env python3

# Sys: allows to interact with the system
import sys
import argparse
import validators
import yaml
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

# print('The arguments are')
# the collection of arguments with which the process is called with
# print(sys.argv)


# constructor (argparse.ArgumentParser), param: description that gets shown
parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerability Analyzer Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
# Pass in configuration file.  Optional arg (--)config, usage info: help
parser.add_argument('--config', help='Path to configuration file')
# flaf: output to report
parser.add_argument('-o', '--output', help='Report file output path')

# if print: is namespace with key-value pairs
args = parser.parse_args()

# Default config.  Is default if no configs from file
config = {'forms': True, 'comments': True, 'passwords': True}

if(args.config):
  print('Using config file: ' + args.config + '\n')
  # Open config file for reading
  config_file = open(args.config, 'r')
  # Take in stream and config to Python object
  config_from_file = yaml.load(config_file, Loader=yaml.FullLoader)
  if(config_from_file):
    # Merge the dictionaries.  **config: first dict, **config_from_file: secondary dict
    config = { **config, **config_from_file }

report = ""

# local var url becomes args.url
url = args.url

# check if it is a valid url (import validators)
#if(validators.url(url)):
#  print('That was a good URL')
#else:
#  print('That one wasn\'t so good')

# check if it is a valid url
if(validators.url(url)):
  result_html = requests.get(url).text
  # Calls BeautifulSoup constructor in html, using html parser as the default parser.
  parsed_html = BeautifulSoup(result_html, 'html.parser')
  # Run through the parsed html and find form
  forms = parsed_html.find_all('form')
  # instruct the parser BeautifulSoup -> perform a lambda function: test if any text is a comment (import comment)
  comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
  # Parser searches for input fields with name attribute of password.  (Plaintext password)
  password_inputs = parsed_html.find_all('input', { 'name' : 'password'})

  if(config['forms']):
    for form in forms:
      # check if there is a https string in the action attribute of the form
      # also check if url from which get request is not https
      if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
        report += 'Form Issue: Insecure form action ' + form.get('action') + ' found in document\n'

  if(config['comments']):
    for comment in comments:
      if(comment.find('key: ') > -1):
        # comment in html: <!-- key: 421523eof56 -->
        report += 'Comment Issue: Key is found in the HTML comments, please remove\n'

  if(config['passwords']):
    for password_input in password_inputs:
      if(password_input.get('type') != 'password'):
        report += 'Input Issue: Plaintext password input found. Please change to password type input\n'

else:
  print('Invalid URL.  Please include full URL including scheme.')

if(report == ''):
  report += 'Nice job! Your HTML document is secure!'
else:
  header += 'Vulnerability Report is as follows:\n'
  header += '==================================\n\n'
  report = header + report
  
print(report)

# Output a report if flag is passed
if(args.output):
  f = open(args.output, 'w')
  f.write(report)
  f.close
  print('Report saved to: ' + args.output)



